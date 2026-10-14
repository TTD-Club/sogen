#pragma once
#include "std_include.hpp"
#include "windows_path.hpp"

namespace sogen
{

    class file_system
    {
      public:
        file_system(const std::filesystem::path& root)
            : root_(root.empty() ? root : canonical(root))
        {
        }

        static bool is_escaping_relative_path(const std::filesystem::path& p)
        {
            return p.empty() || *p.begin() == "..";
        }

        static bool is_subpath(const std::filesystem::path& normal_root, const std::filesystem::path& normal_target)
        {
            // Lexical containment: structural check only, so it does not follow symlinks (unlike
            // std::filesystem::relative, which canonicalizes). Callers pass lexically-normalized
            // paths so that ".." escapes are still caught.
            const auto relative_path = normal_target.lexically_relative(normal_root);
            return !is_escaping_relative_path(relative_path);
        }

        // Host mode: guest paths are host paths (apart from mappings), with no emulation root.
        bool is_host_mode() const
        {
            return this->root_.empty();
        }

        std::set<char> list_drives() const
        {
            std::set<char> drives{};

#ifdef OS_WINDOWS
            if (this->root_.empty())
            {
                const auto drive_bits = GetLogicalDrives();

                for (char drive = 'a'; drive <= 'z'; ++drive)
                {
                    const auto drive_index = drive - 'a';
                    if (drive_bits & (1 << drive_index))
                    {
                        drives.insert(drive);
                    }
                }

                return drives;
            }
#endif

            std::error_code ec{};
            for (const auto& file : std::filesystem::directory_iterator(this->root_, ec))
            {
                const auto filename = file.path().filename().string();
                if (filename.size() == 1)
                {
                    drives.insert(utils::string::char_to_lower(filename.front()));
                }
            }

            return drives;
        }

        uint8_t drive_type(const char drive) const
        {
            const auto drives = this->list_drives();
            if (std::ranges::find(drives, drive) == drives.end())
            {
                constexpr uint8_t no_root_directory = 1;
                return no_root_directory;
            }
#ifdef OS_WINDOWS
            if (this->root_.empty())
            {
                const std::array<wchar_t, 4> path{static_cast<wchar_t>(drive), L':', L'\\', L'\0'};
                return static_cast<uint8_t>(GetDriveTypeW(path.data()));
            }
#endif
            constexpr uint8_t fixed_drive_type = 3;
            return fixed_drive_type;
        }

        std::filesystem::path translate(const windows_path& win_path) const
        {
            if (!win_path.is_absolute())
            {
                throw std::runtime_error("Only absolute paths can be translated: " + win_path.string());
            }

            // Exact file mapping (fast path).
            if (const auto mapping = this->mappings_.find(win_path); mapping != this->mappings_.end())
            {
                return mapping->second;
            }

            // Directory mapping: a mapped ancestor directory mounts its whole subtree.
            if (auto mapped = this->translate_directory_mapping(win_path))
            {
                return std::move(*mapped);
            }

#ifdef OS_WINDOWS
            if (this->root_.empty())
            {
                return keep_trailing_spaces_and_dots(win_path.u16string());
            }
#endif

            // Emulation-root translation, confined to the drive root.
            const std::array<char, 2> root_drive{win_path.get_drive().value_or('c'), 0};
            const auto drive_root = this->root_ / root_drive.data();
            return resolve_case(drive_root, confine(drive_root, this->root_ / win_path.to_portable_path()));
        }

        // The host path at which to create `win_path`, a new entry the guest named `spelled`. Windows keeps the case a
        // name was created with, while windows_path (and so translate) lowercases every component. The new entry takes
        // the guest's spelling of its last component, and later lookups through translate still find it: Windows hosts
        // ignore case, and elsewhere translate matches components ignoring case. An existing entry keeps its name, unless
        // it is being `renamed` (a rename that changes only the case of a name).
        std::filesystem::path translate_for_creation(const windows_path& win_path, const std::u16string_view spelled,
                                                     [[maybe_unused]] const bool renamed = false) const
        {
            auto host_path = this->translate(win_path);
#ifndef OS_WINDOWS
            std::error_code ec{};
            if (!renamed && exists(symlink_status(host_path, ec)))
            {
                return host_path;
            }
#endif
            auto leaf = spelled;
            while (!leaf.empty() && (leaf.back() == u'\\' || leaf.back() == u'/'))
            {
                leaf.remove_suffix(1);
            }
            if (const auto separator = leaf.find_last_of(u"\\/"); separator != std::u16string_view::npos)
            {
                leaf = leaf.substr(separator + 1);
            }
            if (!leaf.empty() && windows_path(std::u16string(leaf)).u16string() == win_path.leaf() &&
                utils::string::equals_ignore_case(std::u16string_view{host_path.filename().u16string()},
                                                  std::u16string_view{win_path.leaf()}))
            {
                host_path.replace_filename(std::filesystem::path(std::u16string(leaf)));
            }
            return host_path;
        }

        // The part of a guest path after its drive ("\Users\x"), its components in the case the file system keeps for
        // them, as Windows reports names (GetFinalPathNameByHandle): the host's case of each existing component (the
        // guest's spelling of components the host lacks or reaches through a link).
        std::u16string true_case(std::u16string_view spelled) const
        {
            for (const std::u16string_view prefix : {u"\\??\\", u"\\\\?\\"})
            {
                if (spelled.starts_with(prefix))
                {
                    spelled.remove_prefix(prefix.size());
                    break;
                }
            }
            std::u16string drive{};
            if (spelled.size() >= 2 && spelled[1] == u':')
            {
                drive = spelled.substr(0, 2);
                spelled.remove_prefix(2);
            }

            std::vector<std::u16string> parts{};
            size_t start = 0;
            while (start <= spelled.size())
            {
                const auto end = spelled.find_first_of(u"\\/", start);
                const auto part = spelled.substr(start, end == std::u16string_view::npos ? std::u16string_view::npos : end - start);
                if (part == u"..")
                {
                    if (!parts.empty())
                    {
                        parts.pop_back();
                    }
                }
                else if (!part.empty() && part != u".")
                {
                    parts.emplace_back(part);
                }
                if (end == std::u16string_view::npos)
                {
                    break;
                }
                start = end + 1;
            }

            if (!drive.empty() && !parts.empty())
            {
                // The host's spelling of the trailing components that name the same entries.
                std::error_code ec{};
                const auto canonical =
                    std::filesystem::canonical(this->translate(windows_path{drive + u"\\" + std::u16string(spelled)}), ec);
                if (!ec)
                {
                    std::vector<std::u16string> host_parts{};
                    for (const auto& component : canonical.relative_path())
                    {
                        host_parts.emplace_back(component.u16string());
                    }

                    auto host = host_parts.rbegin();
                    for (auto part = parts.rbegin(); part != parts.rend() && host != host_parts.rend(); ++part, ++host)
                    {
                        if (!utils::string::equals_ignore_case(std::u16string_view{*part}, std::u16string_view{*host}))
                        {
                            break;
                        }
                        *part = *host;
                    }
                }
            }

            std::u16string result{};
            for (const auto& part : parts)
            {
                result += u"\\" + part;
            }
            return result.empty() ? u"\\" : result;
        }

        template <typename F>
        void access_mapped_entries(const windows_path& win_path, const F& accessor) const
        {
            for (const auto& mapping : this->mappings_)
            {
                const auto& mapped_path = mapping.first;
                if (!mapped_path.empty() && mapped_path.parent() == win_path)
                {
                    accessor(mapping);
                }
            }
        }

        void map(windows_path src, std::filesystem::path dest)
        {
            this->mappings_[std::move(src)] = std::move(dest);
        }

      private:
        // Resolve a host path built from a guest-controlled path, but keep it inside `base`: a ".." in the
        // guest path that would escape `base` falls back to `base` itself. The check is purely lexical (it
        // does not follow symlinks), so a crafted path cannot escape. Host-side symlinks placed inside `base`
        // may still point elsewhere (e.g. a mounted game directory); the OS resolves those at open time.
        static std::filesystem::path confine(const std::filesystem::path& base, const std::filesystem::path& candidate)
        {
            if (is_subpath(base.lexically_normal(), candidate.lexically_normal()))
            {
                // weakly_canonical resolves "dir " to "dir" even in the \\?\ form, so such names skip it.
                auto kept = keep_trailing_spaces_and_dots(candidate);
                return kept.native() != candidate.native() ? std::move(kept) : weakly_canonical(candidate);
            }

            return base;
        }

        // Windows strips trailing spaces and dots from every component of a host path that is not in the \\?\ form,
        // so "dir " would open "dir". Guest NT paths keep them (only Win32 path conversion strips them, in the guest),
        // so a host path with such a component takes the \\?\ form.
        static std::filesystem::path keep_trailing_spaces_and_dots(std::filesystem::path path)
        {
#ifdef OS_WINDOWS
            const auto& native = path.native();
            if (!path.is_absolute() || native.starts_with(LR"(\\)"))
            {
                return path;
            }

            for (const auto& component : path.relative_path())
            {
                const auto& name = component.native();
                if (name != L"." && name != L".." && !name.empty() && (name.back() == L' ' || name.back() == L'.'))
                {
                    return {LR"(\\?\)" + path.lexically_normal().make_preferred().native()};
                }
            }
#endif
            return path;
        }

        // If a mapped directory is an ancestor of `win_path`, resolve the remaining path against the mapped
        // host directory. The deepest matching mount wins, so nested mounts behave intuitively.
        std::optional<std::filesystem::path> translate_directory_mapping(const windows_path& win_path) const
        {
            const std::filesystem::path* best_dest = nullptr;
            windows_path best_remainder{};
            size_t best_depth = 0;

            for (const auto& [src, dest] : this->mappings_)
            {
                auto remainder = win_path.relative_to(src);
                if (remainder.has_value() && (best_dest == nullptr || src.depth() > best_depth))
                {
                    best_dest = &dest;
                    best_remainder = std::move(*remainder);
                    best_depth = src.depth();
                }
            }

            if (best_dest == nullptr)
            {
                return std::nullopt;
            }

            return resolve_case(*best_dest, confine(*best_dest, *best_dest / best_remainder.to_portable_path()));
        }

        // Guest names ignore case, but translated paths are lowercase and the host may keep entries in another case (one
        // the guest created, see translate_for_creation, or a mapped host directory). On case-sensitive hosts each
        // component of `path` below `base` that does not exist as spelled takes the name of an entry of its directory
        // that matches it ignoring case. Components that match nothing are kept, and so is everything after them.
        static std::filesystem::path resolve_case([[maybe_unused]] const std::filesystem::path& base, std::filesystem::path path)
        {
#ifdef OS_WINDOWS
            return path;
#else
            std::error_code ec{};
            if (exists(symlink_status(path, ec)))
            {
                return path;
            }

            const auto relative = path.lexically_relative(base);
            if (is_escaping_relative_path(relative) || relative == ".")
            {
                return path;
            }

            auto resolved = base;
            auto component = relative.begin();
            for (; component != relative.end(); ++component)
            {
                auto next = resolved / *component;
                if (!exists(symlink_status(next, ec)))
                {
                    const auto wanted = component->u16string();
                    std::optional<std::filesystem::path> match{};
                    for (std::filesystem::directory_iterator entry(resolved, ec), end{}; !ec && entry != end; entry.increment(ec))
                    {
                        if (utils::string::equals_ignore_case(std::u16string_view{entry->path().filename().u16string()},
                                                              std::u16string_view{wanted}))
                        {
                            match = entry->path();
                            break;
                        }
                    }

                    if (!match)
                    {
                        break;
                    }

                    next = std::move(*match);
                }

                resolved = std::move(next);
            }

            for (; component != relative.end(); ++component)
            {
                resolved /= *component;
            }

            return resolved;
#endif
        }

        std::filesystem::path root_{};
        std::unordered_map<windows_path, std::filesystem::path> mappings_{};
    };

} // namespace sogen
