#include "host_directory_provider.hpp"

#include <string_view>
#include <unordered_map>

#include <platform/compiler.hpp>
#include <platform/unicode.hpp>
#include <utils/string.hpp>

#ifdef OS_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#if defined(OS_WINDOWS) && !defined(__MINGW64__)
#include <corecrt_io.h>
#else
#include <unistd.h>
#endif

namespace sogen
{

    namespace
    {
        bool is_subpath(const std::filesystem::path& root, const std::filesystem::path& target)
        {
            const auto relative_path = target.lexically_relative(root);
            return !relative_path.empty() && *relative_path.begin() != "..";
        }

        NTSTATUS map_open_error(const int error)
        {
            switch (error)
            {
            case ENOENT:
                return STATUS_OBJECT_NAME_NOT_FOUND;
            case EACCES:
                return STATUS_ACCESS_DENIED;
            case EISDIR:
                return STATUS_FILE_IS_A_DIRECTORY;
            default:
                return STATUS_NOT_SUPPORTED;
            }
        }

        // Windows strips trailing spaces and dots from every component of a host path that is not in the \\?\ form,
        // so "dir " would open "dir". Guest NT paths keep them (only Win32 path conversion strips them, in the guest),
        // so a host path with such a component takes the \\?\ form.
        std::filesystem::path keep_trailing_spaces_and_dots(std::filesystem::path path)
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

        // Guest names ignore case, but guest paths are lowercase and the host may keep entries in another case (one
        // the guest created, see file_system::translate_for_creation, or a mapped host directory). On case-sensitive
        // hosts each component of `path` below `base` that does not exist as spelled takes the name of an entry of its
        // directory that matches it ignoring case. Components that match nothing are kept, and so is everything after.
        std::filesystem::path resolve_case([[maybe_unused]] const std::filesystem::path& base, std::filesystem::path path)
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
            if (relative.empty() || *relative.begin() == ".." || relative == ".")
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

#ifdef OS_WINDOWS
        struct find_handle_deleter
        {
            void operator()(void* handle) const noexcept
            {
                (void)FindClose(handle);
            }
        };
#endif
    }

    host_file::host_file(FILE* file)
        : file_(file)
    {
        // Reads and writes go to the host file directly: the guest's other handles to the file (other streams) see a
        // write once it returns and never read data this stream buffered before another handle changed it.
        (void)setvbuf(this->file_, nullptr, _IONBF, 0);
    }

    host_file::~host_file()
    {
        if (this->file_)
        {
            (void)fclose(this->file_);
        }
    }

    size_t host_file::read(const std::span<std::byte> buffer)
    {
        this->switch_direction(io_direction::read);
        return fread(buffer.data(), 1, buffer.size(), this->file_);
    }

    size_t host_file::write(const std::span<const std::byte> buffer)
    {
        this->switch_direction(io_direction::write);
        return fwrite(buffer.data(), 1, buffer.size(), this->file_);
    }

    bool host_file::flush()
    {
        return fflush(this->file_) == 0;
    }

    bool host_file::seek(const int64_t offset, const int origin)
    {
        this->last_io_ = io_direction::none;
        return _fseeki64(this->file_, offset, origin) == 0;
    }

    // A stream must not read right after writing, or write right after reading, without a seek in between (C11
    // 7.21.5.3): the CRT would read from or write to a stale buffer position.
    void host_file::switch_direction(const io_direction direction)
    {
        if (this->last_io_ != io_direction::none && this->last_io_ != direction)
        {
            (void)this->seek(this->tell(), SEEK_SET);
        }

        this->last_io_ = direction;
    }

    int64_t host_file::tell()
    {
        return _ftelli64(this->file_);
    }

    int64_t host_file::size()
    {
        const auto current_position = this->tell();

        this->seek(0, SEEK_END);
        const auto size = this->tell();
        this->seek(current_position, SEEK_SET);

        return size;
    }

    bool host_file::resize(const uint64_t size)
    {
        const auto fd = fileno(this->file_);
        if (fd == -1)
        {
            return false;
        }

#ifdef OS_WINDOWS
        // NOLINTNEXTLINE(google-runtime-int)
        return _chsize_s(fd, static_cast<long long>(size)) == 0;
#else
        return ftruncate(fd, static_cast<off_t>(size)) == 0;
#endif
    }

    std::optional<struct compat_stat> host_file::stat()
    {
        struct compat_stat file_stat{};
        if (!compat_fstat(fileno(this->file_), &file_stat))
        {
            return std::nullopt;
        }

        return file_stat;
    }

    host_directory_provider::host_directory_provider(std::filesystem::path target)
        : target_(std::move(target))
    {
    }

    std::optional<std::filesystem::path> host_directory_provider::get_host_path(const windows_path& path) const
    {
        if (path.empty())
        {
            return this->target_;
        }

        auto candidate = (this->target_ / path.to_portable_path()).lexically_normal();
        // The containment check is lexical and does not follow symlinks. Host symlinks inside the mount may
        // point elsewhere (e.g. a mounted game directory); the OS resolves those at open time.
        if (!is_subpath(this->target_.lexically_normal(), candidate))
        {
            return std::nullopt;
        }

        // weakly_canonical resolves "dir " to "dir" even in the \\?\ form, so such names skip it.
        if (auto kept = keep_trailing_spaces_and_dots(candidate); kept.native() != candidate.native())
        {
            return kept;
        }

        std::error_code ec{};
        auto resolved = weakly_canonical(candidate, ec);
        if (ec)
        {
            return resolve_case(this->target_, std::move(candidate));
        }

        return resolve_case(this->target_, std::move(resolved));
    }

    std::optional<struct compat_stat> host_directory_provider::stat(const windows_path& path) const
    {
        const auto host_path = this->get_host_path(path);
        if (!host_path)
        {
            return std::nullopt;
        }

        struct compat_stat file_stat{};
        if (!compat_stat(*host_path, &file_stat))
        {
            return std::nullopt;
        }

        return file_stat;
    }

    std::vector<directory_entry> host_directory_provider::list(const windows_path& path) const
    {
        std::vector<directory_entry> entries{};

        const auto host_path = this->get_host_path(path);
        if (!host_path)
        {
            return entries;
        }

#ifdef OS_WINDOWS
        std::unordered_map<std::u16string, std::u16string> short_names{};

        std::wstring search_path = host_path->wstring();
        if (!search_path.ends_with(L'\\') && !search_path.ends_with(L'/'))
        {
            search_path.push_back(L'\\');
        }
        search_path.push_back(L'*');

        WIN32_FIND_DATAW find_data{};
        HANDLE find_handle = FindFirstFileW(search_path.c_str(), &find_data);
        if (find_handle != INVALID_HANDLE_VALUE)
        {
            const std::unique_ptr<void, find_handle_deleter> find_handle_guard{find_handle};

            do
            {
                const std::wstring_view filename{find_data.cFileName};
                const std::wstring_view short_name{find_data.cAlternateFileName};
                if (filename == L"." || filename == L".." || short_name.empty())
                {
                    continue;
                }

                short_names.emplace(std::filesystem::path{find_data.cFileName}.u16string(),
                                    std::filesystem::path{find_data.cAlternateFileName}.u16string());
            } while (FindNextFileW(find_handle_guard.get(), &find_data));
        }
#endif

        std::error_code ec{};
        for (const auto& file : std::filesystem::directory_iterator(*host_path, ec))
        {
            directory_entry entry{
                .name = file.path().filename().u16string(),
                .is_directory = file.is_directory(ec),
            };

#ifdef OS_WINDOWS
            const auto short_name = short_names.find(entry.name);
            if (short_name != short_names.end())
            {
                entry.short_name = short_name->second;
            }
#endif

            struct compat_stat file_stat{};
            if (compat_stat(file.path(), &file_stat))
            {
                entry.stat = file_stat;
            }

            entries.emplace_back(std::move(entry));
        }

        return entries;
    }

    std::filesystem::path spell_created_leaf(std::filesystem::path host_path, const windows_path& path, std::u16string_view spelled,
                                             [[maybe_unused]] const bool renamed)
    {
        if (host_path.empty())
        {
            return host_path;
        }
#ifndef OS_WINDOWS
        std::error_code ec{};
        if (!renamed && exists(symlink_status(host_path, ec)))
        {
            return host_path;
        }
#endif
        while (!spelled.empty() && (spelled.back() == u'\\' || spelled.back() == u'/'))
        {
            spelled.remove_suffix(1);
        }
        if (const auto separator = spelled.find_last_of(u"\\/"); separator != std::u16string_view::npos)
        {
            spelled = spelled.substr(separator + 1);
        }
        if (!spelled.empty() && windows_path(std::u16string(spelled)).u16string() == path.leaf() &&
            utils::string::equals_ignore_case(std::u16string_view{host_path.filename().u16string()}, std::u16string_view{path.leaf()}))
        {
            host_path.replace_filename(std::filesystem::path(std::u16string(spelled)));
        }
        return host_path;
    }

    std::optional<std::filesystem::path> host_directory_provider::get_creation_path(const windows_path& path,
                                                                                    const std::u16string_view spelled_leaf,
                                                                                    const bool renamed) const
    {
        auto host_path = this->get_host_path(path);
        if (!host_path || spelled_leaf.empty() || path.empty())
        {
            return host_path;
        }

        return spell_created_leaf(std::move(*host_path), path, spelled_leaf, renamed);
    }

    open_result host_directory_provider::open(const windows_path& path, const std::u16string& mode, const std::u16string_view spelled_leaf)
    {
        const auto host_path = this->get_creation_path(path, spelled_leaf, false);
        if (!host_path)
        {
            return {.status = STATUS_ACCESS_DENIED};
        }

        FILE* file{};
        const auto error = open_unicode(&file, *host_path, mode);
        if (!file)
        {
            return {.status = map_open_error(error)};
        }

        return {.file = std::make_unique<host_file>(file), .status = STATUS_SUCCESS};
    }

    NTSTATUS host_directory_provider::create_directory(const windows_path& path, const std::u16string_view spelled_leaf)
    {
        const auto host_path = this->get_creation_path(path, spelled_leaf, false);
        if (!host_path)
        {
            return STATUS_ACCESS_DENIED;
        }

        std::error_code ec{};
        if (std::filesystem::exists(*host_path, ec))
        {
            return STATUS_OBJECT_NAME_COLLISION;
        }

        if (!std::filesystem::is_directory(host_path->parent_path(), ec))
        {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }

        std::filesystem::create_directory(*host_path, ec);
        return ec ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
    }

    NTSTATUS host_directory_provider::rename(const windows_path& from, const windows_path& to, const std::u16string_view spelled_leaf)
    {
        const auto host_from = this->get_host_path(from);
        const auto host_to = this->get_creation_path(to, spelled_leaf, from == to);
        if (!host_from || !host_to)
        {
            return STATUS_ACCESS_DENIED;
        }

        std::error_code ec{};
#ifndef OS_WINDOWS
        // Windows lets a directory replace a file; POSIX rename refuses (ENOTDIR).
        const auto target = std::filesystem::symlink_status(*host_to, ec);
        if (std::filesystem::is_directory(*host_from, ec) && std::filesystem::exists(target) && !std::filesystem::is_directory(target))
        {
            std::filesystem::remove(*host_to, ec);
        }
#endif
        std::filesystem::rename(*host_from, *host_to, ec);
        return ec ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
    }

    NTSTATUS host_directory_provider::remove(const windows_path& path)
    {
        const auto host_path = this->get_host_path(path);
        if (!host_path)
        {
            return STATUS_ACCESS_DENIED;
        }

        std::error_code ec{};
        const auto removed = std::filesystem::remove(*host_path, ec);
        if (ec)
        {
            return STATUS_ACCESS_DENIED;
        }

        return removed ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
    }

} // namespace sogen
