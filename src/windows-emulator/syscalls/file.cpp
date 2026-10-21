#include "../std_include.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"
#include "utils/io.hpp"

#include <algorithm>
#include <charconv>
#include <utils/finally.hpp>
#include <utils/wildcard.hpp>
#include "utils/stat.hpp"

#include <sys/stat.h>

#include "../devices/named_pipe.hpp"
#include "../filesystem/host_directory_provider.hpp"

namespace sogen
{

    namespace syscalls
    {
        namespace
        {
            struct file_completion_information
            {
                handle completion_port;
                uint64_t completion_key;
            };

            std::u16string normalize_named_pipe_path(const std::u16string_view filename)
            {
                constexpr std::u16string_view dos_prefix = u"\\??\\Pipe\\";
                if (utils::string::starts_with_ignore_case(filename, dos_prefix))
                {
                    return u"\\Device\\NamedPipe\\" + std::u16string(filename.substr(dos_prefix.size()));
                }
                return std::u16string(filename);
            }

            bool has_valid_filename_characters(const std::u16string_view path)
            {
                constexpr std::u16string_view invalid_characters = u"\"<>|*?";
                return path.find_first_of(invalid_characters) == std::u16string_view::npos;
            }

            constexpr ULONG io_reparse_tag_mount_point = 0xA0000003;
            constexpr ULONG io_reparse_tag_symlink = 0xA000000C;
            constexpr ULONG symlink_flag_relative = 1;
            constexpr ULONG file_open_reparse_point = 0x00200000;
            constexpr auto status_reparse_point_not_resolved = static_cast<NTSTATUS>(0xC0000280);
            // A reparse point's chain may not be longer (as on Windows).
            constexpr int max_reparses = 63;

            std::u16string reparse_key(const std::u16string_view path)
            {
                return windows_path(path).u16string();
            }

            ULONG reparse_tag(const std::vector<uint8_t>& data)
            {
                ULONG tag{};
                if (data.size() >= sizeof(tag))
                {
                    memcpy(&tag, data.data(), sizeof(tag));
                }
                return tag;
            }

            constexpr ULONG file_attribute_readonly = 0x1;
            constexpr auto status_cannot_delete = static_cast<NTSTATUS>(0xC0000121);

            // The attributes a host stat shows: a directory, or a file, read-only without write permission.
            // Files carry FILE_ATTRIBUTE_ARCHIVE, as Windows sets it on files it creates or changes: clearing read-only
            // then leaves a value that is not 0 (which would mean "keep the attributes").
            ULONG host_file_attributes(const struct compat_stat& file_stat)
            {
                constexpr uint32_t owner_write = 0200;
                constexpr ULONG file_attribute_archive = 0x20;
                const auto read_only = (file_stat.st_mode & owner_write) == 0;
                const auto base = (file_stat.st_mode & S_IFDIR) != 0 ? FILE_ATTRIBUTE_DIRECTORY : file_attribute_archive;
                return base | (read_only ? file_attribute_readonly : 0);
            }

            // A file's attributes with FILE_ATTRIBUTE_REPARSE_POINT if it is one (FILE_ATTRIBUTE_NORMAL stands alone).
            ULONG with_reparse_attribute(const ULONG attributes, const ULONG tag)
            {
                constexpr ULONG file_attribute_reparse_point = 0x400;
                return tag ? ((attributes & ~static_cast<ULONG>(FILE_ATTRIBUTE_NORMAL)) | file_attribute_reparse_point) : attributes;
            }

            // The tag of the reparse point the guest made at `path`, 0 for none.
            ULONG emulated_reparse_tag_at(const process_context& process, const std::u16string_view path)
            {
                if (process.reparse_points.empty())
                {
                    return 0;
                }

                const auto entry = process.reparse_points.find(reparse_key(path));
                return entry == process.reparse_points.end() ? 0 : reparse_tag(entry->second);
            }

            // The REPARSE_DATA_BUFFER of the reparse point at `path`: one the guest made, or in host mode one the host
            // has (opens through it already follow it on the host). Nothing for other paths.
            std::optional<std::vector<uint8_t>> reparse_data_at(const syscall_context& c, const std::u16string_view path)
            {
                if (const auto entry = c.proc.reparse_points.find(reparse_key(path)); entry != c.proc.reparse_points.end())
                {
                    return entry->second;
                }

                if (!c.win_emu.file_sys.is_host_mode())
                {
                    return std::nullopt;
                }

                return compat_reparse_data(c.win_emu.file_sys.translate(windows_path(path)));
            }

            // The tag of the reparse point at `path`, 0 for none.
            ULONG reparse_tag_at(const syscall_context& c, const std::u16string_view path)
            {
                if (const auto tag = emulated_reparse_tag_at(c.proc, path); tag || !c.win_emu.file_sys.is_host_mode())
                {
                    return tag;
                }

                const auto data = reparse_data_at(c, path);
                return data ? reparse_tag(*data) : 0;
            }

            // Appends the components of `path` (separated by \ or /) to `parts`, resolving "." and ".." (which stops at the
            // drive, parts[0]).
            void append_components(std::vector<std::u16string>& parts, const std::u16string_view path)
            {
                size_t start = 0;
                while (start <= path.size())
                {
                    const auto end = path.find_first_of(u"\\/", start);
                    const auto component = path.substr(start, end == std::u16string_view::npos ? std::u16string_view::npos : end - start);
                    if (component == u"..")
                    {
                        if (parts.size() > 1)
                        {
                            parts.pop_back();
                        }
                    }
                    else if (!component.empty() && component != u".")
                    {
                        parts.emplace_back(component);
                    }

                    if (end == std::u16string_view::npos)
                    {
                        break;
                    }
                    start = end + 1;
                }
            }

            // An absolute guest path as its drive ("C:") and its components, keeping their case; nothing for other paths.
            std::optional<std::vector<std::u16string>> split_path(std::u16string_view path)
            {
                for (const std::u16string_view prefix : {u"\\??\\", u"\\\\?\\"})
                {
                    if (path.starts_with(prefix))
                    {
                        path.remove_prefix(prefix.size());
                        break;
                    }
                }

                const auto is_drive_letter = [](const char16_t c) { return (c >= u'a' && c <= u'z') || (c >= u'A' && c <= u'Z'); };
                if (path.size() < 2 || path[1] != u':' || !is_drive_letter(path[0]))
                {
                    return std::nullopt;
                }

                std::vector<std::u16string> parts{std::u16string(path.substr(0, 2))};
                append_components(parts, path.substr(2));
                return parts;
            }

            std::u16string join_path(const std::vector<std::u16string>& parts)
            {
                std::u16string path = u"\\??\\" + parts.front() + u"\\";
                for (size_t i = 1; i < parts.size(); ++i)
                {
                    path += (i > 1 ? u"\\" : u"") + parts[i];
                }
                return path;
            }

            // Where a junction or symbolic link leads, as components (a relative link resolves against `link_directory`);
            // nothing for tags opens do not follow.
            std::optional<std::vector<std::u16string>> reparse_target(const std::vector<uint8_t>& data,
                                                                      const std::vector<std::u16string>& link_directory)
            {
                // REPARSE_DATA_BUFFER: tag, data length, reserved, then the substitute and print name offsets and lengths
                // (and, for a symbolic link, its flags) before the path buffer.
                const auto tag = reparse_tag(data);
                const auto buffer_offset = tag == io_reparse_tag_symlink ? size_t{20} : size_t{16};
                if ((tag != io_reparse_tag_mount_point && tag != io_reparse_tag_symlink) || data.size() < buffer_offset)
                {
                    return std::nullopt;
                }

                uint16_t substitute_offset{};
                uint16_t substitute_length{};
                memcpy(&substitute_offset, data.data() + 8, sizeof(substitute_offset));
                memcpy(&substitute_length, data.data() + 10, sizeof(substitute_length));
                ULONG flags{};
                if (tag == io_reparse_tag_symlink)
                {
                    memcpy(&flags, data.data() + 16, sizeof(flags));
                }

                if (buffer_offset + substitute_offset + substitute_length > data.size() || substitute_length % sizeof(char16_t) != 0)
                {
                    return std::nullopt;
                }

                std::u16string substitute(substitute_length / sizeof(char16_t), u'\0');
                memcpy(substitute.data(), data.data() + buffer_offset + substitute_offset, substitute_length);

                if (tag == io_reparse_tag_symlink && (flags & symlink_flag_relative))
                {
                    auto parts = link_directory;
                    append_components(parts, substitute);
                    return parts;
                }

                return split_path(substitute);
            }

            // `name` after following the reparse points among its components, all of them or all but the last (an open
            // with FILE_OPEN_REPARSE_POINT, or a by-name query). Unchanged without reparse points on the way; nothing for
            // a chain longer than Windows follows.
            std::optional<std::u16string> resolve_reparse_points(const process_context& process, const std::u16string& name,
                                                                 const bool follow_last)
            {
                if (process.reparse_points.empty())
                {
                    return name;
                }

                auto parts = split_path(name);
                if (!parts)
                {
                    return name;
                }

                for (int reparses = 0; reparses <= max_reparses; ++reparses)
                {
                    auto replaced = false;
                    std::vector<std::u16string> prefix{parts->front()};
                    for (size_t i = 1; i < parts->size(); ++i)
                    {
                        prefix.push_back((*parts)[i]);
                        if (i + 1 == parts->size() && !follow_last)
                        {
                            break;
                        }

                        const auto entry = process.reparse_points.find(reparse_key(join_path(prefix)));
                        if (entry == process.reparse_points.end())
                        {
                            continue;
                        }

                        prefix.pop_back();
                        auto target = reparse_target(entry->second, prefix);
                        if (!target)
                        {
                            prefix.push_back((*parts)[i]);
                            continue;
                        }

                        target->insert(target->end(), parts->begin() + static_cast<ptrdiff_t>(i) + 1, parts->end());
                        parts = std::move(target);
                        replaced = true;
                        break;
                    }

                    if (!replaced)
                    {
                        return reparses == 0 ? name : join_path(*parts);
                    }
                }

                return std::nullopt;
            }

            // What the host knows of an open file or directory: a file through its stream, a directory by its path (left
            // empty where that fails, as for a volume).
            bool stat_open_file(const file& f, struct compat_stat& file_stat)
            {
                if (f.handle)
                {
                    const auto result = f.handle.stat();
                    if (!result)
                    {
                        return false;
                    }

                    file_stat = *result;
                    return true;
                }

                if (!compat_stat(f.host_path, &file_stat))
                {
                    constexpr uint32_t writable_directory = S_IFDIR | 0700;
                    file_stat = {};
                    file_stat.st_mode = writable_directory;
                }
                return true;
            }

            // A read-only file cannot be deleted (STATUS_CANNOT_DELETE), as on Windows.
            bool is_read_only_file(const file& f)
            {
                struct compat_stat file_stat{};
                return stat_open_file(f, file_stat) && (host_file_attributes(file_stat) & file_attribute_readonly) != 0;
            }

            // The access an open holds for sharing purposes (IoCheckShareAccess): reading, writing, and deleting.
            struct shared_access
            {
                bool read{};
                bool write{};
                bool remove{};

                bool any() const
                {
                    return this->read || this->write || this->remove;
                }
            };

            shared_access get_shared_access(const ACCESS_MASK access)
            {
                if (access & GENERIC_ALL)
                {
                    return {.read = true, .write = true, .remove = true};
                }

                // The granted maximum is not computed; reading and writing cover what callers asking for it use.
                const auto maximum = (access & MAXIMUM_ALLOWED) != 0;
                return {
                    .read = maximum || (access & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_EXECUTE)) != 0,
                    .write = maximum || (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) != 0,
                    .remove = (access & DELETE) != 0,
                };
            }

            std::u16string sharing_key(const std::filesystem::path& host_path)
            {
                auto key = host_path.lexically_normal().generic_u16string();
#ifdef OS_WINDOWS
                // Windows hosts ignore case, so differently spelled paths name one file.
                std::ranges::transform(key, key.begin(), [](const char16_t c) { return utils::string::char_to_lower(c); });
#endif
                return key;
            }

            // Whether an open of `host_path` with `access` and `share_access` is compatible with the process's other
            // opens of that file, the way IoCheckShareAccess decides it.
            NTSTATUS check_share_access(const process_context& process, const std::filesystem::path& host_path, const ACCESS_MASK access,
                                        const ULONG share_access)
            {
                const auto wanted = get_shared_access(access);
                if (!wanted.any())
                {
                    return STATUS_SUCCESS;
                }

                const auto key = sharing_key(host_path);
                for (const auto& open : process.files | std::views::values)
                {
                    const auto held = get_shared_access(open.access_mask);
                    if (!held.any() || open.host_path.empty() || sharing_key(open.host_path) != key)
                    {
                        continue;
                    }

                    const auto refused =
                        (wanted.read && !(open.share_access & FILE_SHARE_READ)) ||
                        (wanted.write && !(open.share_access & FILE_SHARE_WRITE)) ||
                        (wanted.remove && !(open.share_access & FILE_SHARE_DELETE)) || (held.read && !(share_access & FILE_SHARE_READ)) ||
                        (held.write && !(share_access & FILE_SHARE_WRITE)) || (held.remove && !(share_access & FILE_SHARE_DELETE));
                    if (refused)
                    {
                        return STATUS_SHARING_VIOLATION;
                    }
                }

                return STATUS_SUCCESS;
            }

            std::u16string resolve_system_root_path(const syscall_context& c, std::u16string filename)
            {
                auto filename_upper = filename;
                std::ranges::transform(filename_upper, filename_upper.begin(), ::towupper);

                constexpr std::u16string_view system_root_prefix = u"\\SYSTEMROOT";
                if (filename_upper != system_root_prefix &&
                    !(filename_upper.size() > system_root_prefix.size() && filename_upper.starts_with(system_root_prefix) &&
                      windows_path_detail::is_slash(filename_upper[system_root_prefix.size()])))
                {
                    return filename;
                }

                const auto system_root =
                    c.proc.kusd.access([](const KUSER_SHARED_DATA64& kusd) { return std::u16string{kusd.NtSystemRoot.arr}; });
                const auto suffix = std::u16string_view{filename}.substr(system_root_prefix.size());
                filename = system_root;

                if (!suffix.empty() && windows_path_detail::is_slash(filename.back()) && windows_path_detail::is_slash(suffix.front()))
                {
                    filename.append(suffix.substr(1));
                }
                else
                {
                    filename.append(suffix);
                }

                return filename;
            }

            // The counterpart of windows_path::to_device_path. Sogen reports file names in volume-device form
            // (NtQueryObject, NtQueryVirtualMemory, ...) and code that consumes them - ntmarta walking a
            // directory's parents for an ACL check, for one - opens them again as-is. Rewrite the volume back
            // into its drive letter so the path reaches the file system instead of the device registry. A bare
            // volume with no path behind it is a real volume handle and stays a device.
            std::u16string resolve_volume_device_path(std::u16string filename)
            {
                constexpr std::u16string_view volume_prefix = u"\\Device\\HarddiskVolume";
                if (!filename.starts_with(volume_prefix))
                {
                    return filename;
                }

                const std::u16string_view remainder{filename};
                const auto separator = remainder.find(u'\\', volume_prefix.size());
                if (separator == std::u16string_view::npos)
                {
                    return filename;
                }

                const auto number = u16_to_u8(remainder.substr(volume_prefix.size(), separator - volume_prefix.size()));

                int volume_index{};
                const auto* number_start = number.data();
                const auto* number_end = number_start + number.size();
                const auto [parse_end, parse_error] = std::from_chars(number_start, number_end, volume_index);
                if (parse_error != std::errc{} || parse_end != number_end || volume_index < 1 || volume_index > 26)
                {
                    return filename;
                }

                std::u16string path = u"\\??\\";
                path.push_back(static_cast<char16_t>(u'a' + volume_index - 1));
                path.push_back(u':');
                path.append(remainder.substr(separator));

                return path;
            }
        }

        NTSTATUS handle_NtGetCachedSigningLevel(const syscall_context&, handle, emulator_object<ULONG>, emulator_object<UCHAR>, uint64_t,
                                                emulator_object<ULONG>, emulator_object<ULONG>)
        {
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtSetCachedSigningLevel()
        {
            return STATUS_NOT_SUPPORTED;
        }

        bool changes_file_state(const FILE_INFORMATION_CLASS info_class)
        {
            return info_class != FilePositionInformation;
        }

        NTSTATUS handle_NtSetInformationFile(const syscall_context& c, const handle file_handle,
                                             const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                             const uint64_t file_information, const ULONG length, const FILE_INFORMATION_CLASS info_class)
        {
            auto* f = c.proc.files.get(file_handle);
            if (!f)
            {
                // NUL has no position: setting it is ignored (CPython opens os.devnull with mode 'a').
                if (file_handle == NUL_HANDLE && info_class == FilePositionInformation)
                {
                    return length < sizeof(FILE_POSITION_INFORMATION) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;
                }

                auto* device = c.proc.devices.get(file_handle);
                if (device)
                {
                    if (info_class == FileCompletionInformation)
                    {
                        if (length < sizeof(file_completion_information))
                        {
                            return STATUS_INFO_LENGTH_MISMATCH;
                        }

                        const auto info = c.emu.read_memory<file_completion_information>(file_information);
                        return device->set_completion_association(c.proc, c.vcpu.active_thread, info.completion_port, info.completion_key);
                    }

                    if (info_class == FileIoCompletionNotificationInformation)
                    {
                        if (length < sizeof(ULONG))
                        {
                            return STATUS_INFO_LENGTH_MISMATCH;
                        }

                        device->set_completion_notification_flags(c.emu.read_memory<ULONG>(file_information));
                    }

                    // The completion mode decides whether a read of an empty pipe waits (PIPE_WAIT) or returns
                    // STATUS_PIPE_EMPTY (PIPE_NOWAIT).
                    if (auto* pipe = device->get_internal_device<named_pipe>(); pipe && info_class == FilePipeInformation)
                    {
                        if (length < sizeof(file_pipe_information))
                        {
                            return STATUS_INFO_LENGTH_MISMATCH;
                        }

                        const auto info = c.emu.read_memory<file_pipe_information>(file_information);
                        pipe->read_mode = info.read_mode;
                        pipe->completion_mode = info.completion_mode;
                    }

                    return STATUS_SUCCESS;
                }

                return STATUS_INVALID_HANDLE;
            }

            if (changes_file_state(info_class) && !c.win_emu.file_sys.is_writable(f->handle.path()))
            {
                return STATUS_ACCESS_DENIED;
            }

            if (info_class == FileBasicInformation)
            {
                if (length < sizeof(FILE_BASIC_INFORMATION))
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                // Access and write times go to the host file (SetFileTime, os.utime). 0 keeps a time, and -1 and -2
                // switch its automatic updates off and on, so only positive values are times. Creation times are not
                // kept.
                const auto info = c.emu.read_memory<FILE_BASIC_INFORMATION>(file_information);
                const auto time = [](const LARGE_INTEGER value) { return value.QuadPart > 0 ? std::optional(value) : std::nullopt; };
                const auto access_time = time(info.LastAccessTime);
                const auto write_time = time(info.LastWriteTime);
                if ((access_time || write_time) && !f->host_path.empty() && !compat_set_file_times(f->host_path, access_time, write_time))
                {
                    return STATUS_ACCESS_DENIED;
                }

                // Of the attributes (0 keeps them), a file's read-only one is kept as the host file's write permission
                // (SetFileAttributes, os.chmod); others are not kept.
                if (info.FileAttributes != 0 && !f->host_path.empty())
                {
                    constexpr auto write_permissions =
                        std::filesystem::perms::owner_write | std::filesystem::perms::group_write | std::filesystem::perms::others_write;
                    std::error_code ec{};
                    std::filesystem::permissions(f->host_path, write_permissions,
                                                 (info.FileAttributes & file_attribute_readonly) ? std::filesystem::perm_options::remove
                                                                                                 : std::filesystem::perm_options::add,
                                                 ec);
                    if (ec)
                    {
                        return STATUS_ACCESS_DENIED;
                    }
                }

                return STATUS_SUCCESS;
            }

            // FILE_LINK_INFORMATION has the layout of FILE_RENAME_INFORMATION.
            const auto read_target_name = [&](const FILE_RENAME_INFORMATION& info) -> std::optional<std::u16string> {
                auto name =
                    read_string<char16_t>(c.emu, file_information + offsetof(FILE_RENAME_INFORMATION, FileName), info.FileNameLength / 2);
                if (!info.RootDirectory)
                {
                    return name;
                }

                const auto* root = c.proc.files.get(info.RootDirectory);
                if (!root)
                {
                    return std::nullopt;
                }

                const auto has_separator = root->name.ends_with(u"\\") || root->name.ends_with(u"/");
                return root->name + (has_separator ? u"" : u"\\") + name;
            };

            if (info_class == FileLinkInformation)
            {
                if (length < sizeof(FILE_RENAME_INFORMATION))
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                const auto info = c.emu.read_memory<FILE_RENAME_INFORMATION>(file_information);
                const auto link_name = read_target_name(info);
                if (!link_name)
                {
                    return STATUS_INVALID_HANDLE;
                }

                if (!c.win_emu.file_sys.is_writable(windows_path{*link_name}))
                {
                    return STATUS_ACCESS_DENIED;
                }

                const auto source = c.win_emu.file_sys.translate(f->name);
                const auto target = c.win_emu.file_sys.translate_for_creation(*link_name, *link_name);
                std::error_code ec{};
                if (std::filesystem::is_directory(source, ec))
                {
                    return STATUS_FILE_IS_A_DIRECTORY;
                }

                if (std::filesystem::exists(target, ec))
                {
                    if (!info.ReplaceIfExists)
                    {
                        return STATUS_OBJECT_NAME_COLLISION;
                    }

                    std::filesystem::remove(target, ec);
                }

                std::filesystem::create_hard_link(source, target, ec);
                return ec ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
            }

            if (info_class == FileRenameInformation)
            {
                if (length < sizeof(FILE_RENAME_INFORMATION))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const auto info = c.emu.read_memory<FILE_RENAME_INFORMATION>(file_information);
                const auto target_name = read_target_name(info);
                if (!target_name)
                {
                    return STATUS_INVALID_HANDLE;
                }

                // The target's directory may lie behind a junction or link.
                const auto resolved_name = resolve_reparse_points(c.proc, *target_name, false);
                if (!resolved_name)
                {
                    return status_reparse_point_not_resolved;
                }
                const auto& new_name = *resolved_name;

                c.win_emu.callbacks.on_generic_access("File rename requested", f->name + u" --> " + new_name);

                // A directory cannot move below itself. The rename happens when the handle closes, where a host
                // failure would go unreported, so this is refused now, as Windows refuses it.
                const windows_path source_path{f->name};
                const windows_path target_path{new_name};
                if (target_path != source_path && target_path.relative_to(source_path).has_value())
                {
                    return STATUS_INVALID_PARAMETER;
                }

                auto new_path = windows_path{new_name};
                if (new_path.is_relative())
                {
                    new_path = f->handle.path().parent() / new_path;
                }

                if (!c.win_emu.file_sys.is_writable(new_path))
                {
                    return STATUS_ACCESS_DENIED;
                }

                // A rename onto itself (another spelling of the name) changes only the case of the name. It replaces
                // nothing, so it needs no ReplaceIfExists.
                const auto onto_itself = new_path == source_path;
                const auto existing = c.win_emu.file_sys.stat(new_path);
                if (!info.ReplaceIfExists && existing && !onto_itself)
                {
                    return STATUS_OBJECT_NAME_EXISTS;
                }

                // A directory is not replaced (os.replace onto a directory fails; a file may be replaced by a
                // directory).
                std::error_code ec{};
                if (existing && !onto_itself && (existing->st_mode & S_IFMT) == S_IFDIR &&
                    !std::filesystem::equivalent(c.win_emu.file_sys.translate(source_path), c.win_emu.file_sys.translate(new_path), ec))
                {
                    return STATUS_ACCESS_DENIED;
                }

                f->handle.defer_rename(new_path, new_name);
                f->renamed_to = new_name;

                return STATUS_SUCCESS;
            }

            if (info_class == FileDispositionInformation)
            {
                if (length < sizeof(FILE_DISPOSITION_INFORMATION))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                if (!(f->access_mask & DELETE))
                {
                    return STATUS_ACCESS_DENIED;
                }

                const auto info = c.emu.read_memory<FILE_DISPOSITION_INFORMATION>(file_information);
                if (info.DeleteFile && is_read_only_file(*f))
                {
                    return status_cannot_delete;
                }

                f->handle.set_delete_on_close(info.DeleteFile != FALSE);

                return STATUS_SUCCESS;
            }

            if (info_class == FileDispositionInformationEx)
            {
                if (length < sizeof(FILE_DISPOSITION_INFORMATION_EX))
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                const auto info = c.emu.read_memory<FILE_DISPOSITION_INFORMATION_EX>(file_information);
                const bool wants_delete = (info.Flags & FILE_DISPOSITION_DELETE) != 0;

                if (wants_delete && !(f->access_mask & DELETE))
                {
                    return STATUS_ACCESS_DENIED;
                }

                constexpr ULONG file_disposition_ignore_readonly_attribute = 0x10;
                if (wants_delete && !(info.Flags & file_disposition_ignore_readonly_attribute) && is_read_only_file(*f))
                {
                    return status_cannot_delete;
                }

                f->handle.set_delete_on_close(wants_delete);

                return STATUS_SUCCESS;
            }

            if (info_class == FilePositionInformation)
            {
                if (!f->handle)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (io_status_block)
                {
                    IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                    block.Information = sizeof(FILE_POSITION_INFORMATION);
                    io_status_block.write(block);
                }

                if (length != sizeof(FILE_POSITION_INFORMATION))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<FILE_POSITION_INFORMATION> info{c.emu, file_information};
                const auto i = info.read();

                if (!f->handle.seek_to(i.CurrentByteOffset.QuadPart))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                return STATUS_SUCCESS;
            }

            if (info_class == FileEndOfFileInformation)
            {
                if (!f->handle)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (length < sizeof(FILE_END_OF_FILE_INFORMATION))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                if (!f->handle.is_writable())
                {
                    return STATUS_ACCESS_DENIED;
                }

                const auto info = c.emu.read_memory<FILE_END_OF_FILE_INFORMATION>(file_information);

                // A mapped view keeps the file from shrinking under it.
                constexpr auto status_user_mapped_file = static_cast<NTSTATUS>(0xC0000243);
                const windows_path file_path{f->name};
                for (const auto& view : c.proc.file_section_views | std::views::values)
                {
                    if (windows_path{view.file_name} == file_path &&
                        static_cast<uint64_t>(info.EndOfFile.QuadPart) < view.offset + view.length)
                    {
                        return status_user_mapped_file;
                    }
                }

                if (!f->handle.resize(info.EndOfFile.QuadPart))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                return STATUS_SUCCESS;
            }

            if (info_class == FileAllocationInformation)
            {
                return STATUS_SUCCESS;
            }

            c.win_emu.log.error("Unsupported set file info class: 0x%X\n", info_class);
            c.emu.stop();

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtQueryVolumeInformationFile(const syscall_context& c, const handle file_handle,
                                                     const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                                     const uint64_t fs_information, const ULONG length,
                                                     const FS_INFORMATION_CLASS fs_information_class)
        {
            switch (fs_information_class)
            {
            case FileFsDeviceInformation:
                return handle_query<FILE_FS_DEVICE_INFORMATION>(
                    c.emu, fs_information, length, io_status_block, [&](FILE_FS_DEVICE_INFORMATION& info) {
                        const auto* device = c.proc.devices.get(file_handle);
                        const auto device_name = device ? device->get_device_name() : std::u16string_view{};
                        // GetFileType reports these as FILE_TYPE_PIPE: AFD registers its sockets as named pipe devices.
                        if ((device && device->get_internal_device<named_pipe>()) || device_name == u"NamedPipe" ||
                            device_name.starts_with(u"Afd"))
                        {
                            info.DeviceType = FILE_DEVICE_NAMED_PIPE;
                            info.Characteristics = 0;
                        }
                        else if (file_handle == STDOUT_HANDLE || file_handle == STDIN_HANDLE || file_handle == CONSOLE_HANDLE)
                        {
                            info.DeviceType = FILE_DEVICE_CONSOLE;
                            info.Characteristics = 0x20000;
                        }
                        else if (file_handle == NUL_HANDLE)
                        {
                            info.DeviceType = FILE_DEVICE_NULL;
                            info.Characteristics = FILE_DEVICE_SECURE_OPEN;
                        }
                        else
                        {
                            info.DeviceType = FILE_DEVICE_DISK;
                            info.Characteristics = 0x20020;
                        }
                    });

            case FileFsSizeInformation:
                return handle_query<FILE_FS_SIZE_INFORMATION>(c.emu, fs_information, length, io_status_block,
                                                              [&](FILE_FS_SIZE_INFORMATION& info) {
                                                                  info.BytesPerSector = 0x1000;
                                                                  info.SectorsPerAllocationUnit = 0x1000;
                                                                  info.TotalAllocationUnits.QuadPart = 0x10000;
                                                                  info.AvailableAllocationUnits.QuadPart = 0x1000;
                                                              });

            case FileFsFullSizeInformation:
                return handle_query<FILE_FS_FULL_SIZE_INFORMATION>(c.emu, fs_information, length, io_status_block,
                                                                   [&](FILE_FS_FULL_SIZE_INFORMATION& info) {
                                                                       info.BytesPerSector = 0x1000;
                                                                       info.SectorsPerAllocationUnit = 0x1000;
                                                                       info.TotalAllocationUnits.QuadPart = 0x10000;
                                                                       info.CallerAvailableAllocationUnits.QuadPart = 0x1000;
                                                                       info.ActualAvailableAllocationUnits.QuadPart = 0x1000;
                                                                   });

            case FileFsVolumeInformation:
                return handle_query<FILE_FS_VOLUME_INFORMATION>(c.emu, fs_information, length, io_status_block,
                                                                [&](FILE_FS_VOLUME_INFORMATION& info) {
                                                                    // The serial FileIdInformation and FileStatBasicInformation report, so
                                                                    // st_dev matches.
                                                                    if (const auto* f = c.proc.files.get(file_handle))
                                                                    {
                                                                        info.VolumeSerialNumber = f->drive_number;
                                                                    }
                                                                });

            case FileFsAttributeInformation:
                return handle_query<_FILE_FS_ATTRIBUTE_INFORMATION>(
                    c.emu, fs_information, length, io_status_block, [&](_FILE_FS_ATTRIBUTE_INFORMATION& info) {
                        info.FileSystemAttributes = 0x40006; // FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_NAMED_STREAMS
                        info.MaximumComponentNameLength = 255;
                        constexpr auto name = u"NTFS"sv;
                        info.FileSystemNameLength = static_cast<ULONG>(name.size() * sizeof(char16_t));
                        memcpy(info.FileSystemName, name.data(), info.FileSystemNameLength);
                    });

            default:
                c.win_emu.log.error("Unsupported fs info class: 0x%X\n", fs_information_class);
                c.emu.stop();
                return write_io_status(io_status_block, STATUS_NOT_SUPPORTED, true);
            }
        }

        // Host filesystem timestamps are real wall-clock time, not virtualized like KUSER_SHARED_DATA's clock -
        // under the deterministic instruction-tick clock (windows_emulator::uses_relative_time), two runs that
        // touch the same file at different real moments would otherwise observe different values. Substitute a
        // fixed point in time instead of zeroing: a zero FILETIME is the 1601 epoch, and some directory
        // enumeration consumers reject entries with a timestamp older than 1970 (see PR #1210).
        LARGE_INTEGER get_file_time(const bool deterministic, const timespec ts)
        {
            if (deterministic)
            {
                return utils::convert_unix_to_windows_time(1700000000); // 2023-11-14, arbitrary but fixed
            }

            return convert_timespec_to_filetime(ts);
        }

        std::vector<file_entry> scan_directory(const file_system& file_sys, const windows_path& win_path,
                                               const std::u16string_view file_mask, const bool deterministic_time)
        {
            std::vector<file_entry> files{};

            // The host's own junctions and links show in host mode (in root mode their targets are host paths). An exact
            // name (the usual lookup of one file, also by its short name) asks the host for that entry only.
            const auto host_reparse_points = file_sys.is_host_mode();
            const auto exact = !file_mask.empty() && file_mask.find_first_of(u"*?<>\"") == std::u16string_view::npos;
            const auto host_entries = host_reparse_points
                                          ? compat_host_entries(file_sys.translate(win_path), exact ? std::u16string(file_mask) : u"*")
                                          : std::map<std::u16string, compat_host_entry>{};
            const auto make_file_entry = [deterministic_time, host_reparse_points,
                                          &host_entries](const std::filesystem::path& file_path, const bool is_directory,
                                                         const std::optional<struct compat_stat>& file_stat) {
                file_entry entry{.file_path = file_path, .is_directory = is_directory};
                if (const auto host_entry = host_entries.find(file_path.u16string()); host_entry != host_entries.end())
                {
                    entry.short_name = host_entry->second.short_name;
                    // The host's own junctions and links show in host mode (in root mode their targets are host paths).
                    entry.reparse_tag = host_reparse_points ? host_entry->second.reparse_tag : 0;
                }

                if (file_stat)
                {
                    entry.file_size = is_directory ? 0 : static_cast<uint64_t>(file_stat->st_size);
                    entry.read_only = (host_file_attributes(*file_stat) & file_attribute_readonly) != 0;
                    entry.creation_time = get_file_time(deterministic_time, file_stat->st_ctimespec);
                    entry.last_access_time = get_file_time(deterministic_time, file_stat->st_atimespec);
                    entry.last_write_time = get_file_time(deterministic_time, file_stat->st_mtimespec);
                }

                return entry;
            };

            if (file_mask.empty() || file_mask == u"*")
            {
                const auto normalized = win_path.lexically_normal();
                files.emplace_back(make_file_entry(".", true, file_sys.stat(normalized)));
                files.emplace_back(make_file_entry("..", true, file_sys.stat(normalized.parent())));
            }

            for (const auto& entry : file_sys.list_directory(win_path))
            {
                // A mask matches the name or the 8.3 name (GetLongPathName looks up PROGRA~1).
                if (!file_mask.empty() && !utils::wildcard::match_filename(entry.name, file_mask) &&
                    (entry.short_name.empty() || !utils::wildcard::match_filename(entry.short_name, file_mask)))
                {
                    continue;
                }

                auto file = make_file_entry(entry.name, entry.is_directory, entry.stat);
                if (!entry.short_name.empty())
                {
                    file.short_name = entry.short_name;
                }
                files.emplace_back(std::move(file));
            }

            return files;
        }

        template <typename T>
        NTSTATUS handle_file_enumeration(const syscall_context& c,
                                         const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                         const uint64_t file_information, const uint32_t length, const ULONG query_flags,
                                         const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> file_mask, file* f)
        {
            if (!f->enumeration_state || query_flags & SL_RESTART_SCAN)
            {
                const auto mask = file_mask ? read_unicode_string(c.emu, file_mask) : u"";
                c.win_emu.callbacks.on_generic_access("Enumerating directory", f->name + mask);

                f->enumeration_state.emplace(file_enumeration_state{});
                f->enumeration_state->files = scan_directory(c.win_emu.file_sys, f->name, mask, c.win_emu.uses_relative_time());
                if (!c.proc.reparse_points.empty())
                {
                    for (auto& entry : f->enumeration_state->files)
                    {
                        if (const auto tag = emulated_reparse_tag_at(c.proc, f->name + u"\\" + entry.file_path.u16string()))
                        {
                            entry.reparse_tag = tag;
                        }
                    }
                }
            }

            auto& enum_state = *f->enumeration_state;

            uint64_t current_offset{0};
            emulator_object<T> object{c.emu.memory()};

            size_t current_index = enum_state.current_index;

            if (current_index >= enum_state.files.size())
            {
                IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                block.Information = 0;
                io_status_block.write(block);

                return STATUS_NO_MORE_FILES;
            }

            do
            {
                const auto new_offset = align_up(current_offset, 8);
                const auto& current_file = enum_state.files[current_index];
                const auto file_name = current_file.file_path.u16string();
                const auto required_size = sizeof(T) + (file_name.size() * 2) - 2;
                const auto end_offset = new_offset + required_size;

                if (end_offset > length)
                {
                    if (current_offset == 0)
                    {
                        IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                        block.Information = end_offset;
                        io_status_block.write(block);

                        return STATUS_BUFFER_OVERFLOW;
                    }

                    break;
                }

                if (object)
                {
                    const auto object_offset = object.value() - file_information;

                    object.access([&](T& dir_info) {
                        dir_info.NextEntryOffset = static_cast<ULONG>(new_offset - object_offset); //
                    });
                }

                T info{};
                info.NextEntryOffset = 0;
                info.FileIndex = static_cast<ULONG>(current_index);

                info.CreationTime = current_file.creation_time;
                info.LastAccessTime = current_file.last_access_time;
                info.LastWriteTime = current_file.last_write_time;
                info.ChangeTime = info.LastWriteTime;

                // As host_file_attributes: directories, or archived files, read-only where the host says so.
                constexpr ULONG file_attribute_archive = 0x20;
                const ULONG attributes = (current_file.is_directory ? FILE_ATTRIBUTE_DIRECTORY : file_attribute_archive) |
                                         (current_file.read_only ? file_attribute_readonly : 0);
                info.FileAttributes = with_reparse_attribute(attributes, current_file.reparse_tag);
                info.FileNameLength = static_cast<ULONG>(file_name.size() * 2);
                info.EndOfFile.QuadPart = current_file.file_size;

                // For a reparse point, the EA size field holds its tag.
                if constexpr (requires { info.EaSize; })
                {
                    info.EaSize = current_file.reparse_tag;
                }

                if constexpr (requires { info.ShortName; })
                {
                    const auto short_length = std::min(current_file.short_name.size(), std::size(info.ShortName));
                    std::copy_n(current_file.short_name.begin(), short_length, std::begin(info.ShortName));
                    info.ShortNameLength = static_cast<char>(short_length * sizeof(char16_t));
                }

                object.set_address(file_information + new_offset);
                object.write(info);

                c.emu.write_memory(object.value() + offsetof(T, FileName), file_name.data(), info.FileNameLength);

                ++current_index;
                current_offset = end_offset;
            } while ((query_flags & SL_RETURN_SINGLE_ENTRY) == 0 && current_index < enum_state.files.size());

            if ((query_flags & SL_NO_CURSOR_UPDATE) == 0)
            {
                enum_state.current_index = current_index;
            }

            IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
            block.Information = current_offset;
            io_status_block.write(block);

            return current_index <= enum_state.files.size() ? STATUS_SUCCESS : STATUS_NO_MORE_FILES;
        }

        NTSTATUS handle_NtQueryDirectoryFileEx(const syscall_context& c, const handle file_handle, const handle /*event_handle*/,
                                               const EMULATOR_CAST(emulator_pointer, PIO_APC_ROUTINE) /*apc_routine*/,
                                               const emulator_pointer /*apc_context*/,
                                               const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                               const uint64_t file_information, const uint32_t length, const uint32_t info_class,
                                               const ULONG query_flags,
                                               const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> file_name)
        {
            auto* f = c.proc.files.get(file_handle);
            if (!f || !f->is_directory())
            {
                return STATUS_INVALID_HANDLE;
            }

            if (info_class == FileDirectoryInformation)
            {
                return handle_file_enumeration<FILE_DIRECTORY_INFORMATION>(c, io_status_block, file_information, length, query_flags,
                                                                           file_name, f);
            }

            if (info_class == FileFullDirectoryInformation)
            {
                return handle_file_enumeration<FILE_FULL_DIR_INFORMATION>(c, io_status_block, file_information, length, query_flags,
                                                                          file_name, f);
            }

            if (info_class == FileBothDirectoryInformation)
            {
                return handle_file_enumeration<FILE_BOTH_DIR_INFORMATION>(c, io_status_block, file_information, length, query_flags,
                                                                          file_name, f);
            }

            if (info_class == FileIdBothDirectoryInformation)
            {
                return handle_file_enumeration<FILE_ID_BOTH_DIR_INFORMATION>(c, io_status_block, file_information, length, query_flags,
                                                                             file_name, f);
            }

            c.win_emu.log.error("Unsupported query directory file info class: %X\n", info_class);
            c.emu.stop();

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtQueryDirectoryFile(const syscall_context& c, const handle file_handle, const handle event_handle,
                                             const EMULATOR_CAST(emulator_pointer, PIO_APC_ROUTINE) apc_routine,
                                             const emulator_pointer apc_context,
                                             const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                             const uint64_t file_information, const uint32_t length, const uint32_t info_class,
                                             const BOOLEAN return_single_entry,
                                             const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> file_name,
                                             const BOOLEAN restart_scan)
        {
            ULONG query_flags = 0;
            if (return_single_entry)
            {
                query_flags |= SL_RETURN_SINGLE_ENTRY;
            }
            if (restart_scan)
            {
                query_flags |= SL_RESTART_SCAN;
            }
            return handle_NtQueryDirectoryFileEx(c, file_handle, event_handle, apc_routine, apc_context, io_status_block, file_information,
                                                 length, info_class, query_flags, file_name);
        }

        NTSTATUS handle_NtQueryInformationFile(const syscall_context& c, const handle file_handle,
                                               const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                               const uint64_t file_information, uint32_t length, const uint32_t info_class)
        {
            if (info_class == 0 || info_class >= FileMaximumInformation)
            {
                return STATUS_INVALID_INFO_CLASS;
            }

            auto block = io_status_block.try_read();
            if (!block.has_value())
            {
                return STATUS_ACCESS_VIOLATION;
            }

            const auto _ = utils::finally([&] {
                if (io_status_block)
                {
                    (void)io_status_block.try_write(block.value());
                }
            });

            const auto ret = [&](const NTSTATUS status, size_t size = 0) {
                block->Status = status;
                block->Information = size;
                return status;
            };

            const auto write_information = [&](const auto& information) {
                if (length < sizeof(information))
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }
                c.emu.write_memory(file_information, information);
                return ret(STATUS_SUCCESS, sizeof(information));
            };

            // As console handles (ConDrv) answer on Windows 11: these four classes, nothing else. Callers such as Python's
            // stdio setup take STATUS_INVALID_HANDLE for a closed stream.
            if (file_handle == STDOUT_HANDLE || file_handle == STDIN_HANDLE)
            {
                switch (info_class)
                {
                case FileAccessInformation: {
                    constexpr ACCESS_MASK file_generic_read_write = 0x12019F;
                    return write_information(FILE_ACCESS_INFORMATION{file_generic_read_write});
                }
                case FilePositionInformation:
                    return write_information(FILE_POSITION_INFORMATION{});
                case FileModeInformation:
                    return write_information(FILE_MODE_INFORMATION{FILE_SYNCHRONOUS_IO_NONALERT});
                case FileAlignmentInformation:
                    return write_information(FILE_ALIGNMENT_INFORMATION{FILE_BYTE_ALIGNMENT});
                default:
                    return ret(STATUS_INVALID_DEVICE_REQUEST);
                }
            }

            if (const auto* container = c.proc.devices.get(file_handle))
            {
                if (const auto* pipe = container->get_internal_device<named_pipe>())
                {
                    switch (info_class)
                    {
                    case FileModeInformation:
                        return write_information(FILE_MODE_INFORMATION{pipe->create_options & FILE_MODE_MASK});
                    case FileAccessInformation:
                        return write_information(FILE_ACCESS_INFORMATION{container->granted_access});
                    case FilePipeInformation:
                        return write_information(std::array<ULONG, 2>{pipe->read_mode, pipe->completion_mode});
                    // A pipe has no position: it reads as 0, and setting it is ignored (so SetFilePointerEx succeeds, and
                    // CPython opens a pipe with open(name, 'w+b')).
                    case FilePositionInformation:
                        return write_information(FILE_POSITION_INFORMATION{});
                    // The end of a pipe is the data waiting to be read, which SetFilePointerEx(FILE_END) seeks past
                    // (CPython opens a pipe with open(fd, 'a')).
                    case FileStandardInformation: {
                        FILE_STANDARD_INFORMATION information{};
                        information.AllocationSize.QuadPart = static_cast<LONGLONG>(pipe->inbound_quota) + pipe->outbound_quota;
                        information.EndOfFile.QuadPart = pipe->bytes_available();
                        information.NumberOfLinks = 1;
                        return write_information(information);
                    }
                    default:
                        return ret(STATUS_INVALID_INFO_CLASS);
                    }
                }
            }

            const auto* f = c.proc.files.get(file_handle);
            if (!f)
            {
                // NUL is an empty file at position 0 whatever is written to it.
                if (file_handle == NUL_HANDLE && (info_class == FilePositionInformation || info_class == FileStandardInformation))
                {
                    if (info_class == FilePositionInformation)
                    {
                        if (length < sizeof(FILE_POSITION_INFORMATION))
                        {
                            return ret(STATUS_INFO_LENGTH_MISMATCH);
                        }
                        c.emu.write_memory(file_information, FILE_POSITION_INFORMATION{});
                        return ret(STATUS_SUCCESS, sizeof(FILE_POSITION_INFORMATION));
                    }

                    if (length < sizeof(FILE_STANDARD_INFORMATION))
                    {
                        return ret(STATUS_INFO_LENGTH_MISMATCH);
                    }
                    FILE_STANDARD_INFORMATION i{};
                    i.NumberOfLinks = 1;
                    c.emu.write_memory(file_information, i);
                    return ret(STATUS_SUCCESS, sizeof(FILE_STANDARD_INFORMATION));
                }

                return ret(STATUS_INVALID_HANDLE);
            }

            if (info_class == FileAttributeTagInformation)
            {
                if (!f->handle && !f->is_directory())
                {
                    return ret(STATUS_NOT_SUPPORTED);
                }

                constexpr auto required_length = sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                const emulator_object<FILE_ATTRIBUTE_TAG_INFORMATION> info{c.emu, file_information};
                FILE_ATTRIBUTE_TAG_INFORMATION i{};

                struct compat_stat file_stat{};
                if (!stat_open_file(*f, file_stat))
                {
                    return ret(STATUS_INVALID_HANDLE);
                }
                i.ReparseTag = reparse_tag_at(c, f->name);
                i.FileAttributes = with_reparse_attribute(host_file_attributes(file_stat), i.ReparseTag);

                info.write(i);

                return ret(STATUS_SUCCESS, required_length);
            }

            if (info_class == FileIsRemoteDeviceInformation)
            {
                if (!f->handle)
                {
                    return ret(STATUS_NOT_SUPPORTED);
                }

                constexpr auto required_length = sizeof(FILE_IS_REMOTE_DEVICE_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                const emulator_object<FILE_IS_REMOTE_DEVICE_INFORMATION> info{c.emu, file_information};
                FILE_IS_REMOTE_DEVICE_INFORMATION i{};

                i.IsRemote = FALSE;

                info.write(i);

                return ret(STATUS_SUCCESS, required_length);
            }

            if (info_class == FileRemoteProtocolInformation)
            {
                return ret(STATUS_INVALID_PARAMETER);
            }

            if (info_class == FileIdInformation)
            {
                constexpr auto required_length = sizeof(FILE_ID_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                struct compat_stat file_stat{};
                if (!stat_open_file(*f, file_stat))
                {
                    return ret(STATUS_INVALID_HANDLE);
                }

                const emulator_object<FILE_ID_INFORMATION> info{c.emu, file_information};
                FILE_ID_INFORMATION i{};

                i.VolumeSerialNumber = f->drive_number;
                memset(&i.FileId, 0, sizeof(i.FileId));
                memcpy(&i.FileId.Identifier[0], &file_stat.st_ino, sizeof(file_stat.st_ino));

                info.write(i);

                return ret(STATUS_SUCCESS, required_length);
            }

            if (info_class == FileStreamInformation)
            {
                const std::u16string stream_name = u"::$DATA";
                const auto stream_name_len = static_cast<uint32_t>(stream_name.size() * sizeof(char16_t));

                const uint32_t required_length = offsetof(FILE_STREAM_INFORMATION, StreamName) + stream_name_len;

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                struct compat_stat file_stat{};
                if (!stat_open_file(*f, file_stat))
                {
                    return ret(STATUS_INVALID_HANDLE);
                }

                FILE_STREAM_INFORMATION info{};
                info.NextEntryOffset = 0;
                info.StreamNameLength = stream_name_len;

                if (f->is_directory())
                {
                    info.StreamSize.QuadPart = 0;
                    info.StreamAllocationSize.QuadPart = 0;
                }
                else
                {
                    info.StreamSize.QuadPart = file_stat.st_size;
                    info.StreamAllocationSize.QuadPart = file_stat.st_size;
                }

                c.emu.write_memory(file_information, info);
                c.emu.write_memory(file_information + offsetof(FILE_STREAM_INFORMATION, StreamName), stream_name.c_str(), stream_name_len);

                return ret(STATUS_SUCCESS, required_length);
            }

            if (info_class == FileVolumeNameInformation)
            {
                const auto volume_name = u8_to_u16("\\Device\\HarddiskVolume" + std::to_string(f->drive_number));
                const auto name_bytes = static_cast<uint32_t>(volume_name.size() * sizeof(char16_t));

                const uint32_t required_length = offsetof(FILE_VOLUME_NAME_INFORMATION, DeviceName) + name_bytes;

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                FILE_VOLUME_NAME_INFORMATION vni{};
                vni.DeviceNameLength = name_bytes;

                c.emu.write_memory(file_information, vni);
                c.emu.write_memory(file_information + offsetof(FILE_VOLUME_NAME_INFORMATION, DeviceName), volume_name.c_str(), name_bytes);

                return ret(STATUS_SUCCESS, required_length);
            }

            const auto all_info = info_class == FileAllInformation;
            size_t all_length = 0;

            if (all_info && length < sizeof(FILE_ALL_INFORMATION))
            {
                return ret(STATUS_INFO_LENGTH_MISMATCH);
            }

            if (info_class == FileBasicInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_BASIC_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                struct compat_stat file_stat{};
                if (!stat_open_file(*f, file_stat))
                {
                    return STATUS_INVALID_HANDLE;
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, BasicInformation);
                }

                const emulator_object<FILE_BASIC_INFORMATION> info{c.emu, address};
                FILE_BASIC_INFORMATION i{};
                i.CreationTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_ctimespec);
                i.LastAccessTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_atimespec);
                i.LastWriteTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_mtimespec);
                i.ChangeTime = i.LastWriteTime;
                i.FileAttributes = with_reparse_attribute(host_file_attributes(file_stat), reparse_tag_at(c, f->name));

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileStandardInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_STANDARD_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, StandardInformation);
                }

                const emulator_object<FILE_STANDARD_INFORMATION> info{c.emu, address};
                FILE_STANDARD_INFORMATION i{};
                i.Directory = f->is_directory() ? TRUE : FALSE;
                // Hard links (CreateHardLink, os.link) count.
                struct compat_stat link_stat{};
                i.NumberOfLinks = stat_open_file(*f, link_stat) && link_stat.st_nlink > 0 ? link_stat.st_nlink : 1;

                if (f->handle)
                {
                    i.EndOfFile.QuadPart = f->handle.size();
                    i.AllocationSize.QuadPart = static_cast<LONGLONG>(align_up(i.EndOfFile.QuadPart, 512));
                }

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileInternalInformation || all_info)
            {
                const uint32_t required_length = sizeof(FILE_INTERNAL_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                struct compat_stat file_stat{};
                if (!stat_open_file(*f, file_stat))
                {
                    return STATUS_INVALID_HANDLE;
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, InternalInformation);
                }

                const emulator_object<FILE_INTERNAL_INFORMATION> info{c.emu, address};
                FILE_INTERNAL_INFORMATION i{};

                i.IndexNumber.QuadPart = static_cast<LONGLONG>(file_stat.st_ino);

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileEaInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_EA_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, EaInformation);
                }
                const emulator_object<FILE_EA_INFORMATION> info{c.emu, address};
                FILE_EA_INFORMATION i{};

                i.EaSize = 0;

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileAccessInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_ACCESS_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, AccessInformation);
                }

                const emulator_object<FILE_ACCESS_INFORMATION> info{c.emu, address};
                FILE_ACCESS_INFORMATION i{};

                i.AccessFlags = f->access_mask;

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FilePositionInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_POSITION_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, PositionInformation);
                }

                const emulator_object<FILE_POSITION_INFORMATION> info{c.emu, address};
                FILE_POSITION_INFORMATION i{};

                i.CurrentByteOffset.QuadPart = f->handle ? f->handle.tell() : 0;

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileModeInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_MODE_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, ModeInformation);
                }

                const emulator_object<FILE_MODE_INFORMATION> info{c.emu, address};
                FILE_MODE_INFORMATION i{};

                i.Mode = f->file_mode;

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileAlignmentInformation || all_info)
            {
                constexpr auto required_length = sizeof(FILE_ALIGNMENT_INFORMATION);

                if (length < required_length)
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, AlignmentInformation);
                }

                const emulator_object<FILE_ALIGNMENT_INFORMATION> info{c.emu, address};
                FILE_ALIGNMENT_INFORMATION i{};

                i.AlignmentRequirement = FILE_BYTE_ALIGNMENT;

                info.write(i);

                if (!all_info)
                {
                    return ret(STATUS_SUCCESS, required_length);
                }

                length -= required_length;
                all_length += required_length;
            }

            if (info_class == FileNameInformation || info_class == FileNormalizedNameInformation || all_info)
            {
                // In the case the file system keeps, as GetFinalPathNameByHandle reports it.
                const auto relative_path = c.win_emu.file_sys.true_case(f->name);
                const auto required_length = static_cast<uint32_t>((relative_path.size() * 2) + offsetof(FILE_NAME_INFORMATION, FileName));

                if (length < sizeof(FILE_NAME_INFORMATION))
                {
                    return ret(STATUS_INFO_LENGTH_MISMATCH);
                }

                const uint32_t copy_length = std::min(length, required_length) - offsetof(FILE_NAME_INFORMATION, FileName);

                auto address = file_information;
                if (all_info)
                {
                    address += offsetof(FILE_ALL_INFORMATION, NameInformation);
                }

                c.emu.write_memory(address, FILE_NAME_INFORMATION{
                                                .FileNameLength = static_cast<ULONG>(relative_path.size() * 2),
                                                .FileName = {},
                                            });

                c.emu.write_memory(address + offsetof(FILE_NAME_INFORMATION, FileName), relative_path.c_str(), copy_length);

                const uint32_t total_copied = copy_length + offsetof(FILE_NAME_INFORMATION, FileName);

                if (!all_info)
                {
                    return ret(total_copied == required_length ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW, total_copied);
                }

                length -= total_copied;
                all_length += total_copied;
            }

            if (all_info)
            {
                return ret(STATUS_SUCCESS, all_length);
            }

            c.win_emu.log.error("Unsupported query file info class: 0x%X\n", info_class);
            c.emu.stop();

            return ret(STATUS_NOT_SUPPORTED);
        }

        NTSTATUS handle_NtQueryInformationByName(const syscall_context& c,
                                                 const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                                 const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                                 const uint64_t file_information, const uint32_t length, const uint32_t info_class)
        {
            IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
            block.Status = STATUS_SUCCESS;
            block.Information = 0;

            const auto _ = utils::finally([&] {
                if (io_status_block)
                {
                    (void)io_status_block.try_write(block);
                }
            });

            const auto attributes = object_attributes.read();
            auto filename = resolve_volume_device_path(resolve_system_root_path(c, read_unicode_string(c.emu, attributes.ObjectName)));

            c.win_emu.callbacks.on_generic_access("Query file info", filename);

            const auto ret = [&](const NTSTATUS status) {
                block.Status = status;
                return status;
            };

            // Devices have no by-name information; callers such as Python's os.stat fall back to opening them.
            std::u16string filename_upper = filename;
            std::ranges::transform(filename_upper, filename_upper.begin(), ::towupper);
            if (filename_upper == u"\\??\\NUL")
            {
                return ret(STATUS_INVALID_INFO_CLASS);
            }
            if (filename_upper == u"\\??\\CON" || filename_upper == u"\\??\\CONIN$" || filename_upper == u"\\??\\CONOUT$")
            {
                return ret(STATUS_INVALID_PARAMETER);
            }

            if (info_class == FileStatBasicInformation)
            {
                block.Information = sizeof(EMU_FILE_STAT_BASIC_INFORMATION);

                if (length < block.Information)
                {
                    return ret(STATUS_BUFFER_OVERFLOW);
                }

                // The name itself, not where a link at its end leads (as an open with FILE_OPEN_REPARSE_POINT).
                const auto resolved = resolve_reparse_points(c.proc, filename, false);
                if (!resolved)
                {
                    return ret(status_reparse_point_not_resolved);
                }

                const auto filepath = windows_path(*resolved);
                if (filepath.is_relative())
                {
                    return ret(STATUS_OBJECT_NAME_NOT_FOUND);
                }

                const auto file_stat_result = c.win_emu.file_sys.stat(filepath);
                if (!file_stat_result)
                {
                    return ret(STATUS_OBJECT_NAME_NOT_FOUND);
                }

                const auto& file_stat = *file_stat_result;

                const auto is_directory = (file_stat.st_mode & S_IFDIR) != 0;

                EMU_FILE_STAT_BASIC_INFORMATION i{};

                i.CreationTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_ctimespec);
                i.LastAccessTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_atimespec);
                i.LastWriteTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_mtimespec);
                i.ChangeTime = i.LastWriteTime;
                i.ReparseTag = reparse_tag_at(c, *resolved);
                i.FileAttributes = with_reparse_attribute(host_file_attributes(file_stat), i.ReparseTag);
                i.NumberOfLinks = file_stat.st_nlink > 0 ? file_stat.st_nlink : 1;
                i.FileId.QuadPart = static_cast<LONGLONG>(file_stat.st_ino);
                memcpy(&i.FileId128.Identifier[0], &file_stat.st_ino, sizeof(file_stat.st_ino));
                if (const auto drive = filepath.get_drive())
                {
                    i.VolumeSerialNumber.QuadPart = *drive - 'a' + 1;
                }
                // Python's os.path.isfile counts only files on disk devices as regular files.
                i.DeviceType = FILE_DEVICE_DISK;
                i.DeviceCharacteristics = 0x20020;

                const auto file_size = is_directory ? 0LL : file_stat.st_size;
                i.EndOfFile.QuadPart = file_size;
                i.AllocationSize.QuadPart = static_cast<LONGLONG>(align_up(file_size, 512));

                c.emu.write_memory(file_information, i);

                return ret(STATUS_SUCCESS);
            }

            c.win_emu.log.error("Unsupported query name info class: %X\n", info_class);
            c.emu.stop();

            return ret(STATUS_NOT_SUPPORTED);
        }

        void commit_file_data(const std::string_view data, memory_interface& emu,
                              const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, const uint64_t buffer)
        {
            if (io_status_block)
            {
                IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                block.Information = data.size();
                io_status_block.write(block);
            }

            emu.write_memory(buffer, data.data(), data.size());
        }

        void write_lock_io_status(const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, const NTSTATUS status,
                                  const uint64_t information = 0)
        {
            if (!io_status_block)
            {
                return;
            }

            IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
            block.Status = status;
            block.Information = information;
            io_status_block.write(block);
        }

        std::optional<uint64_t> get_lock_range_end(const LARGE_INTEGER& byte_offset, const LARGE_INTEGER& length)
        {
            if (byte_offset.QuadPart < 0 || length.QuadPart == 0)
            {
                return std::nullopt;
            }

            const auto offset = static_cast<uint64_t>(byte_offset.QuadPart);
            const auto range_length = static_cast<uint64_t>(length.QuadPart);
            if (offset > std::numeric_limits<uint64_t>::max() - range_length)
            {
                return std::nullopt;
            }

            return offset + range_length;
        }

        bool does_lock_range_overlap(const file_lock_range& existing, const uint64_t offset, const uint64_t end)
        {
            const auto existing_end = existing.offset + existing.length;
            return existing.offset < end && offset < existing_end;
        }

        // Completion of an asynchronous (overlapped) file operation: signal the optional completion event and,
        // for an APC-based request (ReadFileEx/WriteFileEx), queue the I/O completion APC on the issuing thread.
        // The APC routine follows the PIO_APC_ROUTINE contract (ApcContext, IoStatusBlock, Reserved); it is
        // delivered the next time the thread enters an alertable wait.
        void deliver_file_io_completion(const syscall_context& c, const uint64_t event, const uint64_t apc_routine,
                                        const uint64_t apc_context,
                                        const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                        const NTSTATUS status, const uint64_t information)
        {
            if (event)
            {
                if (auto* e = c.proc.events.get(event))
                {
                    e->signaled = true;
                    c.win_emu.wake_idle_vcpu();
                }
            }

            if (apc_routine)
            {
                // A WoW64 completion routine (kernel32!BasepIoCompletion) reads the I/O status block with the
                // 32-bit layout (NTSTATUS Status @0, ULONG Information @4). Our 64-bit block keeps Information at
                // @8, so the 32-bit reader would see 0 bytes transferred. Mirror Status/Information into the
                // 32-bit slots so the completion routine reports the correct byte count.
                if (c.proc.is_wow64_process && io_status_block)
                {
                    const auto status32 = static_cast<uint32_t>(static_cast<ULONG>(status));
                    const auto information32 = static_cast<uint32_t>(information);
                    c.emu.write_memory(io_status_block.value(), &status32, sizeof(status32));
                    c.emu.write_memory(io_status_block.value() + sizeof(status32), &information32, sizeof(information32));
                }

                c.thread().pending_apcs.push_back({
                    .flags = 0,
                    .apc_routine = apc_routine,
                    .apc_argument1 = apc_context,
                    .apc_argument2 = io_status_block.value(),
                    .apc_argument3 = 0,
                    .restamp_io_status_block = c.proc.is_wow64_process && io_status_block,
                    .io_status = static_cast<int32_t>(static_cast<ULONG>(status)),
                    .io_information = static_cast<uint32_t>(information),
                });
                c.win_emu.wake_idle_vcpu();
            }
        }

        NTSTATUS handle_pipe_io(const syscall_context& c, const handle file_handle, const uint64_t event, const uint64_t apc_routine,
                                const uint64_t apc_context, const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                const uint64_t buffer, const ULONG length, const bool reading)
        {
            auto* container = c.proc.devices.get(file_handle);
            auto* pipe = container ? container->get_internal_device<named_pipe>() : nullptr;
            if (!pipe)
            {
                return STATUS_OBJECT_TYPE_MISMATCH;
            }
            io_device_context context{c.emu};
            context.source_handle = file_handle;
            context.event = make_handle(event);
            context.apc_routine = apc_routine;
            context.apc_context = apc_context;
            context.io_status_block = io_status_block;
            context.input_buffer = buffer;
            context.input_buffer_length = length;
            context.output_buffer = buffer;
            context.output_buffer_length = length;
            context.vcpu = &c.vcpu;
            if (c.proc.is_wow64_process && io_status_block)
            {
                context.wow64_io_status_block.set_address(io_status_block.read().Pointer);
            }
            return pipe->start_io(c.win_emu, container->prepare_io_context(context), reading);
        }

        NTSTATUS handle_NtReadFile(const syscall_context& c, const handle file_handle, const uint64_t event, const uint64_t apc_routine,
                                   const uint64_t apc_context,
                                   const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, const uint64_t buffer,
                                   const ULONG length, const emulator_object<LARGE_INTEGER> byte_offset,
                                   const emulator_object<ULONG> /*key*/)
        {
            if (file_handle == STDIN_HANDLE)
            {
                const auto data = c.win_emu.console().read_input(length);
                commit_file_data(data, c.emu, io_status_block, buffer);
                return STATUS_SUCCESS;
            }

            std::string temp_buffer{};
            temp_buffer.resize(length);

            if (file_handle == NUL_HANDLE)
            {
                if (io_status_block)
                {
                    IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                    block.Information = 0;
                    io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            if (const auto* container = c.proc.devices.get(file_handle); container && container->get_internal_device<named_pipe>())
            {
                return handle_pipe_io(c, file_handle, event, apc_routine, apc_context, io_status_block, buffer, length, true);
            }

            const auto* f = c.proc.files.get(file_handle);
            if (!f)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (byte_offset)
            {
                const auto offset = byte_offset.read();
                const bool use_current_file_pointer = offset.LowPart == FILE_USE_FILE_POINTER_POSITION && offset.HighPart == -1;

                if (!use_current_file_pointer)
                {
                    if (offset.QuadPart < 0)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    if (!f->handle.seek_to(offset.QuadPart))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
            }

            const auto bytes_read = f->handle.read(std::as_writable_bytes(std::span(temp_buffer)));

            if (bytes_read > 0)
            {
                commit_file_data(std::string_view(temp_buffer.data(), bytes_read), c.emu, io_status_block, buffer);
                deliver_file_io_completion(c, event, apc_routine, apc_context, io_status_block, STATUS_SUCCESS, bytes_read);
                return STATUS_SUCCESS;
            }

            const auto status = length > 0 ? STATUS_END_OF_FILE : STATUS_SUCCESS;

            if (io_status_block)
            {
                IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                block.Status = status;
                block.Information = 0;
                io_status_block.write(block);
            }

            deliver_file_io_completion(c, event, apc_routine, apc_context, io_status_block, status, 0);
            return status;
        }

        NTSTATUS handle_NtCancelIoFile(const syscall_context& c, const handle file_handle,
                                       const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block)
        {
            if (!io_status_block)
            {
                return STATUS_INVALID_PARAMETER;
            }
            const auto resolved = c.proc.resolve_object_pseudo_handle(file_handle, c.vcpu.active_thread);
            if (auto* device = c.proc.devices.get(resolved))
            {
                device->cancel_io(c.win_emu, 0, c.thread().id);
            }
            else if (!c.proc.files.get(resolved) && resolved != STDIN_HANDLE && resolved != STDOUT_HANDLE && resolved != CONSOLE_HANDLE &&
                     resolved != NUL_HANDLE)
            {
                return STATUS_INVALID_HANDLE;
            }
            if (c.proc.is_wow64_process)
            {
                emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu32>>>{c.emu, io_status_block.value()}.write({});
            }
            else
            {
                io_status_block.write({});
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCancelIoFileEx(const syscall_context& c, const handle file_handle,
                                         const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_request_to_cancel,
                                         const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block)
        {
            if (!io_status_block)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto resolved_handle = c.proc.resolve_object_pseudo_handle(file_handle, c.vcpu.active_thread);
            auto* device = c.proc.devices.get(resolved_handle);
            if (!device)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (!device->cancel_io(c.win_emu, io_request_to_cancel.value()))
            {
                io_status_block.write(IO_STATUS_BLOCK<EmulatorTraits<Emu64>>{.Status = STATUS_NOT_FOUND, .Information = 0});
                return STATUS_NOT_FOUND;
            }

            io_status_block.write(IO_STATUS_BLOCK<EmulatorTraits<Emu64>>{.Status = STATUS_SUCCESS, .Information = 0});
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtWriteFile(const syscall_context& c, const handle file_handle, const uint64_t event, const uint64_t apc_routine,
                                    const uint64_t apc_context,
                                    const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, const uint64_t buffer,
                                    const ULONG length, const emulator_object<LARGE_INTEGER> byte_offset,
                                    const emulator_object<ULONG> /*key*/)
        {
            std::string temp_buffer{};
            temp_buffer.resize(length);
            c.emu.read_memory(buffer, temp_buffer.data(), temp_buffer.size());

            if (file_handle == STDOUT_HANDLE)
            {
                if (io_status_block)
                {
                    IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                    block.Information = length;
                    io_status_block.write(block);
                }

                c.win_emu.callbacks.on_stdout(temp_buffer);

                return STATUS_SUCCESS;
            }

            if (file_handle == NUL_HANDLE)
            {
                if (io_status_block)
                {
                    IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                    block.Information = length;
                    io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            if (const auto* container = c.proc.devices.get(file_handle); container && container->get_internal_device<named_pipe>())
            {
                return handle_pipe_io(c, file_handle, event, apc_routine, apc_context, io_status_block, buffer, length, false);
            }

            const auto* f = c.proc.files.get(file_handle);
            if (!f)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (!f->handle.is_writable())
            {
                return STATUS_ACCESS_DENIED;
            }

            if (byte_offset)
            {
                const auto offset = byte_offset.read();
                const bool use_end_of_file = offset.LowPart == FILE_WRITE_TO_END_OF_FILE && offset.HighPart == -1;
                const bool use_current_file_pointer = offset.LowPart == FILE_USE_FILE_POINTER_POSITION && offset.HighPart == -1;

                if (use_end_of_file)
                {
                    if (!f->handle.seek_to(0, SEEK_END))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                else if (!use_current_file_pointer)
                {
                    if (offset.QuadPart < 0)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    if (!f->handle.seek_to(offset.QuadPart))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
            }

            const auto bytes_written = f->handle.write(std::as_bytes(std::span(temp_buffer)));
            const auto flushed = f->handle.flush();
            const auto status = flushed && bytes_written == temp_buffer.size() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

            if (io_status_block)
            {
                IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                block.Status = status;
                block.Information = bytes_written;
                io_status_block.write(block);
            }

            return status;
        }

        NTSTATUS handle_NtCopyFileChunk(const syscall_context& c, const handle source_handle, const handle destination_handle,
                                        const handle /*event_handle*/,
                                        const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, const ULONG length,
                                        const emulator_object<LARGE_INTEGER> source_offset,
                                        const emulator_object<LARGE_INTEGER> destination_offset,
                                        const emulator_object<ULONG> /*source_key*/, const emulator_object<ULONG> /*destination_key*/,
                                        const ULONG /*flags*/)
        {
            const auto* source = c.proc.files.get(source_handle);
            const auto* destination = c.proc.files.get(destination_handle);
            if (!source || !destination || !source->handle || !destination->handle)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (!destination->handle.is_writable())
            {
                return STATUS_ACCESS_DENIED;
            }

            if (source_offset)
            {
                const auto offset = source_offset.read();
                if (offset.QuadPart < 0 || !source->handle.seek_to(offset.QuadPart))
                {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            std::string temp_buffer{};
            temp_buffer.resize(length);
            const auto bytes_read = source->handle.read(std::as_writable_bytes(std::span(temp_buffer)));

            if (destination_offset)
            {
                const auto offset = destination_offset.read();
                if (offset.QuadPart < 0 || !destination->handle.seek_to(offset.QuadPart))
                {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            const auto bytes_written = destination->handle.write(std::as_bytes(std::span(temp_buffer).first(bytes_read)));
            (void)destination->handle.flush();

            if (io_status_block)
            {
                IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                block.Information = bytes_written;
                io_status_block.write(block);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtLockFile(const syscall_context& c, const handle file_handle, const handle /*event_handle*/,
                                   const uint64_t /*apc_routine*/, const uint64_t /*apc_context*/,
                                   const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                   const emulator_object<LARGE_INTEGER> byte_offset, const emulator_object<LARGE_INTEGER> length,
                                   const ULONG key, const BOOLEAN fail_immediately, const BOOLEAN exclusive_lock)
        {
            if (!io_status_block || !byte_offset || !length)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto* f = c.proc.files.get(file_handle);
            if (!f || !f->is_file())
            {
                write_lock_io_status(io_status_block, STATUS_INVALID_HANDLE);
                return STATUS_INVALID_HANDLE;
            }

            const auto lock_offset = byte_offset.read();
            const auto lock_length = length.read();
            const auto lock_end = get_lock_range_end(lock_offset, lock_length);
            if (!lock_end)
            {
                write_lock_io_status(io_status_block, STATUS_INVALID_LOCK_RANGE);
                return STATUS_INVALID_LOCK_RANGE;
            }

            const auto offset = static_cast<uint64_t>(lock_offset.QuadPart);
            const auto range_length = static_cast<uint64_t>(lock_length.QuadPart);
            const auto is_exclusive = exclusive_lock != FALSE;
            const auto lock_key = f->handle.path().u16string();

            if (const auto lock_it = c.proc.file_locks.find(lock_key); lock_it != c.proc.file_locks.end())
            {
                for (const auto& existing : lock_it->second.locks)
                {
                    if (existing.owner == file_handle || !does_lock_range_overlap(existing, offset, *lock_end))
                    {
                        continue;
                    }

                    if (!existing.exclusive && !is_exclusive)
                    {
                        continue;
                    }

                    // Blocking lock completion is not modeled yet; surface the conflict immediately.
                    (void)fail_immediately;
                    write_lock_io_status(io_status_block, STATUS_LOCK_NOT_GRANTED);
                    return STATUS_LOCK_NOT_GRANTED;
                }
            }

            c.proc.file_locks[lock_key].locks.push_back(file_lock_range{
                .offset = offset,
                .length = range_length,
                .key = key,
                .exclusive = is_exclusive,
                .owner = file_handle,
            });

            write_lock_io_status(io_status_block, STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtUnlockFile(const syscall_context& c, const handle file_handle,
                                     const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                     const emulator_object<LARGE_INTEGER> byte_offset, const emulator_object<LARGE_INTEGER> length,
                                     const ULONG key)
        {
            if (!io_status_block || !byte_offset || !length)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto* f = c.proc.files.get(file_handle);
            if (!f || !f->is_file())
            {
                write_lock_io_status(io_status_block, STATUS_INVALID_HANDLE);
                return STATUS_INVALID_HANDLE;
            }

            const auto lock_offset = byte_offset.read();
            const auto lock_length = length.read();
            if (!get_lock_range_end(lock_offset, lock_length))
            {
                write_lock_io_status(io_status_block, STATUS_INVALID_LOCK_RANGE);
                return STATUS_INVALID_LOCK_RANGE;
            }

            const auto offset = static_cast<uint64_t>(lock_offset.QuadPart);
            const auto range_length = static_cast<uint64_t>(lock_length.QuadPart);
            const auto lock_key = f->handle.path().u16string();
            const auto lock_it = c.proc.file_locks.find(lock_key);
            if (lock_it == c.proc.file_locks.end())
            {
                write_lock_io_status(io_status_block, STATUS_RANGE_NOT_LOCKED);
                return STATUS_RANGE_NOT_LOCKED;
            }

            auto& locks = lock_it->second.locks;
            const auto entry = std::ranges::find_if(locks, [&](const file_lock_range& existing) {
                return existing.owner == file_handle && existing.offset == offset && existing.length == range_length && existing.key == key;
            });

            if (entry == locks.end())
            {
                write_lock_io_status(io_status_block, STATUS_RANGE_NOT_LOCKED);
                return STATUS_RANGE_NOT_LOCKED;
            }

            locks.erase(entry);
            if (locks.empty())
            {
                c.proc.file_locks.erase(lock_it);
            }

            write_lock_io_status(io_status_block, STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }

        constexpr std::u16string map_mode(const ACCESS_MASK desired_access, const ULONG create_disposition)
        {
            // Changing attributes or extended attributes writes no data: such an open reads the stream, so that it works
            // on a read-only file (os.chmod), as on Windows.
            const auto wants_write = (desired_access & (GENERIC_WRITE | FILE_WRITE_DATA)) != 0;
            const auto wants_read = (desired_access & (GENERIC_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE |
                                                       FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) != 0;

            if (desired_access & FILE_APPEND_DATA)
            {
                return u"a+b";
            }

            switch (create_disposition)
            {
            case FILE_CREATE:
            case FILE_SUPERSEDE:
                if (wants_write)
                {
                    return wants_read ? u"w+b" : u"wb";
                }
                break;

            case FILE_OPEN:
            case FILE_OPEN_IF:
                if (wants_write)
                {
                    return u"r+b";
                }
                if (wants_read)
                {
                    return u"rb";
                }
                break;

            case FILE_OVERWRITE:
            case FILE_OVERWRITE_IF:
                if (wants_write)
                {
                    return u"w+b";
                }
                break;

            default:
                break;
            }

            return {};
        }

        std::optional<std::u16string_view> get_io_device_name(const std::u16string_view filename)
        {
            constexpr std::u16string_view device_prefix = u"\\Device\\";
            if (filename.starts_with(device_prefix))
            {
                return filename.substr(device_prefix.size());
            }

            constexpr std::u16string_view unc_prefix = u"\\??\\";
            if (!filename.starts_with(unc_prefix))
            {
                return std::nullopt;
            }

            const auto path = filename.substr(unc_prefix.size());

            const std::set<std::u16string, std::less<>> devices{
                u"Nsi",
                u"MountPointManager",
                u"SogenGpu",
                u"SogenSteam",
            };

            if (devices.contains(path))
            {
                return path;
            }

            return std::nullopt;
        }

        NTSTATUS handle_named_pipe_create(const syscall_context& c, const emulator_object<handle>& out_handle,
                                          const std::u16string_view filename, const OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>& attributes,
                                          ACCESS_MASK desired_access, const ULONG create_options)
        {
            c.win_emu.callbacks.on_generic_access("Creating/opening named pipe", filename);

            io_device_creation_data data{};

            std::u16string device_name = u"NamedPipe";

            io_device_container container{device_name, c.win_emu, data};

            if (auto* pipe_device = container.get_internal_device<named_pipe>())
            {
                pipe_device->name = normalize_named_pipe_path(filename);
                container.granted_access = desired_access;
                pipe_device->create_options = create_options;
                container.inherit = (attributes.Attributes & OBJ_INHERIT) != 0;

                // A client connects to a server instance of that name that has no client yet; with every instance busy
                // the open fails with STATUS_PIPE_NOT_AVAILABLE (ERROR_PIPE_BUSY), without any with NOT_FOUND.
                auto server_exists = false;
                for (const auto& [index, existing] : c.proc.devices)
                {
                    (void)index;
                    auto* server = existing.get_internal_device<named_pipe>();
                    if (!server || !server->server || server->anonymous || windows_path(server->name) != windows_path(pipe_device->name))
                    {
                        continue;
                    }

                    server_exists = true;
                    if (server->unopened_peer)
                    {
                        pipe_device->copy_configuration(*server);
                        container.granted_access = desired_access;
                        pipe_device->create_options = create_options;
                        pipe_device->endpoint = std::move(server->unopened_peer);
                        break;
                    }
                }
                if (!pipe_device->endpoint && windows_path(pipe_device->name) != windows_path(u"\\Device\\NamedPipe\\"))
                {
                    return server_exists ? STATUS_PIPE_NOT_AVAILABLE : STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }

            const auto handle = c.proc.devices.store(std::move(container));
            out_handle.write(handle);

            return STATUS_SUCCESS;
        }

        // A host reparse point that is there but cannot be followed: an app execution alias, whose tag no file system
        // filter handles (std::filesystem::exists fails on it). Junctions and symbolic links are followed by the host, or
        // dangle, which is a missing file.
        static bool is_unfollowable_host_reparse_point(const syscall_context& c, const std::u16string& name,
                                                       const std::filesystem::path& host_path)
        {
            std::error_code ec{};
            if (!std::filesystem::exists(std::filesystem::symlink_status(host_path, ec)))
            {
                return false;
            }

            const auto tag = reparse_tag_at(c, name);
            return tag != 0 && tag != io_reparse_tag_mount_point && tag != io_reparse_tag_symlink;
        }

        // Windows opens such a reparse point only as itself (FILE_OPEN_REPARSE_POINT); following it fails with
        // STATUS_IO_REPARSE_TAG_NOT_HANDLED (ERROR_CANT_ACCESS_FILE), which CPython's stat retries without following.
        static NTSTATUS open_host_reparse_point(const syscall_context& c, const emulator_object<handle> file_handle, file f,
                                                const std::filesystem::path& host_path, const ULONG create_disposition,
                                                const ULONG create_options)
        {
            constexpr auto status_io_reparse_tag_not_handled = static_cast<NTSTATUS>(0xC0000279);
            if (!(create_options & file_open_reparse_point))
            {
                return status_io_reparse_tag_not_handled;
            }

            if (create_options & FILE_DIRECTORY_FILE)
            {
                return STATUS_NOT_A_DIRECTORY;
            }

            if (create_disposition == FILE_CREATE)
            {
                return STATUS_OBJECT_NAME_COLLISION;
            }

            if (create_disposition != FILE_OPEN && create_disposition != FILE_OPEN_IF)
            {
                return STATUS_ACCESS_DENIED;
            }

            if (const auto status = check_share_access(c.proc, host_path, f.access_mask, f.share_access); status != STATUS_SUCCESS)
            {
                return status;
            }

            c.win_emu.callbacks.on_generic_access("Opening file", f.name);

            auto mode = map_mode(f.access_mask, create_disposition);
            if (mode.empty())
            {
                mode = u"rb";
            }

            const windows_path path{f.name};
            const auto writable = is_write_open_mode(mode);
            if (writable && !c.win_emu.file_sys.is_writable(path))
            {
                return STATUS_ACCESS_DENIED;
            }

            auto* native_file = compat_open_reparse_point(host_path, writable);
            if (!native_file)
            {
                return STATUS_ACCESS_DENIED;
            }

            f.handle = guest_file{c.win_emu.file_sys, path, std::move(mode), std::make_unique<host_file>(native_file), true};
            f.host_path = host_path;

            file_handle.write(c.proc.files.store(std::move(f)));
            return STATUS_SUCCESS;
        }

        static NTSTATUS create_file(const syscall_context& c, const emulator_object<handle> file_handle, ACCESS_MASK desired_access,
                                    const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                    const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, ULONG share_access,
                                    ULONG create_disposition, ULONG create_options, uint64_t ea_buffer, ULONG ea_length)
        {
            constexpr ULONG file_opened = 1;

            if (create_options & FILE_DELETE_ON_CLOSE && !(desired_access & DELETE))
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto attributes = object_attributes.read();
            auto filename = read_unicode_string(c.emu, attributes.ObjectName);

            // \DosDevices\ is another name of \??\ (WaitNamedPipe opens \DosDevices\pipe\).
            if (constexpr std::u16string_view dos_devices = u"\\DosDevices\\";
                utils::string::starts_with_ignore_case(std::u16string_view{filename}, dos_devices))
            {
                filename = u"\\??\\" + filename.substr(dos_devices.size());
            }

            // Check for console device paths
            // Convert to uppercase for case-insensitive comparison
            std::u16string filename_upper = filename;
            std::ranges::transform(filename_upper, filename_upper.begin(), ::towupper);

            filename = resolve_volume_device_path(resolve_system_root_path(c, std::move(filename)));

            if (attributes.RootDirectory && filename.empty())
            {
                handle root_handle{};
                root_handle.bits = attributes.RootDirectory;
                const auto* root_container = c.proc.devices.get(root_handle);
                auto* root_pipe = root_container ? root_container->get_internal_device<named_pipe>() : nullptr;
                if (root_pipe)
                {
                    c.win_emu.callbacks.on_generic_access("Opening anonymous pipe", root_pipe->name);

                    io_device_creation_data data{};
                    io_device_container container{u"NamedPipe", c.win_emu, data};
                    auto* pipe_device = container.get_internal_device<named_pipe>();
                    if (!root_pipe->unopened_peer)
                    {
                        return STATUS_PIPE_NOT_AVAILABLE;
                    }
                    pipe_device->copy_configuration(*root_pipe);
                    container.granted_access = desired_access;
                    pipe_device->create_options = create_options;
                    container.inherit = (attributes.Attributes & OBJ_INHERIT) != 0;
                    pipe_device->endpoint = std::move(root_pipe->unopened_peer);

                    file_handle.write(c.proc.devices.store(std::move(container)));

                    IO_STATUS_BLOCK<EmulatorTraits<Emu64>> iosb{};
                    iosb.Status = STATUS_SUCCESS;
                    iosb.Information = file_opened;
                    io_status_block.write(iosb);
                    return STATUS_SUCCESS;
                }
            }

            // Handle console output device
            if (filename_upper == u"\\??\\CONOUT$" || filename_upper == u"\\DEVICE\\CONOUT$" || filename_upper == u"CONOUT$" ||
                filename_upper == u"\\??\\CON" || filename_upper == u"\\DEVICE\\CONSOLE" || filename_upper == u"CON")
            {
                c.win_emu.callbacks.on_generic_access("Opening console output", filename);
                file_handle.write(console_handle_for(STDOUT_HANDLE, c.proc.is_wow64_process));
                return STATUS_SUCCESS;
            }

            // Handle console input device
            if (filename_upper == u"\\??\\CONIN$" || filename_upper == u"\\DEVICE\\CONIN$" || filename_upper == u"CONIN$")
            {
                c.win_emu.callbacks.on_generic_access("Opening console input", filename);
                file_handle.write(console_handle_for(STDIN_HANDLE, c.proc.is_wow64_process));
                return STATUS_SUCCESS;
            }

            // Handle NUL device
            if (filename_upper == u"\\??\\NUL" || filename_upper == u"NUL")
            {
                c.win_emu.callbacks.on_generic_access("Opening NUL", filename);
                file_handle.write(NUL_HANDLE);
                return STATUS_SUCCESS;
            }

            if (is_named_pipe_path(filename))
            {
                return handle_named_pipe_create(c, file_handle, filename, attributes, desired_access, create_options);
            }

            auto printer = utils::finally([&] {
                c.win_emu.callbacks.on_generic_access("Opening file", filename); //
            });

            const auto io_device_name = get_io_device_name(filename);
            if (io_device_name.has_value())
            {
                if (!is_device_supported(*io_device_name))
                {
                    printer.cancel();
                    c.win_emu.callbacks.on_generic_access("Opening unsupported device", filename);
                    return STATUS_NO_SUCH_DEVICE;
                }

                const io_device_creation_data data{
                    .buffer = ea_buffer,
                    .length = ea_length,
                };

                // A device that cannot serve the request (a socket of an address family the host lacks, such as
                // Bluetooth) fails the open, as on Windows, instead of the emulation.
                std::optional<io_device_container> container{};
                try
                {
                    container.emplace(std::u16string(*io_device_name), c.win_emu, data);
                }
                catch (const std::exception& e)
                {
                    c.win_emu.log.warn("Opening device %s failed: %s\n", u16_to_u8(*io_device_name).c_str(), e.what());
                    return STATUS_NOT_SUPPORTED;
                }

                const auto handle = c.proc.devices.store(std::move(*container));
                file_handle.write(handle);

                return STATUS_SUCCESS;
            }

            handle root_handle{};
            root_handle.bits = attributes.RootDirectory;
            // Opens below the console connection: a pseudo handle, or its WOW64 alias, which the opener gets back.
            if ((root_handle.value.is_pseudo || canonical_console_handle(root_handle) == CONSOLE_HANDLE) &&
                (filename == u"\\Reference" || filename == u"\\Connect"))
            {
                file_handle.write(root_handle);
                return STATUS_SUCCESS;
            }

            if (filename == u"\\??\\CONOUT$")
            {
                file_handle.write(console_handle_for(STDOUT_HANDLE, c.proc.is_wow64_process));
                return STATUS_SUCCESS;
            }

            file f{};
            f.access_mask = desired_access;
            f.share_access = share_access;
            f.inherit = (attributes.Attributes & OBJ_INHERIT) != 0;
            f.file_mode = create_options & FILE_MODE_MASK;
            f.name = std::move(filename);

            if (attributes.RootDirectory)
            {
                const auto* root = c.proc.files.get(attributes.RootDirectory);
                if (!root)
                {
                    return STATUS_INVALID_HANDLE;
                }

                const auto has_separator = root->name.ends_with(u"\\") || root->name.ends_with(u"/");
                f.name = root->name + (has_separator ? u"" : u"\\") + f.name;
            }

            printer.cancel();

            // Junctions and symbolic links on the way lead elsewhere; the last component itself is opened, not followed,
            // with FILE_OPEN_REPARSE_POINT. The handle names where it led (GetFinalPathNameByHandle).
            if (auto resolved = resolve_reparse_points(c.proc, f.name, !(create_options & file_open_reparse_point)))
            {
                f.name = std::move(*resolved);
            }
            else
            {
                return status_reparse_point_not_resolved;
            }

            const windows_path path = f.name;

            if (!path.is_absolute())
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            f.drive_number = path.get_drive().value() - 'a' + 1;

            auto& file_sys = c.win_emu.file_sys;

            if ((create_options & FILE_DELETE_ON_CLOSE) && !file_sys.is_writable(path))
            {
                return STATUS_ACCESS_DENIED;
            }

            f.host_path = file_sys.translate(path);
            const auto existing_stat = file_sys.stat(path);
            const bool file_exists = existing_stat.has_value();

            // The host does not follow such a reparse point (an app execution alias), though stat may describe it.
            std::error_code ec{};
            if (!std::filesystem::exists(f.host_path, ec) && is_unfollowable_host_reparse_point(c, f.name, f.host_path))
            {
                auto host_path = f.host_path;
                return open_host_reparse_point(c, file_handle, std::move(f), host_path, create_disposition, create_options);
            }

            // Opening an existing file or directory must agree with the share modes of its other opens (deleting a
            // file another handle holds without FILE_SHARE_DELETE fails, as it does on Windows).
            if (file_exists && create_disposition != FILE_CREATE)
            {
                if (const auto status = check_share_access(c.proc, f.host_path, desired_access, share_access); status != STATUS_SUCCESS)
                {
                    return status;
                }
            }

            // A missing parent, or one that is a file, is a path that does not exist.
            const auto parent_is_directory = [&] {
                const auto parent_stat = file_sys.stat(path.parent());
                return parent_stat && (parent_stat->st_mode & S_IFMT) == S_IFDIR;
            };

            if (file_exists && (existing_stat->st_mode & S_IFMT) == S_IFDIR)
            {
                if (create_options & FILE_NON_DIRECTORY_FILE)
                {
                    return STATUS_FILE_IS_A_DIRECTORY;
                }

                if (create_disposition == FILE_CREATE)
                {
                    return STATUS_OBJECT_NAME_COLLISION;
                }

                if (create_disposition != FILE_OPEN && create_disposition != FILE_OPEN_IF)
                {
                    return STATUS_ACCESS_DENIED;
                }

                c.win_emu.callbacks.on_generic_access("Opening folder", f.name);

                f.handle = guest_file{file_sys, path};

                const auto handle = c.proc.files.store(std::move(f));
                file_handle.write(handle);

                return STATUS_SUCCESS;
            }

            if (create_options & FILE_DIRECTORY_FILE)
            {
                c.win_emu.callbacks.on_generic_access("Opening folder", f.name);

                if (file_exists)
                {
                    return create_disposition == FILE_CREATE ? STATUS_OBJECT_NAME_COLLISION : STATUS_NOT_A_DIRECTORY;
                }

                if (create_disposition != FILE_CREATE && create_disposition != FILE_OPEN_IF)
                {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }

                if (!parent_is_directory())
                {
                    return STATUS_OBJECT_PATH_NOT_FOUND;
                }

                const auto status = file_sys.create_directory(path, f.name);
                if (status != STATUS_SUCCESS)
                {
                    return status;
                }

                f.host_path = file_sys.translate_for_creation(path, f.name);
                f.handle = guest_file{file_sys, path};

                const auto handle = c.proc.files.store(std::move(f));
                file_handle.write(handle);

                return STATUS_SUCCESS;
            }

            c.win_emu.callbacks.on_generic_access("Opening file", f.name);

            if (create_disposition == FILE_CREATE && file_exists)
            {
                return STATUS_OBJECT_NAME_COLLISION;
            }

            if ((create_disposition == FILE_OVERWRITE || create_disposition == FILE_OPEN) && !file_exists)
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            // A new file is created here, under the name the guest spelled; opening it below then finds it whatever the
            // mode.
            const auto creates = create_disposition == FILE_CREATE || create_disposition == FILE_OPEN_IF ||
                                 create_disposition == FILE_SUPERSEDE || create_disposition == FILE_OVERWRITE_IF;
            if (creates && !file_exists)
            {
                if (!parent_is_directory())
                {
                    return STATUS_OBJECT_PATH_NOT_FOUND;
                }

                if (const auto created = file_sys.open(path, u"ab", f.name); !created.file)
                {
                    return created.status;
                }

                f.host_path = file_sys.translate_for_creation(path, f.name);
            }

            std::u16string mode = map_mode(desired_access, create_disposition);

            if (mode.empty() && create_disposition == FILE_CREATE)
            {
                mode = u"rb";
            }

            if (mode.empty() && (desired_access & DELETE))
            {
                mode = u"rb";
            }

            if (mode.empty())
            {
                return STATUS_NOT_SUPPORTED;
            }

            auto [io, status] = file_sys.open(path, mode, f.name);
            if (status != STATUS_SUCCESS)
            {
                return status;
            }

            f.handle = guest_file{file_sys, path, std::move(mode), std::move(io)};
            f.handle.set_delete_on_close((create_options & FILE_DELETE_ON_CLOSE) != 0);

            const auto handle = c.proc.files.store(std::move(f));
            file_handle.write(handle);

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCreateFile(const syscall_context& c, const emulator_object<handle> file_handle, ACCESS_MASK desired_access,
                                     const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                     const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                     const emulator_object<LARGE_INTEGER> /*allocation_size*/, ULONG /*file_attributes*/,
                                     ULONG share_access, ULONG create_disposition, ULONG create_options, uint64_t ea_buffer,
                                     ULONG ea_length)
        {
            return create_file(c, file_handle, desired_access, object_attributes, io_status_block, share_access, create_disposition,
                               create_options, ea_buffer, ea_length);
        }

        NTSTATUS handle_NtQueryFullAttributesFile(const syscall_context& c,
                                                  const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                                  const emulator_object<FILE_NETWORK_OPEN_INFORMATION> file_information)
        {
            if (!object_attributes)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto attributes = object_attributes.read();
            if (!attributes.ObjectName)
            {
                return STATUS_INVALID_PARAMETER;
            }

            auto filename =
                read_unicode_string(c.emu, emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>>{c.emu, attributes.ObjectName});

            if (attributes.RootDirectory)
            {
                const auto* root = c.proc.files.get(attributes.RootDirectory);
                if (!root)
                {
                    return STATUS_INVALID_HANDLE;
                }

                const auto has_separator = root->name.ends_with(u"\\") || root->name.ends_with(u"/");
                filename = root->name + (has_separator ? u"" : u"\\") + filename;
            }

            filename = resolve_volume_device_path(resolve_system_root_path(c, std::move(filename)));

            c.win_emu.callbacks.on_generic_access("Querying file attributes", filename);

            // A link at the end of the name is described itself, not followed.
            if (auto resolved = resolve_reparse_points(c.proc, filename, false))
            {
                filename = std::move(*resolved);
            }
            else
            {
                return status_reparse_point_not_resolved;
            }

            const windows_path filepath(filename);
            if (!has_valid_filename_characters(filepath.u16string()))
            {
                return STATUS_OBJECT_NAME_INVALID;
            }

            if (filepath.is_relative())
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            const auto file_stat_result = c.win_emu.file_sys.stat(filepath);
            if (!file_stat_result)
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            const auto& file_stat = *file_stat_result;

            file_information.access([&](FILE_NETWORK_OPEN_INFORMATION& info) {
                info.CreationTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_ctimespec);
                info.LastAccessTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_atimespec);
                info.LastWriteTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_mtimespec);
                info.AllocationSize.QuadPart = static_cast<LONGLONG>(file_stat.st_size);
                info.EndOfFile.QuadPart = static_cast<LONGLONG>(file_stat.st_size);
                info.ChangeTime = info.LastWriteTime;
                info.FileAttributes = with_reparse_attribute(host_file_attributes(file_stat), reparse_tag_at(c, filename));
            });

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtQueryAttributesFile(const syscall_context& c,
                                              const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                              const emulator_object<FILE_BASIC_INFORMATION> file_information)
        {
            if (!object_attributes)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto attributes = object_attributes.read();
            if (!attributes.ObjectName)
            {
                return STATUS_INVALID_PARAMETER;
            }

            auto filename =
                read_unicode_string(c.emu, emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>>{c.emu, attributes.ObjectName});

            if (attributes.RootDirectory)
            {
                const auto* root = c.proc.files.get(attributes.RootDirectory);
                if (!root)
                {
                    return STATUS_INVALID_HANDLE;
                }

                const auto has_separator = root->name.ends_with(u"\\") || root->name.ends_with(u"/");
                filename = root->name + (has_separator ? u"" : u"\\") + filename;
            }

            filename = resolve_volume_device_path(resolve_system_root_path(c, std::move(filename)));

            c.win_emu.callbacks.on_generic_access("Querying file attributes", filename);

            // A link at the end of the name is described itself, not followed.
            if (auto resolved = resolve_reparse_points(c.proc, filename, false))
            {
                filename = std::move(*resolved);
            }
            else
            {
                return status_reparse_point_not_resolved;
            }

            const windows_path filepath(filename);
            if (!has_valid_filename_characters(filepath.u16string()))
            {
                return STATUS_OBJECT_NAME_INVALID;
            }

            if (filepath.is_relative())
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            const auto file_stat_result = c.win_emu.file_sys.stat(filepath);
            if (!file_stat_result)
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            const auto& file_stat = *file_stat_result;

            file_information.access([&](FILE_BASIC_INFORMATION& info) {
                info.CreationTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_ctimespec);
                info.LastAccessTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_atimespec);
                info.LastWriteTime = get_file_time(c.win_emu.uses_relative_time(), file_stat.st_mtimespec);
                info.ChangeTime = info.LastWriteTime;
                info.FileAttributes = with_reparse_attribute(host_file_attributes(file_stat), reparse_tag_at(c, filename));
            });

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtOpenFile(const syscall_context& c, const emulator_object<handle> file_handle, const ACCESS_MASK desired_access,
                                   const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                   const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, const ULONG share_access,
                                   const ULONG open_options)
        {
            return handle_NtCreateFile(c, file_handle, desired_access, object_attributes, io_status_block, {c.emu.memory()}, 0,
                                       share_access, FILE_OPEN, open_options, 0, 0);
        }

        NTSTATUS handle_NtOpenDirectoryObject(const syscall_context& c, const emulator_object<handle> directory_handle,
                                              const ACCESS_MASK /*desired_access*/,
                                              const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes)
        {
            const auto attributes = object_attributes.read();
            const auto object_name = read_unicode_string(c.emu, attributes.ObjectName);

            if (object_name == u"\\KnownDlls")
            {
                directory_handle.write(KNOWN_DLLS_DIRECTORY);
                return STATUS_SUCCESS;
            }

            if (object_name == u"\\KnownDlls32")
            {
                directory_handle.write(KNOWN_DLLS32_DIRECTORY);
                return STATUS_SUCCESS;
            }

            if (object_name == u"\\Sessions\\1\\BaseNamedObjects")
            {
                directory_handle.write(BASE_NAMED_OBJECTS_DIRECTORY);
                return STATUS_SUCCESS;
            }

            if (object_name == u"\\RPC Control")
            {
                directory_handle.write(RPC_CONTROL_DIRECTORY);
                return STATUS_SUCCESS;
            }

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtCreateDirectoryObject(const syscall_context& /*c*/, const emulator_object<handle> /*directory_handle*/,
                                                const ACCESS_MASK /*desired_access*/,
                                                const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes)
        {
            const auto attributes = object_attributes.read();

            if (attributes.ObjectName == 0)
            {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtOpenSymbolicLinkObject(const syscall_context& c, const emulator_object<handle> link_handle,
                                                 ACCESS_MASK /*desired_access*/,
                                                 const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes)
        {
            const auto attributes = object_attributes.read();
            const auto object_name = read_unicode_string(c.emu, attributes.ObjectName);

            if (object_name == u"KnownDllPath")
            {
                link_handle.write(KNOWN_DLLS_SYMLINK);
                return STATUS_SUCCESS;
            }

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtQuerySymbolicLinkObject(const syscall_context& c, const handle link_handle,
                                                  const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> link_target,
                                                  const emulator_object<ULONG> returned_length)
        {
            auto write_target = [&](const std::u16string& target) -> NTSTATUS {
                const auto str_length = static_cast<uint16_t>(target.size() * sizeof(char16_t));
                const auto max_length = static_cast<ULONG>(str_length + sizeof(char16_t));

                returned_length.write(max_length);

                bool too_small = false;
                link_target.access([&](UNICODE_STRING<EmulatorTraits<Emu64>>& str) {
                    if (str.MaximumLength < max_length)
                    {
                        too_small = true;
                        return;
                    }

                    str.Length = str_length;
                    c.emu.write_memory(str.Buffer, target.data(), max_length);
                });

                return too_small ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
            };

            const auto& system_root = c.win_emu.version.get_system_root();

            if (link_handle == KNOWN_DLLS_SYMLINK)
            {
                return write_target((system_root / "System32").u16string());
            }

            if (link_handle == KNOWN_DLLS32_SYMLINK)
            {
                return write_target((system_root / "SysWOW64").u16string());
            }

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtCreateNamedPipeFile(const syscall_context& c, emulator_object<handle> file_handle, ULONG desired_access,
                                              emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                              emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block, ULONG share_access,
                                              ULONG create_disposition, ULONG create_options, ULONG named_pipe_type, ULONG read_mode,
                                              ULONG completion_mode, ULONG maximum_instances, ULONG inbound_quota, ULONG outbound_quota,
                                              emulator_object<LARGE_INTEGER> default_timeout)
        {
            constexpr ULONG file_created = 2;

            (void)share_access;
            (void)create_disposition;

            const auto attributes = object_attributes.read();
            const auto filename = read_unicode_string(c.emu, attributes.ObjectName);
            handle root_handle{};
            root_handle.bits = attributes.RootDirectory;
            const auto* root_container = attributes.RootDirectory ? c.proc.devices.get(root_handle) : nullptr;
            const auto* root_pipe = root_container ? root_container->get_internal_device<named_pipe>() : nullptr;
            const bool anonymous_pipe = filename.empty() && root_pipe;

            if (!is_named_pipe_path(filename) && !anonymous_pipe)
            {
                return STATUS_NOT_SUPPORTED;
            }

            const auto& pipe_name = anonymous_pipe ? root_pipe->name : filename;
            c.win_emu.callbacks.on_generic_access("Creating named pipe", pipe_name);

            // The first instance of a name sets how many it may have (unlimited: -1); one more fails (ERROR_PIPE_BUSY).
            if (!anonymous_pipe)
            {
                const windows_path wanted = normalize_named_pipe_path(pipe_name);
                ULONG instances = 0;
                std::optional<ULONG> limit{};
                for (const auto& entry : c.proc.devices | std::views::values)
                {
                    const auto* server = entry.get_internal_device<named_pipe>();
                    if (server && server->server && !server->anonymous && windows_path(server->name) == wanted)
                    {
                        ++instances;
                        limit = limit.value_or(server->max_instances);
                    }
                }

                constexpr auto status_instance_not_available = static_cast<NTSTATUS>(0xC00000AB);
                if (limit && *limit != std::numeric_limits<ULONG>::max() && instances >= *limit)
                {
                    return status_instance_not_available;
                }
            }

            io_device_creation_data data{};
            io_device_container container{u"NamedPipe", c.win_emu, data};

            if (auto* pipe_device = container.get_internal_device<named_pipe>())
            {
                pipe_device->name = normalize_named_pipe_path(pipe_name);
                pipe_device->server = true;
                pipe_device->anonymous = anonymous_pipe;
                container.granted_access = desired_access;
                pipe_device->pipe_type = named_pipe_type;
                pipe_device->read_mode = read_mode;
                pipe_device->completion_mode = completion_mode;
                pipe_device->max_instances = maximum_instances;
                pipe_device->inbound_quota = inbound_quota;
                pipe_device->outbound_quota = outbound_quota;
                pipe_device->create_options = create_options;
                container.inherit = (attributes.Attributes & OBJ_INHERIT) != 0;
                pipe_device->default_timeout = default_timeout.read();
                auto endpoints =
                    utils::host_pipe::create_pair(named_pipe_type != 0, std::max<ULONG>({inbound_quota, outbound_quota, 4096}));
                pipe_device->endpoint = std::move(endpoints.first);
                pipe_device->unopened_peer = std::move(endpoints.second);
            }
            else
            {
                return STATUS_NOT_SUPPORTED;
            }

            handle pipe_handle = c.proc.devices.store(std::move(container));
            file_handle.write(pipe_handle);

            IO_STATUS_BLOCK<EmulatorTraits<Emu64>> iosb{};
            iosb.Status = STATUS_SUCCESS;
            iosb.Information = file_created;
            io_status_block.write(iosb);

            return STATUS_SUCCESS;
        }

        // FSCTL_SET/GET/DELETE_REPARSE_POINT on a file or directory handle (opened with FILE_OPEN_REPARSE_POINT for a link
        // itself); nothing for other controls.
        static std::optional<NTSTATUS> reparse_point_control(const syscall_context& c, const file& f,
                                                             const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                                             const ULONG fs_control_code, const emulator_pointer input_buffer,
                                                             const ULONG input_buffer_length, const emulator_pointer output_buffer,
                                                             const ULONG output_buffer_length)
        {
            constexpr ULONG fsctl_set_reparse_point = 0x900A4;
            constexpr ULONG fsctl_get_reparse_point = 0x900A8;
            constexpr ULONG fsctl_delete_reparse_point = 0x900AC;
            constexpr auto status_io_reparse_data_invalid = static_cast<NTSTATUS>(0xC0000278);
            constexpr auto status_directory_not_empty = static_cast<NTSTATUS>(0xC0000101);
            constexpr auto status_not_a_directory = static_cast<NTSTATUS>(0xC0000103);
            // Tag, data length, reserved.
            constexpr ULONG header_size = 8;

            const auto complete = [&](const NTSTATUS status, const uint64_t information) {
                if (io_status_block)
                {
                    io_status_block.write({.Status = status, .Information = information});
                }
                return status;
            };

            const auto key = reparse_key(f.name);
            switch (fs_control_code)
            {
            case fsctl_set_reparse_point: {
                if (input_buffer_length < header_size)
                {
                    return complete(status_io_reparse_data_invalid, 0);
                }

                std::vector<uint8_t> data(input_buffer_length);
                c.emu.read_memory(input_buffer, data.data(), data.size());
                uint16_t data_length{};
                memcpy(&data_length, data.data() + 4, sizeof(data_length));
                if (header_size + data_length > data.size())
                {
                    return complete(status_io_reparse_data_invalid, 0);
                }
                data.resize(header_size + data_length);

                // A junction replaces an empty directory.
                if (reparse_tag(data) == io_reparse_tag_mount_point && !c.proc.reparse_points.contains(key))
                {
                    if (!f.is_directory())
                    {
                        return complete(status_not_a_directory, 0);
                    }

                    std::error_code ec{};
                    if (!std::filesystem::is_empty(f.host_path, ec))
                    {
                        return complete(status_directory_not_empty, 0);
                    }
                }

                c.proc.reparse_points[key] = std::move(data);
                return complete(STATUS_SUCCESS, 0);
            }
            case fsctl_get_reparse_point: {
                const auto found = reparse_data_at(c, f.name);
                if (!found)
                {
                    return complete(STATUS_NOT_A_REPARSE_POINT, 0);
                }

                const auto& data = *found;
                if (output_buffer_length < header_size)
                {
                    return complete(STATUS_BUFFER_TOO_SMALL, 0);
                }

                const auto size = std::min<size_t>(data.size(), output_buffer_length);
                c.emu.write_memory(output_buffer, data.data(), size);
                return complete(size < data.size() ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS, size);
            }
            case fsctl_delete_reparse_point:
                return complete(c.proc.reparse_points.erase(key) ? STATUS_SUCCESS : STATUS_NOT_A_REPARSE_POINT, 0);
            default:
                return std::nullopt;
            }
        }

        NTSTATUS handle_NtFsControlFile(const syscall_context& c, const handle file_handle, const handle event,
                                        const emulator_pointer apc_routine, const emulator_pointer apc_context,
                                        const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                        const ULONG fs_control_code, const emulator_pointer input_buffer, const ULONG input_buffer_length,
                                        const emulator_pointer output_buffer, const ULONG output_buffer_length)
        {
            auto* device = c.proc.devices.get(file_handle);
            if (!device)
            {
                if (const auto* f = c.proc.files.get(file_handle))
                {
                    if (const auto status = reparse_point_control(c, *f, io_status_block, fs_control_code, input_buffer,
                                                                  input_buffer_length, output_buffer, output_buffer_length))
                    {
                        if (auto* e = c.proc.events.get(event); e && NT_SUCCESS(*status))
                        {
                            e->signaled = true;
                        }
                        return *status;
                    }
                }

                c.win_emu.log.warn("NtFsControlFile on non-device handle (control code 0x%X)\n", static_cast<uint32_t>(fs_control_code));
                return STATUS_INVALID_HANDLE;
            }

            if (auto* e = c.proc.events.get(event))
            {
                e->signaled = false;
            }

            io_device_context context{c.emu};
            context.event = event;
            context.apc_routine = apc_routine;
            context.apc_context = apc_context;
            context.io_status_block = io_status_block;
            context.io_control_code = fs_control_code;
            context.input_buffer = input_buffer;
            context.input_buffer_length = input_buffer_length;
            context.output_buffer = output_buffer;
            context.output_buffer_length = output_buffer_length;
            context.vcpu = &c.vcpu;

            return device->execute_ioctl(c.win_emu, context);
        }

        NTSTATUS handle_NtFlushBuffersFile(const syscall_context& c, const handle file_handle,
                                           const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> /*io_status_block*/)
        {
            if (file_handle == STDOUT_HANDLE)
            {
                return STATUS_SUCCESS;
            }

            const auto* f = c.proc.files.get(file_handle);
            if (!f)
            {
                return STATUS_INVALID_HANDLE;
            }

            (void)f->handle.flush();
            return STATUS_SUCCESS;
        }
    }

} // namespace sogen
