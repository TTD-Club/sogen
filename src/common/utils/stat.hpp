#pragma once

#include <platform/platform.hpp>

#include <filesystem>
#include <map>
#include <optional>
#include <vector>

namespace sogen
{

    struct compat_stat
    {
        uint32_t st_dev;
        uint32_t st_mode;
        uint32_t st_nlink;
        uint32_t st_uid;
        uint32_t st_gid;
        uint32_t st_rdev;
        uint64_t st_ino;
        int64_t st_size;
        timespec st_atimespec;
        timespec st_mtimespec;
        timespec st_ctimespec;
    };

    bool compat_fstat(int fd, struct compat_stat* stat);
    bool compat_stat(const std::filesystem::path& file_name, struct compat_stat* stat);

    // Sets a file's or directory's last access and last write times (FILETIME values, 100 ns since 1601); a missing
    // one stays as it is.
    bool compat_set_file_times(const std::filesystem::path& file_name, std::optional<LARGE_INTEGER> access_time,
                               std::optional<LARGE_INTEGER> write_time);

    // What the host file system keeps for a directory entry beyond stat: its 8.3 short name and its reparse tag.
    struct compat_host_entry
    {
        std::u16string short_name;
        uint32_t reparse_tag{};
    };

    // The entries of a directory that match `pattern` (a name, also matching short names, or "*") and have a short name
    // or are reparse points, by entry name (Windows hosts only; empty elsewhere).
    std::map<std::u16string, compat_host_entry> compat_host_entries(const std::filesystem::path& directory, const std::u16string& pattern);

    // The REPARSE_DATA_BUFFER of a host reparse point (Windows hosts only), nothing for other entries.
    std::optional<std::vector<uint8_t>> compat_reparse_data(const std::filesystem::path& path);

    LARGE_INTEGER convert_timespec_to_filetime(timespec timespec);
} // namespace sogen
