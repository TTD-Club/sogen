#pragma once

#include <platform/platform.hpp>

#include <filesystem>
#include <map>
#include <optional>

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

    // The 8.3 short names the host file system keeps for the entries of a directory that match `pattern` (a name, also
    // matching short names, or "*") and have one, by entry name (Windows hosts only; empty elsewhere).
    std::map<std::u16string, std::u16string> compat_short_names(const std::filesystem::path& directory, const std::u16string& pattern);

    LARGE_INTEGER convert_timespec_to_filetime(timespec timespec);
} // namespace sogen
