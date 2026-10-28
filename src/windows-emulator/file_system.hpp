#pragma once
#include "std_include.hpp"
#include "windows_path.hpp"
#include "filesystem/filesystem_mode.hpp"
#include "filesystem/mount_provider.hpp"

namespace sogen
{

    struct file_system_test_access;

    class file_system
    {
      public:
        explicit file_system(const std::filesystem::path& root, filesystem_mode root_mode = default_root_mode);

        void mount(const windows_path& guest_path, std::unique_ptr<mount_provider> provider, filesystem_mode mode = default_mount_mode);
        void map(const windows_path& guest_path, std::filesystem::path host_path, filesystem_mode mode = default_mount_mode);

        std::set<char> list_drives() const;
        uint8_t drive_type(char drive) const;

        std::optional<struct compat_stat> stat(const windows_path& path) const;
        std::vector<directory_entry> list_directory(const windows_path& path) const;
        bool is_writable(const windows_path& path) const;

        // `spelled` is the guest's spelling of the path (or of its last component): a new entry keeps it.
        open_result open(const windows_path& path, const std::u16string& mode, std::u16string_view spelled = {});
        open_result open_read(const windows_path& path) const;
        NTSTATUS create_directory(const windows_path& path, std::u16string_view spelled = {});
        NTSTATUS rename(const windows_path& from, const windows_path& to, std::u16string_view spelled = {});
        NTSTATUS remove(const windows_path& path);

        bool read_file(const windows_path& path, std::vector<std::byte>* data) const;
        std::vector<std::byte> read_file(const windows_path& path) const;

        friend struct file_system_test_access;

        // Returns an empty path if no mount resolves the guest path.
        std::filesystem::path translate(const windows_path& path) const;

        // The host path at which to create `win_path`, a new entry the guest named `spelled` (see spell_created_leaf).
        std::filesystem::path translate_for_creation(const windows_path& win_path, std::u16string_view spelled, bool renamed = false) const;

        // The part of a guest path after its drive ("\Users\x"), its components in the case the file system keeps for
        // them, as Windows reports names (GetFinalPathNameByHandle): the host's case of each existing component (the
        // guest's spelling of components the host lacks or reaches through a link).
        std::u16string true_case(std::u16string_view spelled) const;

        // Host mode: guest paths are host paths (apart from mappings), with no emulation root.
        bool is_host_mode() const
        {
#ifdef OS_WINDOWS
            return this->host_passthrough_;
#else
            return false;
#endif
        }

      private:
        struct mount_entry
        {
            std::unique_ptr<mount_provider> provider{};
            filesystem_mode mode{};
        };

        struct resolved_path
        {
            mount_provider* provider{};
            filesystem_mode mode{};
            windows_path mount_point{};
            windows_path relative{};
        };

        std::optional<resolved_path> resolve(const windows_path& path) const;

        std::unordered_map<windows_path, mount_entry> mounts_{};
#ifdef OS_WINDOWS
        bool host_passthrough_{false};
#endif
    };

} // namespace sogen
