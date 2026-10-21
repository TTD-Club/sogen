#pragma once

#include "mount_provider.hpp"

namespace sogen
{

    class host_file final : public i_file
    {
      public:
        explicit host_file(FILE* file);
        ~host_file() override;

        host_file(const host_file&) = delete;
        host_file& operator=(const host_file&) = delete;
        host_file(host_file&&) = delete;
        host_file& operator=(host_file&&) = delete;

        size_t read(std::span<std::byte> buffer) override;
        size_t write(std::span<const std::byte> buffer) override;
        bool flush() override;

        bool seek(int64_t offset, int origin) override;
        int64_t tell() override;
        int64_t size() override;
        bool resize(uint64_t size) override;

        std::optional<struct compat_stat> stat() override;

      private:
        enum class io_direction : uint8_t
        {
            none,
            read,
            write,
        };

        FILE* file_{};
        io_direction last_io_{io_direction::none};

        void switch_direction(io_direction direction);
    };

    class host_directory_provider final : public mount_provider
    {
      public:
        explicit host_directory_provider(std::filesystem::path target);

        std::optional<struct compat_stat> stat(const windows_path& path) const override;
        std::vector<directory_entry> list(const windows_path& path) const override;
        open_result open(const windows_path& path, const std::u16string& mode, std::u16string_view spelled_leaf) override;
        NTSTATUS create_directory(const windows_path& path, std::u16string_view spelled_leaf) override;
        NTSTATUS rename(const windows_path& from, const windows_path& to, std::u16string_view spelled_leaf) override;
        NTSTATUS remove(const windows_path& path) override;
        std::optional<std::filesystem::path> get_host_path(const windows_path& path) const override;

      private:
        std::filesystem::path target_{};

        std::optional<std::filesystem::path> get_creation_path(const windows_path& path, std::u16string_view spelled_leaf,
                                                               bool renamed) const;
    };

    // `host_path`, the host path of the guest path `path`, with its last component spelled as the guest spelled it
    // (`spelled`, a name or a path ending in it). Windows keeps the case a name was created with, while windows_path
    // lowercases every component; later lookups still find the entry: Windows hosts ignore case, and elsewhere host
    // paths match components ignoring case. An existing entry keeps its name, unless it is being `renamed` (a rename
    // that changes only the case of a name).
    std::filesystem::path spell_created_leaf(std::filesystem::path host_path, const windows_path& path, std::u16string_view spelled,
                                             bool renamed);

} // namespace sogen
