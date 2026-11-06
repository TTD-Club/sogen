#pragma once

#include "../std_include.hpp"
#include "hive_parser.hpp"
#include "registry_notification.hpp"
#include "serialization_helper.hpp"
#include "../handles.hpp"

#ifndef OS_WINDOWS
#define REG_NONE (0ul) // No value type
#define REG_SZ   (1ul) // Unicode nul terminated string
#define REG_EXPAND_SZ \
    (2ul)                                    // Unicode nul terminated string
                                             // (with environment variable references)
#define REG_BINARY                     (3ul) // Free form binary
#define REG_DWORD                      (4ul) // 32-bit number
#define REG_DWORD_LITTLE_ENDIAN        (4ul) // 32-bit number (same as REG_DWORD)
#define REG_DWORD_BIG_ENDIAN           (5ul) // 32-bit number
#define REG_LINK                       (6ul) // Symbolic Link (unicode)
#define REG_MULTI_SZ                   (7ul) // Multiple Unicode strings
#define REG_RESOURCE_LIST              (8ul) // Resource list in the resource map
#define REG_FULL_RESOURCE_DESCRIPTOR   (9ul) // Resource list in the hardware description
#define REG_RESOURCE_REQUIREMENTS_LIST (10ul)
#define REG_QWORD                      (11ul) // 64-bit number
#define REG_QWORD_LITTLE_ENDIAN        (11ul) // 64-bit number (same as REG_QWORD)
#endif

namespace sogen
{

    struct registry_key : ref_counted_object
    {
        utils::path_key hive{};
        utils::path_key path{};
        uint64_t generation{};
        uint16_t tag{};
        std::optional<registry_notify_block> notify_block{};

        void serialize_object(utils::buffer_serializer& buffer) const override
        {
            buffer.write(this->hive);
            buffer.write(this->path);
            buffer.write(this->generation);
            buffer.write(this->tag);
            buffer.write_optional(this->notify_block);
        }

        void deserialize_object(utils::buffer_deserializer& buffer) override
        {
            buffer.read(this->hive);
            buffer.read(this->path);
            buffer.read(this->generation);
            buffer.read(this->tag);
            buffer.read_optional(this->notify_block);
        }

        std::u16string to_string() const
        {
            return this->hive.get().u16string() + u"\\" + this->path.get().u16string();
        }
    };

    struct registry_value
    {
        uint32_t type;
        std::string_view name;
        std::span<const std::byte> data;

        bool is_dword() const
        {
            return type == REG_DWORD;
        }

        bool is_string() const
        {
            return type == REG_SZ;
        }

        std::optional<DWORD> as_dword() const
        {
            DWORD value{};
            if (!is_dword() || data.size() < sizeof(value))
            {
                return std::nullopt;
            }

            memcpy(&value, data.data(), sizeof(value));
            return value;
        }

        std::optional<std::u16string> as_string() const
        {
            if (!is_string())
            {
                return std::nullopt;
            }

            const auto* data_ptr = reinterpret_cast<const char16_t*>(data.data());
            const auto char_count = data.size() / sizeof(char16_t);
            const auto count = char_count > 0 && data_ptr[char_count - 1] == u'\0' ? char_count - 1 : char_count;
            return std::u16string(data_ptr, count);
        }
    };

    struct exposed_hive_key
    {
        hive_key& key;
        hive_file& file;
    };

    // The parts of a hive file a run read: the file's size and the ranges, with their bytes.
    struct recorded_hive
    {
        uint64_t size{};
        hive_file::ranges contents{};
    };

    // Hive file name (SYSTEM, SECURITY, SAM, SOFTWARE, HARDWARE, NTUSER.DAT) -> what a run read of it.
    using recorded_hives = std::map<std::string, recorded_hive>;

    class registry_manager
    {
      public:
        using hive_ptr = std::unique_ptr<hive_parser>;
        using hive_map = std::unordered_map<utils::path_key, hive_ptr>;

        registry_manager();
        registry_manager(const std::filesystem::path& hive_path);
        ~registry_manager();

        registry_manager(registry_manager&&) noexcept;
        registry_manager& operator=(registry_manager&&) noexcept;

        registry_manager(const registry_manager&) = delete;
        registry_manager& operator=(const registry_manager&) = delete;

        // The directory the hive files are read from; empty for a manager without hive files.
        const std::filesystem::path& get_hive_path() const
        {
            return this->hive_path_;
        }

        // What this run depends on of each hive: everything it read since the hives were set up, and for recorded hives
        // also all they were given.
        recorded_hives read_hives();

        // Serves the hives from what an earlier run read (read_hives), keeping the changes made to the registry. Data
        // outside it comes from the hive files if `fall_back_to_files` (they must be the ones the earlier run read)
        // and is an error otherwise. `identity` names the contents (get_hive_identity).
        void use_recorded_hives(const recorded_hives& hives, std::string identity, bool fall_back_to_files = false);

        // The name use_recorded_hives gave the hive contents, so that a caller can tell them apart without reading them;
        // empty for hives from files.
        const std::string& get_hive_identity() const
        {
            return this->hive_identity_;
        }

        std::optional<registry_key> get_key(const utils::path_key& key);
        bool key_exists(const registry_key& key);
        static bool is_root_key(const registry_key& key);
        bool can_create_key(const std::filesystem::path& key) const;
        std::optional<registry_key> create_key(const std::filesystem::path& key);
        void delete_key(const registry_key& key);
        std::optional<registry_value> get_value(const registry_key& key, std::string_view name);
        std::optional<registry_value> get_value(const registry_key& key, size_t index);
        size_t get_value_count(const registry_key& key);
        void set_value(const registry_key& key, std::string name, uint32_t type, std::span<const std::byte> data);
        bool delete_value(const registry_key& key, std::string_view name);

        std::optional<std::string_view> get_sub_key_name(const registry_key& key, size_t index);
        size_t get_sub_key_count(const registry_key& key);

        std::optional<exposed_hive_key> get_hive_key(const registry_key& key);
        std::vector<std::byte> get_class_name(const registry_key& key);
        uint32_t get_max_sub_key_class_length(const registry_key& key);

        std::optional<std::u16string> read_u16string(const registry_key& key, size_t index);
        void serialize_runtime_state(utils::buffer_serializer& buffer) const;
        void deserialize_runtime_state(utils::buffer_deserializer& buffer);

      private:
        struct overlay_value
        {
            uint32_t type{};
            std::vector<std::byte> data{};
            bool deleted{};

            void serialize(utils::buffer_serializer& buffer) const
            {
                buffer.write(this->type);
                buffer.write_vector(this->data);
                buffer.write(this->deleted);
            }

            void deserialize(utils::buffer_deserializer& buffer)
            {
                buffer.read(this->type);
                buffer.read_vector(this->data);
                buffer.read(this->deleted);
            }
        };

        struct overlay_bucket
        {
            // A false entry hides a sub key that still exists in the read-only hive file.
            utils::insensitive_string_map<bool> sub_keys{};
            utils::insensitive_string_map<overlay_value> values{};

            void serialize(utils::buffer_serializer& buffer) const
            {
                buffer.write_map(this->sub_keys);
                buffer.write_map(this->values);
            }

            void deserialize(utils::buffer_deserializer& buffer)
            {
                buffer.read_map(this->sub_keys);
                buffer.read_map(this->values);
            }
        };

        std::filesystem::path hive_path_{};
        hive_map hives_{};
        // Hive file name -> its key in hives_.
        std::map<std::string, utils::path_key> hive_files_{};
        std::string hive_identity_{};
        std::map<utils::path_key, utils::path_key> path_mapping_{};
        std::map<utils::path_key, overlay_bucket> overlay_values_{};
        std::map<utils::path_key, uint64_t> key_generations_{};

        utils::path_key normalize_path(utils::path_key path) const;
        static utils::path_key get_full_key_path(const registry_key& key);
        uint64_t get_generation(const utils::path_key& full_path) const;
        bool is_deleted_hive_key(const utils::path_key& full_path) const;
        std::optional<exposed_hive_key> get_original_hive_key(const registry_key& key);
        void add_path_mapping(const utils::path_key& key, const utils::path_key& value);

        hive_map::iterator find_hive(const utils::path_key& key);
        hive_map::const_iterator find_hive(const utils::path_key& key) const;

        void setup(const recorded_hives* recorded);
    };

} // namespace sogen
