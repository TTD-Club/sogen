#pragma once

#include <ranges>
#include <fstream>
#include <algorithm>
#include <map>
#include <span>

#include <utils/container.hpp>
#include <platform/unicode.hpp>

namespace sogen
{

    // The bytes of a hive: its file, the parts of a file that an earlier run read (recorded_hive), or those with the
    // file for the rest. Keeps every range read, so a run can hand on the parts of its hives it depended on
    // (known_ranges), and a later run that reads only those needs no hive file.
    class hive_file
    {
      public:
        // Starting offset -> bytes; ranges neither overlap nor touch.
        using ranges = std::map<uint64_t, std::vector<std::byte>>;

        explicit hive_file(const std::filesystem::path& path);
        // Known parts of a file of `size` bytes; reads beyond them come from `path` if not empty (the same file).
        hive_file(uint64_t size, ranges contents, const std::filesystem::path& path = {});

        // Reads [offset, offset + size) into `buffer`, with zeros past the end of the file; false if the file cannot be
        // read. Throws if neither the known parts nor a file hold part of the range.
        bool read(uint64_t offset, void* buffer, size_t size);

        uint64_t size() const
        {
            return this->size_;
        }

        // The parts known: those given at construction and every range read since (clipped to the file), with their
        // bytes.
        ranges known_ranges();

      private:
        std::ifstream file_{};
        uint64_t size_{};
        // Constructed from known parts: without a file, reading beyond them throws.
        bool recorded_{};
        ranges contents_{};
        // Start -> end of the ranges read, merged.
        std::map<uint64_t, uint64_t> read_{};

        bool read_from_file(uint64_t offset, std::span<std::byte> buffer);
    };

    struct hive_value
    {
        uint32_t type{};
        std::string name{};
        std::vector<std::byte> data{};
    };

    class hive_key
    {
      public:
        hive_key(const int subkey_block_offset, const int value_count, const int value_offsets)
            : subkey_block_offset_(subkey_block_offset),
              value_count_(value_count),
              value_offsets_(value_offsets)
        {
        }

        utils::unordered_insensitive_string_map<hive_key>& get_sub_keys(hive_file& file)
        {
            this->parse(file);
            return this->sub_keys_;
        }

        const std::string_view* get_sub_key_name(hive_file& file, size_t index)
        {
            this->parse(file);

            if (index >= sub_keys_by_index_.size())
            {
                return nullptr;
            }

            return &sub_keys_by_index_.at(index);
        }

        hive_key* get_sub_key(hive_file& file, const std::string_view name)
        {
            auto& sub_keys = this->get_sub_keys(file);
            const auto entry = sub_keys.find(name);

            if (entry == sub_keys.end())
            {
                return nullptr;
            }

            return &entry->second;
        }

        hive_key* get_sub_key(hive_file& file, size_t index)
        {
            return get_sub_key(file, *this->get_sub_key_name(file, index));
        }

        const hive_value* get_value(hive_file& file, std::string_view name);
        const hive_value* get_value(hive_file& file, size_t index);

        size_t get_sub_key_count(hive_file& file)
        {
            this->parse(file);
            return this->sub_keys_.size();
        }

        size_t get_value_count(hive_file& file)
        {
            this->parse(file);
            return this->values_.size();
        }

      private:
        struct raw_hive_value : hive_value
        {
            bool parsed{false};
            int data_offset{};
            size_t data_length{};
        };

        bool parsed_{false};
        utils::unordered_insensitive_string_map<hive_key> sub_keys_{};
        std::vector<std::string_view> sub_keys_by_index_{};
        utils::unordered_insensitive_string_map<raw_hive_value> values_{};
        std::vector<std::string_view> values_by_index_{};

        const int subkey_block_offset_{};
        const int value_count_{};
        const int value_offsets_{};

        void parse_subkey_list(hive_file& file, int32_t block_offset, bool allow_root_index);
        void parse(hive_file& file);
    };

    class hive_parser
    {
      public:
        explicit hive_parser(const std::filesystem::path& file_path);
        // A hive from the parts of it an earlier run read, and from `fallback` (the same file) beyond them if not empty.
        hive_parser(uint64_t size, hive_file::ranges contents, const std::filesystem::path& fallback);

        [[nodiscard]] hive_key* get_sub_key(const std::filesystem::path& key)
        {
            hive_key* current_key = &this->root_key_;

            for (const auto& key_part : key)
            {
                if (key_part.empty())
                {
                    continue;
                }

                if (!current_key)
                {
                    return nullptr;
                }

                current_key = current_key->get_sub_key(this->file_, u16_to_u8(key_part.u16string()));
            }

            return current_key;
        }

        [[nodiscard]] const std::string_view* get_sub_key_name(const std::filesystem::path& key, size_t index)
        {
            auto* target_key = this->get_sub_key(key);
            if (!target_key)
            {
                return nullptr;
            }

            return target_key->get_sub_key_name(this->file_, index);
        }

        [[nodiscard]] const hive_value* get_value(const std::filesystem::path& key, const std::string_view name)
        {
            auto* sub_key = this->get_sub_key(key);
            if (!sub_key)
            {
                return nullptr;
            }

            return sub_key->get_value(this->file_, name);
        }

        [[nodiscard]] const hive_value* get_value(const std::filesystem::path& key, size_t index)
        {
            auto* sub_key = this->get_sub_key(key);
            if (!sub_key)
            {
                return nullptr;
            }

            return sub_key->get_value(this->file_, index);
        }

        hive_file& get_file()
        {
            return this->file_;
        }

      private:
        hive_file file_;
        hive_key root_key_;
    };

} // namespace sogen
