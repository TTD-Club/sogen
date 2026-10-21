#include "../std_include.hpp"
#include "hive_parser.hpp"
#include <utils/string.hpp>

// Based on this implementation: https://github.com/reahly/windows-hive-parser

namespace sogen
{

    namespace
    {
        constexpr uint64_t MAIN_ROOT_OFFSET = 0x1000;
        constexpr uint64_t MAIN_KEY_BLOCK_OFFSET = MAIN_ROOT_OFFSET + 0x20;

        // NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

        struct offset_entry_t
        {
            int32_t offset;
            int32_t hash;
        };

        struct offsets_t
        {
            int32_t block_size;
            char block_type[2];
            int16_t count;
            offset_entry_t entries[1];
        };

        struct key_block_t
        {
            int32_t block_size;
            char block_type[2];
            uint8_t dummya[18];
            int32_t subkey_count;
            uint8_t dummyb[4];
            int32_t subkeys;
            uint8_t dummyc[4];
            int32_t value_count;
            int32_t offsets;
            uint8_t dummyd[28];
            int16_t len;
            int16_t du;
            char name[255];
        };

        struct value_block_t
        {
            int32_t block_size;
            char block_type[2];
            int16_t name_len;
            int32_t size;
            int32_t offset;
            int32_t value_type;
            int16_t flags;
            int16_t dummy;
            char name[255];
        };

        // NOLINTEND(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

        void read_file_data(hive_file& file, const uint64_t offset, void* buffer, const size_t size)
        {
            if (!file.read(offset, buffer, size))
            {
                throw std::runtime_error("Failed to read file data");
            }
        }

        std::vector<std::byte> read_file_data(hive_file& file, const uint64_t offset, const size_t size)
        {
            std::vector<std::byte> result{};
            result.resize(size);

            read_file_data(file, offset, result.data(), size);
            return result;
        }

        std::string read_file_data_string(hive_file& file, const uint64_t offset, const size_t size)
        {
            std::string result{};
            result.resize(size);

            read_file_data(file, offset, result.data(), size);
            return result;
        }

        template <typename T>
            requires(std::is_trivially_copyable_v<T>)
        T read_file_object(hive_file& file, const uint64_t offset, const size_t array_index = 0)
        {
            T obj{};
            read_file_data(file, offset + (array_index * sizeof(T)), &obj, sizeof(T));
            return obj;
        }

        hive_key parse_root_block(hive_file& file, const std::filesystem::path& file_path)
        {
            try
            {
                if (read_file_data_string(file, 0, 4) != "regf")
                {
                    throw std::runtime_error("Invalid signature");
                }

                const auto key_block = read_file_object<key_block_t>(file, MAIN_KEY_BLOCK_OFFSET);

                return {key_block.subkeys, key_block.value_count, key_block.offsets};
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error("Bad hive file '" + file_path.string() + "': " + e.what());
            }
        }
    }

    namespace
    {
        // Adds [start, end) to a set of ranges (start -> end), merging it with those it overlaps or touches.
        void add_range(std::map<uint64_t, uint64_t>& ranges, uint64_t start, uint64_t end)
        {
            if (start == end)
            {
                return;
            }

            auto next = ranges.upper_bound(start);
            if (next != ranges.begin())
            {
                if (const auto previous = std::prev(next); previous->second >= start)
                {
                    if (previous->second >= end)
                    {
                        return;
                    }
                    start = previous->first;
                    next = previous;
                }
            }
            while (next != ranges.end() && next->first <= end)
            {
                end = std::max(end, next->second);
                next = ranges.erase(next);
            }
            ranges.emplace(start, end);
        }
    }

    hive_file::hive_file(const std::filesystem::path& path)
        : file_(path, std::ios::binary)
    {
        std::error_code error{};
        this->size_ = std::filesystem::file_size(path, error);
        if (error)
        {
            this->size_ = 0;
        }
    }

    hive_file::hive_file(const uint64_t size, ranges contents, const std::filesystem::path& path)
        : size_(size),
          recorded_(true),
          contents_(std::move(contents))
    {
        if (!path.empty())
        {
            this->file_.open(path, std::ios::binary);
        }
    }

    bool hive_file::read(const uint64_t offset, void* buffer, const size_t size)
    {
        // The parser maps fixed-size structs (key/value/subkey-list blocks) onto variable-size hive
        // cells, so a full-size read of a cell near the end of the hive legitimately runs past EOF --
        // uncompacted hives leave trailing slack that absorbs it, but a compacted hive (e.g. produced
        // by REG SAVE, which drops that slack) does not. Read whatever is available and zero-fill the
        // remainder; callers only consume the real cell fields, and an offset wholly past EOF yields a
        // zeroed block that parses as empty rather than crashing.
        std::memset(buffer, 0, size);

        if (!this->recorded_ && !this->file_.is_open())
        {
            return false;
        }

        if (offset >= this->size_)
        {
            return true; // wholly past EOF: leave the buffer zero-filled
        }

        const auto length = static_cast<size_t>(std::min<uint64_t>(size, this->size_ - offset));
        const std::span target(static_cast<std::byte*>(buffer), length);
        if (auto range = this->contents_.upper_bound(offset);
            range != this->contents_.begin() && (--range, range->first + range->second.size() >= offset + length))
        {
            std::memcpy(target.data(), range->second.data() + (offset - range->first), length);
        }
        else if (this->file_.is_open())
        {
            if (!this->read_from_file(offset, target))
            {
                return false;
            }
        }
        else
        {
            throw std::runtime_error("The recorded registry holds no data at hive offset " + std::to_string(offset) +
                                     ": this run reads registry data the recording never read, so it needs the hive files");
        }

        add_range(this->read_, offset, offset + length);
        return true;
    }

    bool hive_file::read_from_file(const uint64_t offset, const std::span<std::byte> buffer)
    {
        auto& file = this->file_;
        if (file.bad())
        {
            return false;
        }

        file.clear();
        file.seekg(static_cast<std::streamoff>(offset));
        if (!file.good())
        {
            return false;
        }

        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        return !file.bad();
    }

    hive_file::ranges hive_file::known_ranges()
    {
        std::map<uint64_t, uint64_t> known = this->read_;
        for (const auto& [start, bytes] : this->contents_)
        {
            add_range(known, start, start + bytes.size());
        }

        // Without a file, every range read lies in the contents given.
        ranges result{};
        for (const auto& [start, end] : known)
        {
            std::vector<std::byte> bytes(static_cast<size_t>(end - start));
            if (this->file_.is_open())
            {
                if (!this->read_from_file(start, bytes))
                {
                    throw std::runtime_error("Failed to read hive data");
                }
            }
            else
            {
                for (auto part = this->contents_.lower_bound(start); part != this->contents_.end() && part->first < end; ++part)
                {
                    std::ranges::copy(part->second, bytes.begin() + static_cast<ptrdiff_t>(part->first - start));
                }
            }
            result.emplace(start, std::move(bytes));
        }
        return result;
    }

    const hive_value* hive_key::get_value(hive_file& file, const std::string_view name)
    {
        this->parse(file);

        const auto entry = this->values_.find(name);
        if (entry == this->values_.end())
        {
            return nullptr;
        }

        auto& value = entry->second;

        if (!value.parsed)
        {
            value.data = read_file_data(file, MAIN_ROOT_OFFSET + value.data_offset, value.data_length);
            value.parsed = true;
        }

        return &value;
    }

    const hive_value* hive_key::get_value(hive_file& file, const size_t index)
    {
        this->parse(file);

        if (index >= values_by_index_.size())
        {
            return nullptr;
        }

        return get_value(file, values_by_index_[index]);
    }

    void hive_key::parse_subkey_list(hive_file& file, const int32_t block_offset, const bool allow_root_index)
    {
        const auto item = read_file_object<offsets_t>(file, MAIN_ROOT_OFFSET + block_offset);

        const bool simple_block = item.block_type[1] == 'f' || item.block_type[1] == 'h';
        if (!simple_block && (!allow_root_index || (item.block_type[0] != 'r' && item.block_type[1] != 'i')))
        {
            return;
        }

        const auto entry_offsets = block_offset + offsetof(offsets_t, entries);

        for (int16_t i = 0; i < item.count; ++i)
        {
            if (simple_block)
            {
                const auto offset_entry = read_file_object<offset_entry_t>(file, MAIN_ROOT_OFFSET + entry_offsets, i);
                const auto subkey_block_offset = MAIN_ROOT_OFFSET + offset_entry.offset;
                const auto subkey = read_file_object<key_block_t>(file, subkey_block_offset);
                const auto subkey_name_len = subkey.len < 0 ? size_t{0} : std::min(static_cast<size_t>(subkey.len), sizeof(subkey.name));
                std::string subkey_name(subkey.name, subkey_name_len);

                const auto [it, inserted] =
                    this->sub_keys_.emplace(std::move(subkey_name), hive_key{subkey.subkeys, subkey.value_count, subkey.offsets});
                if (inserted)
                {
                    this->sub_keys_by_index_.emplace_back(it->first);
                }
            }
            else
            {
                const auto offset_entry = read_file_object<int32_t>(file, MAIN_ROOT_OFFSET + entry_offsets, i);
                parse_subkey_list(file, offset_entry, false);
            }
        }
    }

    void hive_key::parse(hive_file& file)
    {
        if (this->parsed_)
        {
            return;
        }

        this->parsed_ = true;

        // Values

        for (auto i = 0; i < this->value_count_; i++)
        {
            const auto offset = read_file_object<int>(file, MAIN_ROOT_OFFSET + this->value_offsets_ + 4, i);
            const auto value = read_file_object<value_block_t>(file, MAIN_ROOT_OFFSET + offset);

            const auto value_name_len = value.name_len < 0 ? size_t{0} : std::min(static_cast<size_t>(value.name_len), sizeof(value.name));
            std::string value_name(value.name, value_name_len);

            raw_hive_value raw_value{};
            raw_value.parsed = false;
            raw_value.type = value.value_type;
            raw_value.name = value_name;
            raw_value.data_length = value.size & 0xffff;
            raw_value.data_offset = value.offset + 4;

            if (value.size & 1 << 31)
            {
                raw_value.data_offset = offset + static_cast<int>(offsetof(value_block_t, offset));
            }

            const auto [it, inserted] = this->values_.emplace(std::move(value_name), std::move(raw_value));
            if (inserted)
            {
                this->values_by_index_.emplace_back(it->first);
            }
        }

        // Subkeys

        parse_subkey_list(file, this->subkey_block_offset_, true);
    }

    hive_parser::hive_parser(const std::filesystem::path& file_path)
        : file_(file_path),
          root_key_(parse_root_block(file_, file_path))
    {
    }

    hive_parser::hive_parser(const uint64_t size, hive_file::ranges contents, const std::filesystem::path& fallback)
        : file_(size, std::move(contents), fallback),
          root_key_(parse_root_block(file_, fallback.empty() ? std::filesystem::path{"(recorded)"} : fallback))
    {
    }

} // namespace sogen
