#pragma once

#include "ttd_format.hpp"

#include <algorithm>
#include <bit>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace sogen::ttd
{
    struct decoded_chunk
    {
        std::vector<access_event> events{};
    };

    using bulk_block = std::shared_ptr<const std::vector<std::byte>>;
    using bulk_resolver = std::function<bulk_block(uint64_t index)>;

    // A map from uint64 keys to uint64 values that only grows: open addressing with linear probing. The recorder and the
    // chunk codec look keys up for every event, where std::unordered_map's node allocations and pointer chasing dominated.
    class flat_map
    {
      public:
        const uint64_t* find(const uint64_t key) const
        {
            if (key == empty_key)
            {
                return this->has_empty_key_ ? &this->empty_key_value_ : nullptr;
            }
            if (this->slots_.empty())
            {
                return nullptr;
            }
            for (auto index = this->home(key);; index = (index + 1) & this->mask_)
            {
                const auto& slot = this->slots_[index];
                if (slot.key == key)
                {
                    return &slot.value;
                }
                if (slot.key == empty_key)
                {
                    return nullptr;
                }
            }
        }

        void set(const uint64_t key, const uint64_t value)
        {
            if (key == empty_key)
            {
                this->has_empty_key_ = true;
                this->empty_key_value_ = value;
                return;
            }
            if ((this->size_ + 1) * 2 > this->slots_.size())
            {
                this->grow();
            }
            for (auto index = this->home(key);; index = (index + 1) & this->mask_)
            {
                auto& slot = this->slots_[index];
                if (slot.key == key)
                {
                    slot.value = value;
                    return;
                }
                if (slot.key == empty_key)
                {
                    slot = {.key = key, .value = value};
                    ++this->size_;
                    return;
                }
            }
        }

        // Removes every key and keeps the allocation.
        void clear()
        {
            std::ranges::fill(this->slots_, slot{});
            this->size_ = 0;
            this->has_empty_key_ = false;
        }

      private:
        static constexpr uint64_t empty_key = UINT64_MAX;

        struct slot
        {
            uint64_t key{empty_key};
            uint64_t value{};
        };

        std::vector<slot> slots_{};
        size_t mask_{};
        size_t shift_{};
        size_t size_{};
        bool has_empty_key_{};
        uint64_t empty_key_value_{};

        size_t home(const uint64_t key) const
        {
            return static_cast<size_t>((key * 0x9E3779B97F4A7C15ULL) >> this->shift_);
        }

        void grow()
        {
            const auto old = std::move(this->slots_);
            const size_t capacity = old.empty() ? 1024 : old.size() * 2;
            this->slots_.assign(capacity, {});
            this->mask_ = capacity - 1;
            this->shift_ = 64 - static_cast<size_t>(std::countr_zero(capacity));
            this->size_ = 0;
            for (const auto& entry : old)
            {
                if (entry.key != empty_key)
                {
                    this->set(entry.key, entry.value);
                }
            }
        }
    };

    // Distinct executed instructions of a whole recording, in order of first execution.
    class code_table
    {
      public:
        uint64_t id_of(const access_event& execute);

        const std::vector<code_entry>& entries() const
        {
            return entries_;
        }

      private:
        std::vector<code_entry> entries_{};
        std::vector<uint64_t> previous_version_{};
        flat_map latest_version_{};
    };

    // A chunk is a zstd frame of a header and eight streams: one tag byte per event (kind, irregular step, and new code
    // or known value flags), then varint steps, instruction pointers, code ids, addresses, sizes, access data, and bulk
    // references. Each stream predicts from earlier events of the same chunk only, so chunks decode independently given
    // the code table and the bulk blocks. Accesses larger than an event payload keep their bytes in a bulk block; their
    // payload holds the offset and block index, which `bulk` resolves. encode_chunk returns the frame's content; the
    // caller compresses it.
    //
    // Encoding needs no shared recorder state, so it can run on a worker: `code_ids` holds the code table id of each
    // execute event in order, and `bulk` the bytes of every large access in the chunk, which all lie in one block.
    struct chunk_bulk_bytes
    {
        uint64_t block{};
        // Offset of bytes->front() within the block.
        uint64_t offset{};
        bulk_block bytes{};
    };

    std::vector<std::byte> encode_chunk(std::span<const access_event> events, std::span<const uint64_t> code_ids,
                                        const chunk_bulk_bytes& bulk);
    // Without `with_data`, reads and writes keep their positions, addresses, and sizes but not their bytes: no bulk block
    // is resolved, and reads predicted from known memory come out as zeros. Execute events are complete either way.
    decoded_chunk decode_chunk(std::span<const std::byte> compressed, std::span<const code_entry> code, const bulk_resolver& bulk,
                               bool with_data = true);

    // A page block stores page deltas, chunks (as deltas while the page repeats), and kinds as three streams.
    std::vector<std::byte> encode_page_block(std::span<const page_entry> entries);
    std::vector<page_entry> decode_page_block(std::span<const std::byte> compressed, const page_block& block);

    struct syscall_table
    {
        std::vector<syscall_entry> entries{};
        // The names of the ids that occur, as the recording emulator's ntdll and win32u export them.
        std::map<uint32_t, std::string> names{};
    };

    // The syscalls section is a zstd frame of the entry and name counts, six stream sizes, and six streams: step deltas,
    // event_number gaps (to the end of the previous entry's events), ids, and event counts as varints, results as
    // little-endian uint64 values, and the names as varint id, varint length, and bytes.
    std::vector<std::byte> encode_syscalls(const syscall_table& table);
    syscall_table decode_syscalls(std::span<const std::byte> compressed);

    // A symbol a module's export directory lists; `name` is "#<ordinal>" for one exported by ordinal only.
    struct module_export
    {
        uint64_t rva{};
        uint64_t ordinal{};
        std::string name{};
        // For an export the loader resolves in another module, that export as "module.dll!name" or
        // "module.dll!#<ordinal>", with an API set name already resolved to its host module; then `rva` points at the
        // forwarder string. Empty otherwise.
        std::string forwarder{};
    };

    // A module mapped into the process: present from load_step (after load_event_number events; the start of the trace
    // for modules mapped before it) until unload_step, if it was unmapped while recording.
    struct module_entry
    {
        uint64_t base{};
        uint64_t size{};
        uint64_t load_step{};
        uint64_t load_event_number{};
        std::optional<uint64_t> unload_step{};
        std::optional<uint64_t> unload_event_number{};
        std::string name{};
        std::string path{};
        // Sorted by RVA, then name; null for traces without the exports section. Shared, so copies stay cheap.
        std::shared_ptr<const std::vector<module_export>> exports{};
    };

    // From event `event_number` (at step `step`) on, thread `thread_id` runs: with execute events recorded, the event is
    // the thread's first instruction after the switch.
    struct thread_switch
    {
        uint64_t step{};
        uint64_t event_number{};
        uint32_t thread_id{};
    };

    struct thread_table
    {
        std::vector<thread_switch> switches{};
        // UTF-8 names of the threads that ran, empty for unnamed ones.
        std::map<uint32_t, std::string> names{};
    };

    // The modules section is a zstd frame of a varint count and per module, as varints: base, size, load step, load
    // event number, unload step + 1 (0 while loaded at the end), unload event number, then the name and the path as a
    // varint length and UTF-8 bytes.
    std::vector<std::byte> encode_modules(std::span<const module_entry> modules);
    std::vector<module_entry> decode_modules(std::span<const std::byte> compressed);

    // The exports section is a zstd frame of the module count (that of the modules section, whose order it follows) and
    // three stream sizes as little-endian uint64 values, then three streams over each module's exports in ordinal
    // order: per module the export count and per export the ordinal delta as varints; the RVAs as little-endian uint32
    // values; and the names as the varint length of the prefix shared with the previous name of the module, then the
    // rest as a varint length and UTF-8 bytes (empty for an export by ordinal only). decode_exports fills in the exports
    // of the decoded modules.
    std::vector<std::byte> encode_exports(std::span<const module_entry> modules);
    void decode_exports(std::span<const std::byte> compressed, std::span<module_entry> modules);

    // The export forwarders section is a zstd frame of varints: the module count (that of the modules section), then
    // per module the number of forwarded exports and per forwarded export, in ordinal order, the ordinal delta and the
    // forwarder as a length and UTF-8 bytes. decode_export_forwarders fills them into the decoded exports.
    std::vector<std::byte> encode_export_forwarders(std::span<const module_entry> modules);
    void decode_export_forwarders(std::span<const std::byte> compressed, std::span<module_entry> modules);

    // The threads section is a zstd frame of varints: the switch count, per switch the step and event number deltas
    // and the thread id; then the name count, per name the thread id and the name as a length and UTF-8 bytes.
    // The register snapshots section is a zstd frame of varints: the entry count, then per entry the step and
    // event_number deltas, the offset relative to the end of the previous entry's bytes (zigzag), the size, and the
    // distance back to the base entry (0 for an entry without a base).
    std::vector<std::byte> encode_register_snapshots(std::span<const register_snapshot_entry> entries);
    std::vector<register_snapshot_entry> decode_register_snapshots(std::span<const std::byte> compressed);

    // The mapping changes section is a zstd frame of varints: the count, then per change the step and event_number
    // deltas, the address relative to the previous change's (zigzag), and the size.
    std::vector<std::byte> encode_mapping_changes(std::span<const mapping_change> changes);
    std::vector<mapping_change> decode_mapping_changes(std::span<const std::byte> compressed);

    std::vector<std::byte> encode_threads(const thread_table& threads);
    thread_table decode_threads(std::span<const std::byte> compressed);

    // A bulk block is a zstd frame of its bytes after an x86-64 filter that turns branch and RIP-relative
    // displacements into absolute block offsets (`filtered`; version 7 traces store the bytes unfiltered). An empty
    // result means compression or decompression failed.
    std::vector<std::byte> encode_bulk_block(std::span<const std::byte> data, int level);
    std::vector<std::byte> decode_bulk_block(std::span<const std::byte> compressed, bool filtered);
}
