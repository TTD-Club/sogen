#pragma once

#include "ttd_format.hpp"

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
        std::unordered_map<uint64_t, uint64_t> latest_version_{};
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
    decoded_chunk decode_chunk(std::span<const std::byte> compressed, std::span<const code_entry> code, const bulk_resolver& bulk);

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

    // The threads section is a zstd frame of varints: the switch count, per switch the step and event number deltas
    // and the thread id; then the name count, per name the thread id and the name as a length and UTF-8 bytes.
    std::vector<std::byte> encode_threads(const thread_table& threads);
    thread_table decode_threads(std::span<const std::byte> compressed);

    // A bulk block is a zstd frame of its bytes after an x86-64 filter that turns branch and RIP-relative
    // displacements into absolute block offsets (`filtered`; version 7 traces store the bytes unfiltered). An empty
    // result means compression or decompression failed.
    std::vector<std::byte> encode_bulk_block(std::span<const std::byte> data, int level);
    std::vector<std::byte> decode_bulk_block(std::span<const std::byte> compressed, bool filtered);
}
