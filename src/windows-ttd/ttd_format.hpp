#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace sogen::ttd
{
    enum class access_kind : uint64_t
    {
        read = 1,
        write = 2,
        execute = 4,
        host_write = 8,
    };

    constexpr uint64_t all_access_kinds = 15;

    constexpr const char* access_kind_name(const access_kind kind)
    {
        switch (kind)
        {
        case access_kind::read:
            return "read";
        case access_kind::write:
            return "write";
        case access_kind::execute:
            return "execute";
        case access_kind::host_write:
            return "host-write";
        }
        return "unknown";
    }

    struct access_event
    {
        // Emulator instruction counter while the access happens, i.e. the 1-based number of the instruction performing
        // it. The execute event fires before that instruction runs, but the emulator's counting hook is registered
        // first, so it carries the same step as the instruction's reads and writes. Seeking to position N yields the
        // state after instruction N.
        uint64_t step{};
        uint64_t ip{};
        uint64_t address{};
        uint64_t size{};
        access_kind kind{};
        // Execute: the instruction bytes just before execution. Reads and writes: the accessed bytes when size <= 16,
        // otherwise their offset within a bulk block (bytes 0-7) and the block's index (bytes 8-15).
        std::array<uint8_t, 16> payload{};
    };

    static_assert(sizeof(access_event) == 56);

    constexpr size_t inline_data_limit = sizeof(access_event::payload);

    // Version 8 layout: a fixed header, then event chunks and checkpoints in recording order, then the tables the
    // section table points to. Unknown section types are ignored, so sections can be added without a new version.
    // Version 7 differs only in storing bulk blocks without the x86-64 filter.
    struct file_header
    {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        char magic[8]{'S', 'O', 'G', 'T', 'T', 'D', '8', '\0'};
        uint64_t instruction_count{};
        uint64_t event_count{};
        uint64_t access_mask{};
        uint64_t section_count{};
        uint64_t section_table_offset{};
    };

    enum class section_type : uint64_t
    {
        chunk_table = 1,
        checkpoint_table = 2,
        page_index = 3,
        // zstd-compressed code_entry array; the section size is the compressed byte count.
        code_table = 4,
        bulk_table = 5,
    };

    struct section_entry
    {
        section_type type{};
        uint64_t offset{};
        uint64_t size{};
    };

    struct chunk_entry
    {
        uint64_t first_event{};
        uint64_t event_count{};
        uint64_t first_step{};
        uint64_t last_step{};
        uint64_t offset{};
        uint64_t size{};
    };

    constexpr uint64_t no_base_checkpoint = UINT64_MAX;

    // A checkpoint delta whose base is at most this many checkpoints back references the base's state followed by
    // the bulk blocks recorded between the two checkpoints, so data written by large accesses is stored only once.
    constexpr uint64_t bulk_reference_span = 16;

    // Checkpoint 0 is the initial state. A checkpoint with a base is a zstd delta against the base's state.
    struct checkpoint_entry
    {
        uint64_t step{};
        uint64_t offset{};
        uint64_t size{};
        uint64_t base{no_base_checkpoint};
    };

    struct page_entry
    {
        uint64_t page{};
        uint32_t chunk{};
        uint32_t kinds{};
    };

    constexpr uint64_t page_block_entries = 4096;

    // The page index is a directory of blocks, each a zstd frame holding up to page_block_entries consecutive
    // page_entry values (sorted by page and chunk) as varint columns.
    struct page_block
    {
        uint64_t first_page{};
        uint64_t entry_count{};
        uint64_t offset{};
        uint64_t size{};
    };

    // Bulk block i is one zstd frame (or nothing, when size is zero) holding, in recording order, the bytes of every
    // access larger than inline_data_limit that was recorded after checkpoint i and before checkpoint i + 1, filtered
    // as described at encode_bulk_block.
    struct bulk_entry
    {
        uint64_t offset{};
        uint64_t size{};
    };

    // One distinct executed instruction: its address, length, and bytes. Execute events refer to entries by index.
    struct code_entry
    {
        uint64_t address{};
        uint64_t size{};
        std::array<uint8_t, 16> bytes{};
    };

    static_assert(sizeof(file_header) == 48);
    static_assert(sizeof(code_entry) == 32);
    static_assert(sizeof(bulk_entry) == 16);
    static_assert(sizeof(section_entry) == 24);
    static_assert(sizeof(chunk_entry) == 48);
    static_assert(sizeof(checkpoint_entry) == 32);
    static_assert(sizeof(page_entry) == 16);
    static_assert(sizeof(page_block) == 32);
}
