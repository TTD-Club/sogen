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
        // otherwise their offset within the chunk's data blob (bytes 0-7) and the chunk's index (bytes 8-15).
        std::array<uint8_t, 16> payload{};
    };

    static_assert(sizeof(access_event) == 56);

    constexpr size_t inline_data_limit = sizeof(access_event::payload);

    // Version 6 layout: a fixed header, then event chunks and checkpoints in recording order, then the tables the
    // section table points to. Unknown section types are ignored, so sections can be added without a new version.
    struct file_header
    {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        char magic[8]{'S', 'O', 'G', 'T', 'T', 'D', '6', '\0'};
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

    static_assert(sizeof(file_header) == 48);
    static_assert(sizeof(section_entry) == 24);
    static_assert(sizeof(chunk_entry) == 48);
    static_assert(sizeof(checkpoint_entry) == 32);
    static_assert(sizeof(page_entry) == 16);
}
