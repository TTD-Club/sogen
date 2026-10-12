#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

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
        // How the trace was recorded, as UTF-8 key/value pairs; the section size is the byte count. Each pair is a
        // uint32 key length and a uint32 value length followed by the key and value bytes.
        manifest = 6,
        // ui_input_entry array (size = entry count): host window events delivered to the guest while recording.
        ui_inputs = 7,
        // Every dispatched syscall (see syscall_entry), encoded as described at encode_syscalls; the section size is the
        // compressed byte count.
        syscalls = 8,
        // The modules mapped while recording, encoded as described at encode_modules; size = compressed bytes.
        modules = 9,
        // The running thread over the recording, encoded as described at encode_threads; size = compressed bytes.
        threads = 10,
        // The export directories of the modules in the modules section, encoded as described at encode_exports;
        // size = compressed bytes.
        exports = 11,
        // The targets of the forwarded exports in the exports section, encoded as described at
        // encode_export_forwarders; size = compressed bytes.
        export_forwarders = 12,
        // The register snapshots (see register_snapshot_entry), encoded as described at encode_register_snapshots;
        // size = compressed bytes.
        register_snapshots = 13,
        // Every mapping and unmapping of guest memory (see mapping_change), encoded as described at
        // encode_mapping_changes; size = compressed bytes.
        mapping_changes = 14,
        // The PE machine of each module in the modules section, encoded as described at encode_module_machines;
        // size = compressed bytes.
        module_machines = 15,
        // The stack of each thread that ran (see thread_stack), encoded as described at encode_thread_stacks;
        // size = compressed bytes.
        thread_stacks = 16,
        // The memory map at the start and its changes (see memory_region), encoded as described at
        // encode_memory_regions; size = compressed bytes.
        memory_regions = 17,
    };

    // What NtQueryVirtualMemory showed for [address, address + size) from position `step` on (after `event_number`
    // events), until a later entry covers the range again. The entries at the trace's start position with event number
    // 0 are the memory that existed when recording began (free memory then is not listed); later ones describe a range
    // whose reservation, commit, protection or mapping changed, free memory included. The values are Windows' own:
    // MEM_* states and types, PAGE_* protections (PAGE_GUARD included).
    struct memory_region
    {
        uint64_t step{};
        uint64_t event_number{};
        uint64_t address{};
        uint64_t size{};
        // The reservation's base and its protection when reserved (AllocationProtect); 0 for free memory.
        uint64_t allocation_base{};
        uint32_t allocation_protection{};
        // MEM_COMMIT, MEM_RESERVE or MEM_FREE.
        uint32_t state{};
        // MEM_PRIVATE, MEM_MAPPED or MEM_IMAGE; 0 for free memory.
        uint32_t type{};
        // The protection of committed memory; 0 otherwise.
        uint32_t protection{};
        // Sogen's finer kind: 0 free, 1 private, 2 file view, 3 pagefile-backed view, 4 image, 5 MMIO or host-aliased
        // memory, 6 reserved for the host.
        uint32_t kind{};
        // The mapped file of a file view, as an index into memory_region_table::names; UINT32_MAX for none. Images have
        // none: the modules section names them (trace::module_at).
        uint32_t name{UINT32_MAX};
    };

    struct memory_region_table
    {
        std::vector<memory_region> regions{};
        std::vector<std::string> names{};
    };

    // A thread's stack as its TEB (NT_TIB StackBase and StackLimit) described it when the thread first ran in the trace:
    // at its creation, or at the trace's start for a thread that already existed. Sogen commits a thread's whole stack
    // when it creates it, so these hold for the thread's life unless the guest rewrites its TEB itself (fibers, which
    // memory_at at the TEB shows).
    struct thread_stack
    {
        uint32_t thread_id{};
        // The thread's first instruction in the trace, and the number of events recorded before it.
        uint64_t step{};
        uint64_t event_number{};
        uint64_t teb{};
        // The stack's high end (StackBase) and low end (StackLimit): it holds [stack_limit, stack_base).
        uint64_t stack_base{};
        uint64_t stack_limit{};
        // For a WoW64 thread, its 32-bit TEB and the 32-bit stack; 0 otherwise.
        uint64_t teb32{};
        uint64_t stack32_base{};
        uint64_t stack32_limit{};
    };

    // Guest memory [address, address + size) was mapped or unmapped at position `step`, after `event_number` events,
    // so its bytes no longer hold what earlier accesses showed.
    struct mapping_change
    {
        uint64_t step{};
        uint64_t event_number{};
        uint64_t address{};
        uint64_t size{};
    };

    // The CPU registers (the backend's save_registers, zstd-compressed) at position `step`, after `event_number` events.
    // The recorder takes one before the first instruction, after anything but a guest instruction changed registers or
    // memory (syscalls, thread switches, exception dispatch, instruction hooks, host writes), and at least every so many
    // instructions, so the instructions up to the next snapshot depend only on these registers and the bytes the trace
    // records for them. A snapshot with a base is a zstd delta against the base's registers; a base has none.
    struct register_snapshot_entry
    {
        uint64_t step{};
        uint64_t event_number{};
        uint64_t offset{};
        uint64_t size{};
        uint64_t base{UINT64_MAX};
    };

    // A syscall instruction the emulator dispatched: its handler ran after `event_number` events had been recorded,
    // produced the next `event_count` events (its host writes, and the descriptor table reads of segment registers it
    // loads), and left `result` in RAX. A replay checks the syscall as one unit and, unless strict, gives the guest the
    // recorded host writes and result when the live ones differ.
    struct syscall_entry
    {
        uint64_t step{};
        uint64_t event_number{};
        uint64_t event_count{};
        uint64_t result{};
        uint32_t id{};
    };

    // A window event the host UI delivered between instruction slices. It reached the guest after `event_number`
    // events had been recorded, after checkpoint `checkpoint` was taken; a replay delivers it at that point instead
    // of taking live input.
    struct ui_input_entry
    {
        uint64_t checkpoint{};
        uint64_t event_number{};
        uint64_t step{};
        uint64_t window{};
        uint32_t message{};
        uint32_t reserved{};
        uint64_t wparam{};
        uint64_t lparam{};
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

    // Checkpoint 0 is the initial state; its step is the first position of the trace, which is not zero for a trace
    // recorded from a forked replay. A checkpoint with a base is a zstd delta against the base's state.
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
    static_assert(sizeof(ui_input_entry) == 56);
    static_assert(sizeof(register_snapshot_entry) == 40);
}
