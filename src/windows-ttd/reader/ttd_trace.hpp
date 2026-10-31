#pragma once

// The trace reader: everything that reads a recording without an emulator. Recording and replaying are in
// ttd_record.hpp and ttd_session.hpp (target windows-ttd); registers at a position are in ttd_view.hpp
// (target windows-ttd-view).

#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ttd_chunk.hpp"
#include "ttd_format.hpp"

namespace sogen::ttd
{
    using manifest_entries = std::vector<std::pair<std::string, std::string>>;

    // The manifest entry holding a recording's random id (see trace::id).
    constexpr std::string_view trace_id_key = "trace_id";

    // A replay that does not repeat the recording.
    class divergence_error : public std::runtime_error
    {
      public:
        using std::runtime_error::runtime_error;
    };

    struct trace_metadata
    {
        uint64_t instruction_count{};
        uint64_t event_count{};
    };

    struct module_symbol
    {
        const module_entry* module{};
        const module_export* symbol{};
    };

    struct symbol_location
    {
        const module_entry* module{};
        // Null when no export of the module is at or below the address.
        const module_export* symbol{};
        // From the export, or from the image base without one.
        uint64_t offset{};
    };

    struct checkpoint_state
    {
        uint64_t step{};
        std::shared_ptr<const std::vector<std::byte>> state{};
    };

    struct self_modifying_hit
    {
        uint64_t address{};
        uint64_t size{};
        uint64_t write_step{};
        uint64_t write_ip{};
        uint64_t execute_step{};
        uint64_t execute_ip{};
        uint64_t executions{};
    };

    // Thrown by a query or replay whose `interrupted` callback asked it to stop.
    class operation_cancelled : public std::runtime_error
    {
      public:
        operation_cancelled()
            : std::runtime_error("TTD operation cancelled")
        {
        }
    };

    // Lets the caller of a long query or replay follow and stop it. Both callbacks run on the calling thread, between
    // units of work (a batch of chunks, a slice of instructions), so they can drive a UI's wait box directly.
    struct operation_control
    {
        // Returning true stops the operation, which then throws operation_cancelled.
        std::function<bool()> interrupted{};
        // The work done so far out of `total`, in units of the operation's own choosing; `total` stays the same over one
        // operation.
        std::function<void(uint64_t done, uint64_t total)> progress{};

        // Throws operation_cancelled when interrupted.
        void check() const
        {
            if (interrupted && interrupted())
            {
                throw operation_cancelled();
            }
        }

        void report(const uint64_t done, const uint64_t total) const
        {
            if (progress)
            {
                progress(done, total);
            }
            check();
        }
    };

    // The trace format versions this library reads; files of other versions are refused. Within a version, sections
    // added later are optional (readers ignore section types they do not know), so newer files of a supported version
    // open, and the accessors for sections a file lacks report that (has_syscalls, has_mapping_changes, ...).
    constexpr uint32_t oldest_trace_version = 1;
    constexpr uint32_t newest_trace_version = 9;

    // Whether the file starts like a Sogen TTD trace of any version, readable or not; reads only its first 8 bytes.
    bool is_trace_file(const std::filesystem::path& path);
    // The format version of a trace file, or nothing if it is not one. Versions this library does not read are returned
    // too: compare with oldest_trace_version/newest_trace_version (or use is_supported_trace_version).
    std::optional<uint32_t> trace_file_version(const std::filesystem::path& path);
    bool is_supported_trace_version(uint32_t version);

    // A function entered at `entry_step` (its first instruction ran there), with what led there and when it returned.
    struct call_event
    {
        // The instruction that transferred control: the call (or jump) at `site`. UINT64_MAX when the thread entered the
        // function without an instruction of its own before it (its first instruction in the trace).
        uint64_t step{UINT64_MAX};
        uint64_t entry_step{};
        // The return instruction that left this invocation (cpu_at there shows the return value), or UINT64_MAX when the
        // trace does not show it: the function had not returned by the end of the trace, unwound without returning,
        // was entered by a jump, or the trace lacks the read and write events that pair calls with returns.
        uint64_t return_step{UINT64_MAX};
        // The address of the instruction at `step`, 0 without one.
        uint64_t site{};
        uint64_t target{};
        uint32_t thread_id{};
        // Whether the instruction at `step` is a call; false for a jump or any other way in.
        bool is_call{};
    };

    // Where an indirect call or jump at `site` went, and how often.
    struct indirect_branch
    {
        uint64_t site{};
        uint64_t target{};
        uint64_t hits{};
        // The first execution of the branch that went to `target`.
        uint64_t first_step{};
        bool is_call{};
    };

    // An exception the system dispatched to user mode (see trace::exceptions).
    struct exception_event
    {
        // The dispatcher's first instruction (ntdll!KiUserExceptionDispatcher).
        uint64_t step{};
        // The instruction that raised it (the faulting one, or the syscall of RaiseException), UINT64_MAX if unknown.
        uint64_t raise_step{UINT64_MAX};
        uint32_t thread_id{};
        uint32_t code{};
        uint32_t flags{};
        uint64_t address{};
        // ExceptionInformation[0..1]: for an access violation, whether it read (0), wrote (1), or executed (8), and
        // the address it accessed.
        std::array<uint64_t, 2> information{};
    };

    class view_engine;
    class keyframe_store;

    class trace
    {
      public:
        explicit trace(const std::filesystem::path& path);

        const trace_metadata& metadata() const
        {
            return metadata_;
        }

        std::span<const checkpoint_entry> checkpoints() const
        {
            return std::span(checkpoints_).subspan(1);
        }

        // The position of the initial state: zero unless the trace was recorded from a forked replay.
        uint64_t start_position() const
        {
            return checkpoints_.empty() ? 0 : checkpoints_.front().step;
        }

        // Empty for traces recorded before the manifest existed.
        const manifest_entries& manifest() const
        {
            return manifest_;
        }

        std::optional<std::string_view> manifest_value(std::string_view key) const;

        // Whether the trace holds what the recording read of its registry hives (registry_hives), so that replays need
        // no hive files.
        bool has_registry_hives() const
        {
            return !registry_hives_.empty();
        }

        // What the recording read of each registry hive file (decoded on each call; empty without has_registry_hives).
        std::vector<recorded_hive_file> registry_hives() const;

        // Identifies this recording: ASCII that differs between any two recordings (also of the same program) and stays
        // with the file when it is moved or copied, at most 33 characters. Recordings store a random id of 32 hex digits
        // (manifest key "trace_id"); for older ones it is "h" and 32 hex digits of a hash of the file's header and
        // tables, 33 characters.
        const std::string& id() const
        {
            return id_;
        }

        uint32_t version() const
        {
            return version_;
        }

        // Host window events delivered while recording, in delivery order.
        std::span<const ui_input_entry> ui_inputs() const
        {
            return ui_inputs_;
        }

        // False for traces recorded before syscalls were recorded; their replays verify host writes one by one.
        bool has_syscalls() const
        {
            return syscalls_.has_value();
        }

        // Every dispatched syscall in recording order (empty without has_syscalls()).
        std::span<const syscall_entry> syscalls() const
        {
            return syscalls_ ? std::span<const syscall_entry>(syscalls_->entries) : std::span<const syscall_entry>{};
        }

        // The name the recording emulator gave a syscall id, or nothing when the trace does not know it.
        std::optional<std::string_view> syscall_name(uint32_t id) const;

        // Every module mapped while recording, in load order (those mapped before the start first); empty for traces
        // recorded before modules were recorded.
        std::span<const module_entry> modules() const
        {
            return modules_;
        }

        // The module whose image holds `address` at position `step`.
        const module_entry* module_at(uint64_t address, uint64_t step) const;

        // `address` at position `step` as a module and its closest export at or below it, forwarded exports aside.
        std::optional<symbol_location> symbol_at(uint64_t address, uint64_t step) const;

        // The exports called `name`, or "module!name" (the module name ignoring case, ".dll" optional), in module load
        // order. Exports by ordinal only are called "#<ordinal>", and "#<ordinal>" also finds a named export.
        std::vector<module_symbol> find_exports(std::string_view name) const;

        // The execute events of the first instruction of each export find_exports(name) returns, at positions start
        // through end while its module was mapped, in order: the calls of a function, and jumps to it. A forwarded
        // export stands for its target while both modules are mapped, so this includes calls through other names.
        std::vector<access_event> calls(std::string_view name, uint64_t start, uint64_t end, const operation_control& control = {});

        // Every entry into the function at `address` at positions start through end, in order, with the instruction
        // that led there and the matching return (see call_event). Needs execute events; returns also need reads and
        // writes. Progress counts candidate chunks, then entries.
        std::vector<call_event> calls_to(uint64_t address, uint64_t start = 0, uint64_t end = UINT64_MAX,
                                         const operation_control& control = {});

        // The targets of the indirect calls (and, with `jumps`, indirect jumps) whose instruction starts in one of
        // `ranges` (address and size), by site and target. A branch that faulted instead of reaching its target is left
        // out. Needs execute events. Progress counts candidate chunks.
        std::vector<indirect_branch> indirect_branches(std::span<const std::pair<uint64_t, uint64_t>> ranges, bool jumps = false,
                                                       const operation_control& control = {});

        // Every exception the system dispatched to user mode (through ntdll!KiUserExceptionDispatcher), in order, read
        // from the exception records the dispatch wrote to the stack: faults, breakpoints, single steps, and exceptions
        // passed to NtRaiseException. RaiseException's software exceptions (C++ throw) are dispatched by ntdll in user
        // mode and do not appear (find them with calls_to on ntdll!RtlRaiseException). An entry whose record was not
        // found has code 0. Needs execute and host write events and the modules section.
        // Progress counts candidate chunks.
        std::vector<exception_event> exceptions(const operation_control& control = {});

        // The execute event of the instruction thread `thread_id` ran before position `step` (the previous instruction on
        // that thread), or nothing at its first instruction in the trace. Needs execute events.
        std::optional<access_event> previous_instruction(uint64_t step, uint32_t thread_id);
        // The execute event of the instruction thread `thread_id` runs after position `step`, or nothing after its last.
        std::optional<access_event> next_instruction(uint64_t step, uint32_t thread_id);

        // Thread switches and names; empty for traces recorded before threads were recorded.
        const thread_table& threads() const
        {
            return threads_;
        }

        // The thread running instruction `step`, or nothing before the first switch.
        std::optional<uint32_t> thread_at(uint64_t step) const;

        // Empty for traces recorded without register snapshots.
        std::span<const register_snapshot_entry> register_snapshots() const
        {
            return register_snapshots_;
        }

        // The registers of register snapshot `index`, as the backend's save_registers returned them.
        std::vector<std::byte> snapshot_registers(size_t index);

        // Every mapping and unmapping of guest memory, in order; nothing for traces that predate recording them.
        std::span<const mapping_change> mapping_changes() const
        {
            return mapping_changes_;
        }

        // Whether the trace records mapping changes (an empty list then means there were none).
        bool has_mapping_changes() const
        {
            return has_mapping_changes_;
        }

        // The stack of each thread that ran, in the order threads first ran (see thread_stack); empty for traces recorded
        // before stacks were (has_thread_stacks).
        std::span<const thread_stack> thread_stacks() const
        {
            return thread_stacks_;
        }

        bool has_thread_stacks() const
        {
            return has_thread_stacks_;
        }

        // The memory map at the start and every change to it, in order (see memory_region); empty for traces recorded
        // before it was (has_memory_regions).
        const memory_region_table& memory_regions() const
        {
            return memory_regions_;
        }

        bool has_memory_regions() const
        {
            return has_memory_regions_;
        }

        // Whether memory_at can take bytes no access shows from checkpoints (traces recorded with the checkpoint memory
        // section).
        bool has_checkpoint_memory() const
        {
            return !checkpoint_memory_offsets_.empty();
        }

        // The memory map at `position` (after the changes made up to and at it), as NtQueryVirtualMemory would list it:
        // reserved and committed ranges in address order, free memory left out. Empty without has_memory_regions().
        std::vector<memory_region> memory_regions_at(uint64_t position) const;

        // The mapped file of a region, empty for none.
        std::string_view memory_region_name(const memory_region& region) const
        {
            return region.name < memory_regions_.names.size() ? std::string_view(memory_regions_.names[region.name]) : std::string_view{};
        }

        // The stack of thread `thread_id`, or null when the trace does not record it.
        const thread_stack* thread_stack_of(uint32_t thread_id) const
        {
            const auto found = std::ranges::find(thread_stacks_, thread_id, &thread_stack::thread_id);
            return found == thread_stacks_.end() ? nullptr : &*found;
        }

        // The standalone CPU cpu_view replays on (see ttd_view.cpp), created on first use and kept with the reader.
        std::shared_ptr<view_engine>& view_engine_slot()
        {
            return view_engine_;
        }

        // Index of the checkpoint at `step` (0 for the initial state); throws if no checkpoint is there.
        uint64_t checkpoint_index(uint64_t step) const;

        bool has_instruction_bytes() const
        {
            return this->chunked() || version_ >= 4;
        }

        bool has_access_data() const
        {
            return this->chunked();
        }

        // How many decoded checkpoint states the reader keeps, least recently used dropped first (default 4, at least
        // 1). memory_at and cpu_view decode the checkpoint a position replays from, so callers that alternate between
        // a few checkpoint intervals (a call and its return) pay for each once. A state is about the size of the
        // guest's committed memory.
        void set_checkpoint_cache_size(size_t count);

        size_t checkpoint_cache_size() const
        {
            return checkpoint_cache_size_;
        }

        // The position of the checkpoint that checkpoint_for_step(step) restores, without decoding it.
        uint64_t checkpoint_step_for(uint64_t step) const;
        checkpoint_state checkpoint_for_step(uint64_t step);

        // Where windows-ttd keeps the states replays of this trace reached (null until first used): see keyframes() and
        // share_keyframes() in ttd_keyframes.hpp, which need the emulator. The reader only holds the pointer.
        std::shared_ptr<keyframe_store>& keyframes_slot() const
        {
            return keyframes_;
        }

        const std::filesystem::path& path() const
        {
            return path_;
        }

        // Progress counts candidate chunks.
        std::vector<access_event> accesses(uint64_t address, uint64_t size, uint64_t first_step = 0, uint64_t last_step = UINT64_MAX,
                                           uint64_t kind_mask = all_access_kinds, const operation_control& control = {});
        std::optional<access_event> next_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask = all_access_kinds);
        std::optional<access_event> previous_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask = all_access_kinds);
        // The bytes of [address, address + size) at `position` (before instruction position + 1 runs, like cpu_view).
        // With has_checkpoint_memory: the latest write or host write since the checkpoint the position replays from,
        // found walking back from the position, else the checkpoint's memory, so the cost follows the writes to the
        // memory, not its reads and executions. Bytes mapped since the checkpoint and not written after are zero while
        // committed (has_memory_regions) and nothing otherwise. MMIO (host-aliased memory included, whose contents
        // checkpoints don't save) is read from accesses as below.
        // Otherwise: each byte from the latest access at or before the position that shows it (a read, a write, a host
        // write, or executed bytes), else from the first later access if that one reads or executes it; an access
        // counts only when the memory was not mapped or unmapped between it and the position. Nothing for the rest.
        // Traces without mapping changes cannot tell remapped memory apart. Progress counts candidate chunks.
        std::vector<std::optional<uint8_t>> memory_at(uint64_t position, uint64_t address, uint64_t size,
                                                      const operation_control& control = {});
        // Progress counts events.
        std::vector<self_modifying_hit> self_modifying_code(const operation_control& control = {});
        access_event event_at(uint64_t number);
        size_t read_events(uint64_t first_number, std::span<access_event> output);
        uint64_t first_event_after(uint64_t step);
        // The number of the first event after the state a replay stands in at `step`. The events recorded at a
        // position come before that state, except at a checkpoint: window input delivered at the first pump after it
        // (logged with its index) is recorded at its position too.
        uint64_t first_event_after_state(uint64_t step);
        uint64_t access_mask();
        std::vector<std::byte> access_data(const access_event& event);
        std::optional<uint64_t> latest_write_to_byte(uint64_t page, uint64_t address, uint64_t first_number, uint64_t last_number);

      private:
        struct number_range
        {
            uint64_t begin{};
            uint64_t end{};
        };

        struct cached_chunk
        {
            uint32_t index{};
            decoded_chunk chunk{};
        };

        struct cached_bulk
        {
            uint64_t index{};
            bulk_block block{};
        };

        std::ifstream file_;
        trace_metadata metadata_{};
        uint32_t version_{};
        std::optional<uint64_t> access_mask_{};
        std::vector<checkpoint_entry> checkpoints_{};
        manifest_entries manifest_{};
        std::vector<ui_input_entry> ui_inputs_{};
        std::optional<syscall_table> syscalls_{};
        std::vector<module_entry> modules_{};
        thread_table threads_{};
        std::vector<register_snapshot_entry> register_snapshots_{};
        // Empty for traces recorded before mapping changes were, whose memory_at cannot notice remapped memory.
        std::vector<mapping_change> mapping_changes_{};
        bool has_mapping_changes_{};
        std::vector<thread_stack> thread_stacks_{};
        bool has_thread_stacks_{};
        memory_region_table memory_regions_{};
        bool has_memory_regions_{};
        // Per checkpoint, where the memory manager's state begins in its decoded state; empty for traces without it.
        std::vector<uint64_t> checkpoint_memory_offsets_{};
        // The registry hives section as stored (compressed); empty for traces without it.
        std::vector<std::byte> registry_hives_{};

        // memory_at from the accesses to the memory, then the checkpoint for bytes they don't show.
        std::vector<std::optional<uint8_t>> memory_from_accesses(uint64_t position, uint64_t address, uint64_t size,
                                                                 const operation_control& control);
        // memory_at from the checkpoint and the writes since (has_checkpoint_memory).
        std::vector<std::optional<uint8_t>> memory_from_checkpoint(uint64_t position, uint64_t address, uint64_t size,
                                                                   const operation_control& control);

        // The committed memory of a checkpoint: by address, each range's length and its offset in the state
        // (no_contents for MMIO, whose contents are not saved).
        struct checkpoint_memory
        {
            static constexpr size_t no_contents = SIZE_MAX;

            std::shared_ptr<const std::vector<std::byte>> state{};
            std::map<uint64_t, std::pair<uint64_t, size_t>> ranges{};
        };

        // Least recently used first, at most checkpoint_cache_size_ each (see set_checkpoint_cache_size).
        std::vector<std::pair<uint64_t, std::shared_ptr<const checkpoint_memory>>> checkpoint_memory_cache_{};
        std::shared_ptr<const checkpoint_memory> checkpoint_memory_at(uint64_t index);
        // Fills the bytes of `value` (at `address`, `position`) that no access showed from the memory of the checkpoint
        // the position replays from, where nothing remapped them between it and `boundary`.
        void fill_from_checkpoint(uint64_t position, uint64_t address, uint64_t boundary, std::vector<std::optional<uint8_t>>& value);
        // Whether a mapping change covering `address` came after event `after_number` and before event `through_number`.
        bool remapped(uint64_t address, uint64_t after_number, uint64_t through_number) const;
        std::shared_ptr<view_engine> view_engine_{};
        // The last decoded snapshot base: its index and registers.
        std::optional<std::pair<uint64_t, std::vector<std::byte>>> register_base_cache_{};

        std::vector<chunk_entry> chunks_{};
        std::vector<code_entry> code_{};
        std::vector<page_block> page_blocks_{};
        std::vector<bulk_entry> bulk_table_{};
        std::vector<cached_bulk> bulk_cache_{};
        std::vector<cached_chunk> chunk_cache_{};
        std::vector<std::pair<uint64_t, std::shared_ptr<const std::vector<std::byte>>>> state_cache_{};
        size_t checkpoint_cache_size_{4};
        std::filesystem::path path_{};
        std::string id_{};
        // Created on first use by keyframes() (windows-ttd), so the reader does not need keyframe_store.
        mutable std::shared_ptr<keyframe_store> keyframes_{};

        uint64_t legacy_event_offset_{};
        uint64_t legacy_event_size_{};
        uint64_t legacy_index_offset_{};
        uint64_t legacy_index_count_{};

        bool chunked() const
        {
            return version_ >= 7;
        }

        void read_chunked_layout(uint64_t length);
        void read_legacy_layout(uint64_t length);
        std::vector<std::byte> read_bytes(uint64_t offset, uint64_t size);
        const decoded_chunk& chunk(uint32_t index);
        bulk_block bulk(uint64_t index);
        // The given blocks by index, decoding the uncached ones in parallel.
        std::unordered_map<uint64_t, bulk_block> bulk_blocks(std::span<const uint64_t> indexes);
        void remember_bulk(uint64_t index, bulk_block block);
        uint32_t chunk_of(uint64_t number) const;
        std::shared_ptr<const std::vector<std::byte>> checkpoint_state_at(uint64_t index);
        std::vector<number_range> candidates(uint64_t first_page, uint64_t last_page, uint64_t kind_mask, uint64_t first_number,
                                             uint64_t end_number);
        std::vector<number_range> chunked_candidates(uint64_t first_page, uint64_t last_page, uint64_t kind_mask);
        // The events of `ranges` (in order, each within one chunk) for which `matches` holds, in order. Uncached chunks
        // decode on worker threads, a batch at a time; without `with_data`, reads and writes come without their bytes
        // (see decode_chunk).
        // `control` is checked and told about progress (in ranges) after each batch.
        std::vector<access_event> matching_events(std::span<const number_range> ranges,
                                                  const std::function<bool(const access_event&)>& matches, bool with_data,
                                                  const operation_control& control = {});
        void compute_id();
        // The execute event of instruction `position`, if the trace has one.
        std::optional<access_event> execute_at(uint64_t position);
        std::optional<uint64_t> return_of_call(const access_event& call, uint64_t entry_step, uint32_t thread_id);
        std::vector<number_range> legacy_candidates(uint64_t first_page, uint64_t last_page, uint64_t kind_mask, uint64_t first_number,
                                                    uint64_t end_number);
        uint64_t first_event_at_or_after(uint64_t step);
    };

    struct trace_difference
    {
        // The differing events and their numbers in each trace. An absent event means that trace has no further event up
        // to the end both share; its number is then meaningless.
        uint64_t first_number{};
        std::optional<access_event> first{};
        uint64_t second_number{};
        std::optional<access_event> second{};
    };

    // The first event two traces record differently, comparing the kinds both recorded (with their data) from the
    // later start position to the earlier end; nothing when they agree. For a fork and its parent this is where the
    // change first shows.
    std::optional<trace_difference> first_difference(trace& first, trace& second);

    class event_reader
    {
      public:
        explicit event_reader(trace& recorded, uint64_t first_number = 0);
        std::optional<access_event> next(uint64_t kind_mask = all_access_kinds);

        uint64_t last_number() const
        {
            return last_number_;
        }

      private:
        trace& trace_;
        std::vector<access_event> buffer_{};
        uint64_t buffer_first_{};
        size_t position_{};
        uint64_t last_number_{};
    };

}
