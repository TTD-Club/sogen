#pragma once

// Recording and replay verification: the parts of windows-ttd that run an emulator. The reader is ttd_trace.hpp.

#include <cstdint>
#include <cstddef>
#include <array>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <windows_emulator.hpp>
#include <emulator/scoped_hook.hpp>

#include "ttd_compressor.hpp"
#include "ttd_keyframes.hpp"
#include "ttd_trace.hpp"
#include "ttd_ui.hpp"

namespace sogen::ttd
{
    // Keeps a callback in one of the emulator's callback lists until destroyed or reset.
    template <typename Signature>
    class scoped_callback
    {
      public:
        scoped_callback() = default;

        scoped_callback(utils::callback_list<Signature>& list, std::function<Signature> callback)
            : list_(&list),
              id_(list.add(std::move(callback)))
        {
        }

        ~scoped_callback()
        {
            reset();
        }

        scoped_callback(const scoped_callback&) = delete;
        scoped_callback& operator=(const scoped_callback&) = delete;

        scoped_callback(scoped_callback&& other) noexcept
        {
            *this = std::move(other);
        }

        scoped_callback& operator=(scoped_callback&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                list_ = std::exchange(other.list_, nullptr);
                id_ = other.id_;
            }
            return *this;
        }

        void reset()
        {
            if (list_)
            {
                list_->remove(id_);
                list_ = nullptr;
            }
        }

      private:
        utils::callback_list<Signature>* list_{};
        utils::callback_id_type id_{};
    };

    using syscall_callback = scoped_callback<void(uint32_t syscall_id)>;
    using module_callback = scoped_callback<void(mapped_module& mod)>;
    using instruction_callback = scoped_callback<void(uint64_t address, size_t size)>;

    class recorder
    {
      public:
        recorder(windows_emulator& emu, const std::filesystem::path& path, uint64_t access_mask = all_access_kinds,
                 manifest_entries manifest = {});
        ~recorder();
        recorder(const recorder&) = delete;
        recorder& operator=(const recorder&) = delete;
        void checkpoint();
        void finish();

      private:
        static constexpr size_t events_per_chunk = 65536;
        static constexpr size_t checkpoints_per_level = 16;
        static constexpr size_t checkpoint_levels = 8;
        // Chunks and bulk blocks compress on background threads, so these slow, strong levels do not slow recording
        // down. Level 19 takes about as long per chunk as recording it; two chunk workers still slowed a test-sample
        // recording by 10%, four did not.
        static constexpr int chunk_compression_level = 19;
        static constexpr int bulk_compression_level = 19;
        static constexpr size_t chunk_workers = 4;
        static constexpr size_t bulk_workers = 4;
        static constexpr size_t max_pending_compressions = 16;
        // A checkpoint delta takes about 120 ms at full size, longer than recording the 500,000 instructions between
        // checkpoints once events are cheap, so several compress at once. Each pending one holds a full emulator state.
        static constexpr size_t checkpoint_workers = 4;
        static constexpr size_t max_pending_checkpoints = 2;

        windows_emulator& emu_;
        std::filesystem::path path_;
        std::ofstream file_;
        file_header header_{};
        std::vector<chunk_entry> chunks_{};
        std::vector<page_entry> pages_{};
        std::vector<checkpoint_entry> checkpoints_{};
        code_table code_{};
        std::vector<access_event> chunk_events_{};
        std::vector<bulk_entry> bulk_table_{};
        manifest_entries manifest_{};
        std::shared_ptr<std::vector<std::byte>> current_bulk_{std::make_shared<std::vector<std::byte>>()};
        // Size of current_bulk_ when the open chunk started.
        uint64_t chunk_bulk_start_{};
        // The last bulk_reference_span closed blocks, oldest first.
        std::deque<bulk_block> recent_bulk_{};
        background_compressor bulk_compressor_{
            [](const std::span<const std::byte> data) { return encode_bulk_block(data, bulk_compression_level); }, bulk_workers,
            max_pending_compressions};
        // Encodes and compresses chunks (see flush_chunk).
        background_compressor chunk_compressor_{{}, chunk_workers, max_pending_compressions};
        background_compressor checkpoint_compressor_{{}, checkpoint_workers, max_pending_checkpoints};

        // Register snapshots (see register_snapshot_entry), taken when every access kind is recorded and the backend
        // reports host register changes.
        static constexpr uint64_t register_snapshot_interval = 25000;
        static constexpr size_t register_snapshots_per_base = 64;
        static constexpr size_t max_pending_register_snapshots = 64;
        bool snapshots_registers_{};
        std::vector<register_snapshot_entry> register_snapshots_{};
        std::optional<uint64_t> snapshot_register_generation_{};
        bool host_changed_memory_{};
        std::shared_ptr<const std::vector<std::byte>> register_base_{};
        background_compressor register_compressor_{{}, 1, max_pending_register_snapshots};
        bool at_block_start_{};
        scoped_hook block_hook_{};
        std::vector<mapping_change> mapping_changes_{};
        void snapshot_registers(uint64_t position);
        // The access kinds of each page the open chunk touches, and those pages in first-touch order.
        flat_map chunk_pages_{};
        std::vector<uint64_t> chunk_page_list_{};

        // Event allocations released by encoded chunks, reused for later chunks.
        struct event_pool
        {
            std::mutex mutex{};
            std::vector<std::vector<access_event>> free{};
        };

        std::shared_ptr<event_pool> event_pool_{std::make_shared<event_pool>()};
        static constexpr uint64_t no_recent_page = UINT64_MAX;
        // Per access kind, the last single page entered into chunk_pages_, so repeated accesses skip the map.
        std::array<uint64_t, 16> recent_page_of_kind_{};
        // With execute events recorded, the address of the instruction running now, which guest accesses share.
        bool tracks_instructions_{};
        uint64_t instruction_ip_{};

        // Executed instruction bytes by address, so most execute events skip reading guest memory. Only kept while
        // every way code can change is observed: guest and host writes are recorded and mapping changes reported.
        struct cached_instruction
        {
            uint64_t size{};
            std::array<uint8_t, inline_data_limit> bytes{};
            // The instruction's id in code_.
            uint64_t code_id{};
        };

        // The code id of each execute event in the open chunk, in order.
        std::vector<uint64_t> chunk_code_ids_{};

        // Host window events, when the emulator has a recordable UI backend.
        recordable_ui_backend* ui_{};
        std::vector<ui_input_entry> ui_inputs_{};

        syscall_table syscalls_{};
        // The syscall whose handler is running: its step and the event count when the handler started.
        std::optional<syscall_entry> open_syscall_{};
        syscall_callback syscall_enter_{};
        syscall_callback syscall_exit_{};
        void close_syscall(uint32_t id);

        std::vector<module_entry> modules_{};
        // Index in modules_ of each loaded module by image base.
        std::unordered_map<uint64_t, size_t> loaded_modules_{};
        module_callback module_load_{};
        module_callback module_unload_{};
        void add_module(const mapped_module& mod);

        thread_table threads_{};
        std::optional<uint32_t> running_thread_{};
        void note_thread(const access_event& event);

        bool caches_instructions_{};
        // Index in cached_instructions_ by address; a forgotten instruction keeps its entry with size 0.
        flat_map instruction_cache_{};
        std::vector<cached_instruction> cached_instructions_{};
        // Index in cached_pages_ by page number: the cached instruction addresses in each page.
        flat_map cached_instructions_by_page_{};
        std::vector<std::vector<uint64_t>> cached_pages_{};
        void forget_instructions(uint64_t address, uint64_t size);
        // Entry k: the state of the latest checkpoint whose index is a multiple of checkpoints_per_level^k.
        std::vector<std::shared_ptr<const std::vector<std::byte>>> base_states_{};

        // Allocations of released checkpoint states, reused for later ones: a fresh allocation of a whole state costs
        // a page fault per page while serializing.
        struct state_pool
        {
            std::mutex mutex{};
            std::vector<std::vector<std::byte>> free{};
        };

        std::shared_ptr<state_pool> state_pool_{std::make_shared<state_pool>()};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
        instruction_callback instruction_callback_{};
        scoped_hook host_write_hook_{};
        bool finished_{};

        void append_event(access_kind kind, uint64_t address, size_t size);
        void append_data_event(access_kind kind, uint64_t address, std::span<const std::byte> data);
        void push_event(const access_event& event);
        void flush_chunk();
        void close_bulk_block();
        void write_compressed(bool wait);
        void write_checkpoint(uint64_t step);
        uint64_t append_to_file(std::span<const std::byte> bytes);
    };

    // Checks every event a replay produces against the recording and stops the emulator at the first difference.
    //
    // Syscalls and host writes are the environment's input to the guest (statuses, network data, file contents). When
    // the trace records syscalls, each one is checked as a unit: its id, its events (host writes), and the result it
    // leaves in RAX. Unless `strict`, a syscall whose live events or result differ (a live network answer, a file that is gone)
    // has its live writes undone and the recorded writes and result applied, so the guest sees what it saw while
    // recording; emulator state outside guest memory and registers keeps the live outcome. A host write outside a
    // syscall (or in a trace without syscalls) that matches its recorded event in position, address, and size but
    // carries other bytes takes the recorded bytes. substituted_inputs() counts both. Strict replays report them as
    // divergences instead, which also exposes emulator bugs such as uninitialized host bytes copied into the guest.
    class replay_verifier
    {
      public:
        replay_verifier(windows_emulator& emu, trace& recorded, uint64_t from_step, bool strict = false);
        replay_verifier(const replay_verifier&) = delete;
        replay_verifier& operator=(const replay_verifier&) = delete;
        void finish();

        uint64_t verified_events() const
        {
            return verified_events_;
        }

        // The number of the next recorded event the replay should produce.
        uint64_t next_event_number() const
        {
            return first_number_ + verified_events_;
        }

        uint64_t substituted_inputs() const
        {
            return substituted_inputs_;
        }

        // Whether the replay differed from the recording; finish() then throws.
        bool diverged() const
        {
            return error_.has_value();
        }

        // Whether `observe_writes` sees every change to guest memory: the trace records guest and host writes.
        bool observes_all_writes() const
        {
            constexpr auto writes = static_cast<uint64_t>(access_kind::write) | static_cast<uint64_t>(access_kind::host_write);
            return (access_mask_ & writes) == writes;
        }

        // Called with the range of every replayed guest or host write (and so of every substitution).
        void observe_writes(std::function<void(uint64_t address, size_t size)> observer)
        {
            write_observer_ = std::move(observer);
        }

      private:
        windows_emulator& emu_;
        trace& trace_;
        uint64_t first_number_{};
        event_reader reader_;
        uint64_t access_mask_{};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
        instruction_callback instruction_callback_{};
        // The address of the instruction the replay runs now, which guest accesses share.
        uint64_t instruction_ip_{};

        // Executed instruction bytes by address, so most executes skip reading guest memory. An entry holds while no
        // write touched its page (page_epochs_) and no mapping changed (layout_epoch_, advanced as the replay passes the
        // trace's recorded mapping changes); traces without recorded mapping changes read every time.
        struct cached_code
        {
            uint64_t size{};
            std::array<uint8_t, inline_data_limit> bytes{};
            uint64_t page_epoch{};
            uint64_t layout_epoch{};
        };

        bool caches_code_{};
        flat_map code_index_{};
        std::vector<cached_code> code_cache_{};
        flat_map page_epochs_{};
        uint64_t write_epoch_{};
        uint64_t layout_epoch_{};
        std::span<const mapping_change> pending_mapping_changes_{};
        std::array<uint8_t, inline_data_limit> instruction_bytes(uint64_t address, size_t size);
        uint64_t page_epoch(uint64_t address, size_t size) const;
        void note_write(uint64_t address, uint64_t size);

        scoped_hook host_write_hook_{};
        std::optional<std::string> error_{};
        uint64_t verified_events_{};
        bool strict_{};
        // Set while writing recorded bytes over a host write, whose own notification is not an event.
        bool substituting_{};
        uint64_t substituted_inputs_{};

        struct live_event
        {
            access_event event{};
            // For a host write, the bytes it replaced; empty when they could not be read.
            std::vector<std::byte> previous{};
            std::vector<std::byte> data{};
        };

        // The recorded syscalls from the replay's start and the next one the replay should dispatch.
        std::span<const syscall_entry> syscalls_{};
        size_t next_syscall_{};
        // While a syscall's handler runs: its events, checked when it returns.
        bool in_syscall_{};
        std::function<void(uint64_t, size_t)> write_observer_{};
        std::vector<live_event> syscall_events_{};
        std::vector<std::byte> previous_bytes_{};
        scoped_hook host_write_before_hook_{};
        syscall_callback syscall_enter_{};
        syscall_callback syscall_exit_{};

        void verify(access_kind kind, uint64_t address, size_t size, std::span<const std::byte> data = {});
        bool matches(const access_event& expected, const access_event& observed, std::span<const std::byte> data, bool compare_data = true);
        void enter_syscall(uint32_t id);
        void exit_syscall();
        void diverge(const std::string& message);
        std::string syscall_description(const syscall_entry& entry) const;
    };

    class replay_selfmod_scanner
    {
      public:
        replay_selfmod_scanner(windows_emulator& emu, trace& recorded_writes, uint64_t capture_address = 0, size_t capture_size = 0,
                               size_t capture_wave = 1);
        ~replay_selfmod_scanner();
        void finish();

        const std::vector<self_modifying_hit>& hits() const
        {
            return hits_;
        }

        const std::vector<uint8_t>& captured_memory() const
        {
            return captured_memory_;
        }

        uint64_t missing_capture_pages() const
        {
            return missing_capture_pages_;
        }

        const std::optional<self_modifying_hit>& first_hit() const
        {
            return first_hit_;
        }

        uint64_t verified_writes() const
        {
            return verified_writes_;
        }

      private:
        windows_emulator& emu_;
        trace& recorded_writes_;
        event_reader expected_writes_;

        struct written_page
        {
            std::array<uint64_t, 64> bytes{};
            uint64_t first_number{};
        };

        std::unordered_map<uint64_t, written_page> writers_{};
        std::unordered_map<uint64_t, uint64_t> page_latest_write_{};
        scoped_hook write_hook_{};
        scoped_hook execute_hook_{};
        std::optional<self_modifying_hit> first_hit_{};
        std::vector<self_modifying_hit> hits_{};
        std::unordered_map<uint64_t, uint64_t> reported_page_writes_{};
        std::optional<std::string> error_{};
        uint64_t verified_writes_{};
        uint64_t last_write_number_{};
        uint64_t capture_address_{};
        size_t capture_size_{};
        size_t capture_wave_{1};
        std::vector<uint8_t> captured_memory_{};
        uint64_t missing_capture_pages_{};
    };
}
