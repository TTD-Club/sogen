#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <windows_emulator.hpp>
#include <emulator/scoped_hook.hpp>
#include <utils/compression.hpp>

#include "ttd_chunk.hpp"
#include "ttd_compressor.hpp"
#include "ttd_format.hpp"
#include "ttd_ui.hpp"

namespace sogen::ttd
{
    using manifest_entries = std::vector<std::pair<std::string, std::string>>;

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

    struct checkpoint_state
    {
        uint64_t step{};
        std::vector<std::byte> state{};
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
        // Each pending checkpoint holds a full emulator state, so at most one waits while another compresses.
        static constexpr size_t max_pending_checkpoints = 1;

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
        background_compressor checkpoint_compressor_{{}, 1, max_pending_checkpoints};
        std::unordered_map<uint64_t, uint32_t> chunk_pages_{};
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
        };

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
        std::unordered_map<uint64_t, cached_instruction> instruction_cache_{};
        std::unordered_map<uint64_t, std::vector<uint64_t>> cached_instructions_by_page_{};
        void forget_instructions(uint64_t address, uint64_t size);
        // Entry k: the state of the latest checkpoint whose index is a multiple of checkpoints_per_level^k.
        std::vector<std::shared_ptr<const std::vector<std::byte>>> base_states_{};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
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

        // Thread switches and names; empty for traces recorded before threads were recorded.
        const thread_table& threads() const
        {
            return threads_;
        }

        // The thread running instruction `step`, or nothing before the first switch.
        std::optional<uint32_t> thread_at(uint64_t step) const;

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

        checkpoint_state checkpoint_for_step(uint64_t step);
        std::vector<access_event> accesses(uint64_t address, uint64_t size, uint64_t first_step = 0, uint64_t last_step = UINT64_MAX,
                                           uint64_t kind_mask = all_access_kinds);
        std::optional<access_event> next_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask = all_access_kinds);
        std::optional<access_event> previous_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask = all_access_kinds);
        std::vector<self_modifying_hit> self_modifying_code();
        access_event event_at(uint64_t number);
        size_t read_events(uint64_t first_number, std::span<access_event> output);
        uint64_t first_event_after(uint64_t step);
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

        std::vector<chunk_entry> chunks_{};
        std::vector<code_entry> code_{};
        std::vector<page_block> page_blocks_{};
        std::vector<bulk_entry> bulk_table_{};
        std::vector<cached_bulk> bulk_cache_{};
        std::vector<cached_chunk> chunk_cache_{};
        std::optional<std::pair<uint64_t, std::vector<std::byte>>> state_cache_{};

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
        // Blocks first to end - 1 (at most cached_bulk_blocks), decoding the uncached ones in parallel.
        std::vector<bulk_block> bulk_range(uint64_t first, uint64_t end);
        void remember_bulk(uint64_t index, bulk_block block);
        uint32_t chunk_of(uint64_t number) const;
        std::vector<std::byte> checkpoint_state_at(uint64_t index);
        std::vector<number_range> candidates(uint64_t first_page, uint64_t last_page, uint64_t kind_mask, uint64_t first_number,
                                             uint64_t end_number);
        std::vector<number_range> chunked_candidates(uint64_t first_page, uint64_t last_page, uint64_t kind_mask);
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

      private:
        windows_emulator& emu_;
        trace& trace_;
        uint64_t first_number_{};
        event_reader reader_;
        uint64_t access_mask_{};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
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
