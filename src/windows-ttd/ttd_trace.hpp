#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <deque>
#include <filesystem>
#include <fstream>
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

    class replay_verifier
    {
      public:
        replay_verifier(windows_emulator& emu, trace& recorded, uint64_t from_step);
        replay_verifier(const replay_verifier&) = delete;
        replay_verifier& operator=(const replay_verifier&) = delete;
        void finish();

        uint64_t verified_events() const
        {
            return verified_events_;
        }

      private:
        windows_emulator& emu_;
        trace& trace_;
        event_reader reader_;
        uint64_t access_mask_{};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
        scoped_hook host_write_hook_{};
        std::optional<std::string> error_{};
        uint64_t verified_events_{};
        void verify(access_kind kind, uint64_t address, size_t size, std::span<const std::byte> data = {});
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
