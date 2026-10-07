#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows_emulator.hpp>
#include <emulator/scoped_hook.hpp>

namespace sogen::ttd
{
    // Version 4 adds the instruction bytes observed immediately before execution; version 5 adds the recorded
    // access kinds to the header and host writes.
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

    struct header
    {
        char magic[8]{'S', 'O', 'G', 'T', 'T', 'D', '5', '\0'};
        uint64_t snapshot_size{};
        uint64_t instruction_count{};
        uint64_t event_count{};
        uint64_t checkpoint_count{};
        uint64_t checkpoint_table_offset{};
        uint64_t index_offset{};
        uint64_t index_count{};
        uint64_t access_mask{};
    };

    struct checkpoint_entry
    {
        uint64_t step{};
        uint64_t offset{};
        uint64_t size{};
    };

    struct checkpoint_state
    {
        uint64_t step{};
        std::vector<std::byte> snapshot{};
    };

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
        std::array<uint8_t, 16> instruction_bytes{};
    };

    struct index_entry
    {
        uint64_t page{};
        uint64_t event_number{};
        access_kind kind{};
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

    static_assert(sizeof(header) == 72);
    static_assert(sizeof(checkpoint_entry) == 24);
    static_assert(sizeof(access_event) == 56);
    static_assert(sizeof(index_entry) == 24);

    class recorder
    {
      public:
        recorder(windows_emulator& emu, const std::filesystem::path& path, uint64_t access_mask = all_access_kinds);
        ~recorder();
        recorder(const recorder&) = delete;
        recorder& operator=(const recorder&) = delete;
        void checkpoint();
        void finish();

      private:
        windows_emulator& emu_;
        std::filesystem::path path_;
        std::fstream file_;
        header header_{};
        std::filesystem::path checkpoint_path_;
        std::fstream checkpoint_file_;
        std::vector<checkpoint_entry> checkpoints_{};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
        scoped_hook host_write_hook_{};
        static constexpr size_t pending_event_limit = 16384;
        std::vector<access_event> pending_events_{};
        void append_event(access_kind kind, uint64_t address, size_t size);
        void flush_events();
        bool finished_{};
    };

    class trace
    {
      public:
        explicit trace(const std::filesystem::path& path);

        const header& metadata() const
        {
            return header_;
        }

        std::span<const checkpoint_entry> checkpoints() const
        {
            return checkpoints_;
        }

        bool has_instruction_bytes() const
        {
            return !legacy_ && !v3_;
        }

        const std::vector<std::byte>& snapshot() const
        {
            return snapshot_;
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
        std::optional<uint64_t> latest_write_to_byte(uint64_t page, uint64_t address, uint64_t first_number, uint64_t last_number);

      private:
        std::ifstream file_;
        header header_{};
        uint64_t header_size_{sizeof(header)};
        std::vector<std::byte> snapshot_{};
        std::vector<checkpoint_entry> checkpoints_{};
        bool legacy_{};
        bool v3_{};
        uint64_t event_size_{};
        std::optional<uint64_t> access_mask_{};

        index_entry index_at(uint64_t position);
        uint64_t index_lower_bound(uint64_t page, access_kind kind, uint64_t event_number);
        uint64_t first_event_at_or_after(uint64_t step);

        template <typename Callback>
        void for_each_index_group(uint64_t first_page, uint64_t last_page, uint64_t kind_mask, const Callback& callback);
    };

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
        void verify(access_kind kind, uint64_t address, size_t size);
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
