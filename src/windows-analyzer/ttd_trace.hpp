#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <vector>

#include <windows_emulator.hpp>
#include <emulator/scoped_hook.hpp>

namespace sogen::ttd
{
    // Version 4 adds the instruction bytes observed immediately before execution.
    enum class access_kind : uint64_t
    {
        read = 1,
        write = 2,
        execute = 4
    };

    struct header
    {
        char magic[8]{'S', 'O', 'G', 'T', 'T', 'D', '4', '\0'};
        uint64_t snapshot_size{};
        uint64_t instruction_count{};
        uint64_t write_count{};
        uint64_t checkpoint_count{};
        uint64_t checkpoint_table_offset{};
        uint64_t index_offset{};
        uint64_t index_count{};
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

    struct write_event
    {
        uint64_t step{}; // 1-based instruction position; state after this instruction
        uint64_t ip{};
        uint64_t address{};
        uint64_t size{};
    };

    struct access_event
    {
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

    static_assert(sizeof(header) == 64);
    static_assert(sizeof(checkpoint_entry) == 24);
    static_assert(sizeof(write_event) == 32);
    static_assert(sizeof(access_event) == 56);
    static_assert(sizeof(index_entry) == 24);

    class recorder
    {
      public:
        recorder(windows_emulator& emu, const std::filesystem::path& path, uint64_t access_mask = 7);
        ~recorder();
        recorder(const recorder&) = delete;
        recorder& operator=(const recorder&) = delete;
        void checkpoint();
        void finish();

      private:
        windows_emulator& emu_;
        std::fstream file_;
        header header_{};
        std::vector<checkpoint_state> checkpoints_{};
        scoped_hook write_hook_{};
        scoped_hook read_hook_{};
        scoped_hook execute_hook_{};
        void append_event(access_kind kind, uint64_t address, size_t size);
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
                                           uint64_t kind_mask = 7);
        std::optional<access_event> next_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask = 7);
        std::optional<access_event> previous_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask = 7);
        std::vector<self_modifying_hit> self_modifying_code();
        access_event event_at(uint64_t number);

      private:
        std::ifstream file_;
        header header_{};
        uint64_t header_size_{sizeof(header)};
        std::vector<std::byte> snapshot_{};
        std::vector<checkpoint_entry> checkpoints_{};
        std::vector<index_entry> page_index_{};
        bool legacy_{};
        bool v3_{};
        uint64_t event_size_{};
    };
}
