#pragma once

#include "ttd_trace.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sogen::ttd
{
    struct recovered_buffer
    {
        uint64_t address{};
        uint64_t size{};
        uint64_t first_step{};
        uint64_t last_step{};
        uint64_t writer_ip{};
        uint64_t writes{};
        std::string kind{};
        std::string preview{};
        std::vector<uint8_t> data{};
    };

    class buffer_scanner
    {
      public:
        buffer_scanner(windows_emulator& emu, trace& recorded_writes);
        ~buffer_scanner();
        buffer_scanner(const buffer_scanner&) = delete;
        buffer_scanner& operator=(const buffer_scanner&) = delete;

        void finish();
        void save(const std::filesystem::path& path) const;

        size_t count() const
        {
            return results_.size();
        }

        uint64_t verified_writes() const
        {
            return verified_writes_;
        }

        uint64_t skipped_bytes() const
        {
            return skipped_bytes_;
        }

      private:
        struct pending_write
        {
            uint64_t address{};
            size_t size{};
            uint64_t step{};
            uint64_t ip{};
        };

        struct region
        {
            uint64_t base{};
            std::vector<uint8_t> bytes{};
            std::vector<uint8_t> known{};
            std::vector<uint8_t> executed{};
            uint64_t first_step{};
            uint64_t last_step{};
            uint64_t writer_ip{};
            uint64_t writes{};
        };

        void flush_pending();
        void ingest(const pending_write& write, std::span<const uint8_t> bytes);
        void emit(region&& value);
        void evict_oldest();

        windows_emulator& emu_;
        trace& trace_;
        event_reader expected_writes_;
        std::map<uint64_t, region> active_{};
        std::vector<pending_write> pending_{};
        std::vector<recovered_buffer> results_{};
        std::optional<std::string> error_{};
        scoped_hook write_hook_{};
        scoped_hook execute_hook_{};
        uint64_t verified_writes_{};
        uint64_t skipped_bytes_{};
        size_t retained_bytes_{};
        bool finished_{};
    };
}
