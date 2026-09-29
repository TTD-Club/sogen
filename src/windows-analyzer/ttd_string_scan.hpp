#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <emulator/scoped_hook.hpp>
#include <windows_emulator.hpp>

namespace sogen::ttd
{
    struct recovered_string
    {
        uint64_t address{};
        uint64_t step{};
        std::string encoding{};
        std::string value{};
    };

    class string_scanner
    {
      public:
        explicit string_scanner(windows_emulator& emu, size_t minimum_length = 6);
        void scan_initial_memory();
        void finish();
        void save(const std::filesystem::path& path) const;
        size_t count() const;

      private:
        void scan_range(uint64_t address, uint64_t size, uint64_t step);
        void inspect(uint64_t address, const std::vector<uint8_t>& bytes, uint64_t step);
        void add(uint64_t address, uint64_t step, std::string encoding, std::string value);
        void flush_pending();

        windows_emulator& emu_;
        size_t minimum_length_{};
        std::vector<std::pair<uint64_t, uint64_t>> pending_{};
        std::map<uint64_t, std::vector<recovered_string>> strings_{};
        scoped_hook write_hook_{};
        scoped_hook execute_hook_{};
    };
}
