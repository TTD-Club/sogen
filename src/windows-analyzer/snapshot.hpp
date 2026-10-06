#pragma once

#include <windows_emulator.hpp>

namespace sogen
{

    namespace snapshot
    {
        std::vector<std::byte> create_emulator_snapshot(const windows_emulator& win_emu);
        std::vector<std::byte> get_emulator_state(std::span<const std::byte> snapshot);
        std::filesystem::path write_emulator_snapshot(const windows_emulator& win_emu, bool log = true);

        void load_emulator_snapshot(windows_emulator& win_emu, std::span<const std::byte> snapshot);
        void load_emulator_snapshot(windows_emulator& win_emu, const std::filesystem::path& snapshot_file);
    }

} // namespace sogen
