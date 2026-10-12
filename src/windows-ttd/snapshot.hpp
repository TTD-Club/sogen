#pragma once

#include <windows_emulator.hpp>

#include "snapshot_format.hpp"

namespace sogen
{

    namespace snapshot
    {
        std::vector<std::byte> create_emulator_snapshot(const windows_emulator& win_emu);
        // `expected_size` (e.g. the previous state's size) avoids regrowing the buffer while serializing; `storage` is an
        // allocation to reuse.
        std::vector<std::byte> create_emulator_state(const windows_emulator& win_emu, size_t expected_size = 0,
                                                     std::vector<std::byte> storage = {});
        void load_emulator_state(windows_emulator& win_emu, std::span<const std::byte> state);
        std::filesystem::path write_emulator_snapshot(const windows_emulator& win_emu, bool log = true);

        void load_emulator_snapshot(windows_emulator& win_emu, std::span<const std::byte> snapshot);
        void load_emulator_snapshot(windows_emulator& win_emu, const std::filesystem::path& snapshot_file);
    }

} // namespace sogen
