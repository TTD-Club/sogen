#pragma once

#include <windows_emulator.hpp>

namespace sogen
{

    namespace snapshot
    {
        // `expected_size` (e.g. the previous state's size) avoids regrowing the buffer while serializing; `storage` is an
        // allocation to reuse.
        std::vector<std::byte> create_emulator_state(const windows_emulator& win_emu, size_t expected_size = 0,
                                                     std::vector<std::byte> storage = {});
        // Also tells where in the state the memory manager's state begins.
        std::vector<std::byte> create_emulator_state(const windows_emulator& win_emu, size_t expected_size, std::vector<std::byte> storage,
                                                     size_t& memory_offset);
        void load_emulator_state(windows_emulator& win_emu, std::span<const std::byte> state);
    }

} // namespace sogen
