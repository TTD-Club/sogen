#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace sogen::snapshot
{
    // The header of an emulator snapshot: the compressed emulator state follows it.
    struct snapshot_header
    {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        char magic[4] = {'S', 'N', 'A', 'P'};
        uint32_t version{1};
    };

    static_assert(sizeof(snapshot_header) == 8);

    // The compressed state after a valid header; throws for anything else.
    std::span<const std::byte> validate_header(std::span<const std::byte> snapshot);
    // The decompressed emulator state of a snapshot.
    std::vector<std::byte> get_emulator_state(std::span<const std::byte> snapshot);
}
