#include "snapshot_format.hpp"

#include <utils/compression.hpp>

#include <cstring>
#include <stdexcept>
#include <string>

namespace sogen::snapshot
{
    std::span<const std::byte> validate_header(const std::span<const std::byte> snapshot)
    {
        snapshot_header header{};
        constexpr snapshot_header default_header{};

        if (snapshot.size() < sizeof(header))
        {
            throw std::runtime_error("Snapshot is too small");
        }

        memcpy(&header, snapshot.data(), sizeof(header));

        if (memcmp(default_header.magic, header.magic, sizeof(header.magic)) != 0)
        {
            throw std::runtime_error("Invalid snapshot");
        }

        if (default_header.version != header.version)
        {
            throw std::runtime_error("Unsupported snapshot version: " + std::to_string(header.version) +
                                     "(needed: " + std::to_string(default_header.version) + ")");
        }

        return snapshot.subspan(sizeof(header));
    }

    std::vector<std::byte> get_emulator_state(const std::span<const std::byte> snapshot)
    {
        const auto data = validate_header(snapshot);
        return utils::compression::zstd::decompress(data);
    }
}
