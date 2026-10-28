#include "emulator_state.hpp"

namespace sogen
{

    namespace snapshot
    {
        std::vector<std::byte> create_emulator_state(const windows_emulator& win_emu, const size_t expected_size,
                                                     std::vector<std::byte> storage)
        {
            utils::buffer_serializer serializer{std::move(storage)};
            serializer.reserve(expected_size);
            win_emu.serialize(serializer);
            return serializer.move_buffer();
        }

        std::vector<std::byte> create_emulator_state(const windows_emulator& win_emu, const size_t expected_size,
                                                     std::vector<std::byte> storage, size_t& memory_offset)
        {
            utils::buffer_serializer serializer{std::move(storage)};
            serializer.reserve(expected_size);
            win_emu.serialize(serializer, memory_offset);
            return serializer.move_buffer();
        }

        void load_emulator_state(windows_emulator& win_emu, const std::span<const std::byte> state)
        {
            utils::buffer_deserializer deserializer{state};
            win_emu.deserialize(deserializer);
        }
    }

} // namespace sogen
