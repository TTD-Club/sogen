#include "snapshot.hpp"

#include <utils/io.hpp>
#include <utils/compression.hpp>

namespace sogen
{

    namespace snapshot
    {
        namespace
        {
            std::vector<std::byte> get_compressed_emulator_state(const windows_emulator& win_emu)
            {
                return utils::compression::zstd::compress(create_emulator_state(win_emu));
            }

            std::string get_main_executable_name(const windows_emulator& win_emu)
            {
                const auto* exe = win_emu.mod_manager.executable;
                if (exe)
                {
                    return std::filesystem::path(exe->name).stem().string();
                }

                return "process";
            }
        }

        std::vector<std::byte> create_emulator_snapshot(const windows_emulator& win_emu)
        {
            const auto state = get_compressed_emulator_state(win_emu);

            snapshot_header header{};
            std::span header_span(reinterpret_cast<const std::byte*>(&header), sizeof(header));

            std::vector<std::byte> snapshot{};
            snapshot.reserve(header_span.size() + state.size());
            snapshot.assign(header_span.begin(), header_span.end());
            snapshot.insert(snapshot.end(), state.begin(), state.end());

            return snapshot;
        }

        std::filesystem::path write_emulator_snapshot(const windows_emulator& win_emu, const bool log)
        {
            std::filesystem::path snapshot_file = get_main_executable_name(win_emu) + "-" + std::to_string(time(nullptr)) + ".snap";

            if (log)
            {
                win_emu.log.log("Writing snapshot to %s...\n", snapshot_file.string().c_str());
            }

            const auto snapshot = create_emulator_snapshot(win_emu);
            if (!utils::io::write_file(snapshot_file, snapshot))
            {
                throw std::runtime_error("Failed to write snapshot!");
            }

            return snapshot_file;
        }

        std::vector<std::byte> create_emulator_state(const windows_emulator& win_emu, const size_t expected_size,
                                                     std::vector<std::byte> storage)
        {
            utils::buffer_serializer serializer{std::move(storage)};
            serializer.reserve(expected_size);
            win_emu.serialize(serializer);
            return serializer.move_buffer();
        }

        void load_emulator_state(windows_emulator& win_emu, const std::span<const std::byte> state)
        {
            utils::buffer_deserializer deserializer{state};
            win_emu.deserialize(deserializer);
        }

        void load_emulator_snapshot(windows_emulator& win_emu, const std::span<const std::byte> snapshot)
        {
            load_emulator_state(win_emu, get_emulator_state(snapshot));
        }

        void load_emulator_snapshot(windows_emulator& win_emu, const std::filesystem::path& snapshot_file)
        {
            std::vector<std::byte> data{};
            if (!utils::io::read_file(snapshot_file, &data))
            {
                throw std::runtime_error("Failed to read snapshot file: " + snapshot_file.string());
            }

            load_emulator_snapshot(win_emu, data);
        }
    }

} // namespace sogen
