#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include <windows_emulator.hpp>

namespace CLI
{
    class App;
}

namespace sogen::ttd
{
    struct cli_options
    {
        std::filesystem::path record{};
        std::filesystem::path replay{};
        bool scan_selfmod{false};
        bool verify_checkpoints{false};
        uint64_t seek{};
        uint64_t checkpoint_interval{500000};
        uint64_t max_instructions{};
        std::filesystem::path dump_image{};
        std::optional<uint64_t> dump_address{};
        std::optional<uint64_t> dump_size{};
        size_t dump_wave{1};
        bool no_checkpoints{false};
        bool no_read_trace{false};
        bool no_write_trace{false};
        bool no_execute_trace{false};
        std::optional<uint64_t> read{};
        std::filesystem::path strings{};
        std::filesystem::path buffers{};
        size_t min_string_length{6};

        std::filesystem::path query{};
        std::filesystem::path selfmod{};
        std::filesystem::path first_selfmod{};
        std::string access{"write"};
        std::optional<uint64_t> address{};
        std::optional<uint64_t> size{};
        uint64_t from{};
        uint64_t to{UINT64_MAX};
        bool next_access{};
        bool previous_access{};

        bool records() const
        {
            return !this->record.empty();
        }

        bool replays() const
        {
            return !this->replay.empty();
        }
    };

    struct analyzer_configuration
    {
        uint32_t vcpu_count{};
        bool gdb{};
        bool snapshot_input{};
        bool instruction_precision{};
        std::string_view backend_name{};
    };

    struct replay_result
    {
        std::optional<std::string> failure{};
        std::optional<NTSTATUS> exit_status{};
    };

    void add_options(CLI::App& app, cli_options& options);
    void validate(const cli_options& options, const analyzer_configuration& configuration);

    std::optional<int> run_offline(const cli_options& options);

    void prepare_replay(windows_emulator& win_emu, const cli_options& options);
    replay_result replay(windows_emulator& win_emu, const cli_options& options);
    void record(windows_emulator& win_emu, const cli_options& options, const std::function<bool()>& interrupted);
}
