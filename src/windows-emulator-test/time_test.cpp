#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQuerySystemInformation(const syscall_context& c, uint32_t info_class, uint64_t system_information,
                                             uint32_t system_information_length, emulator_object<uint32_t> return_length);
}

namespace sogen::test
{
    TEST(TimeTest, LeapSecondQueryReportsUnadjustedClockWithExactBufferSize)
    {
        emulator_interfaces interfaces{};
        interfaces.ui = std::make_unique<null_ui_backend>();
        interfaces.audio = std::make_unique<null_audio_backend>();
        interfaces.console = std::make_unique<null_console_backend>();
        windows_emulator emu(create_x86_64_emulator_from_environment(),
                             emulator_settings{.disable_logging = true, .emulation_root = get_emulator_root(), .load_registry = false},
                             emulator_callbacks{}, std::move(interfaces));
        const auto storage = emu.memory.allocate_memory(0x1000, memory_permission::read_write);
        const syscall_context context{.win_emu = emu, .emu = emu.vcpu(0).cpu, .vcpu = emu.vcpu(0), .proc = emu.process};
        for (const auto size : {0u, 4u, 8u, 16u})
        {
            emulator_object<uint64_t>{emu.memory, storage + 0x100}.write(0x1122334455667788);
            EXPECT_EQ(size == 8 ? STATUS_SUCCESS : STATUS_INFO_LENGTH_MISMATCH,
                      syscalls::handle_NtQuerySystemInformation(context, SystemLeapSecondInformation, storage + 0x100, size,
                                                                {emu.memory, storage}));
            EXPECT_EQ(8, (emulator_object<uint32_t>{emu.memory, storage}.read()));
            EXPECT_EQ(size == 8 ? 0 : 0x1122334455667788, (emulator_object<uint64_t>{emu.memory, storage + 0x100}.read()));
        }
    }

    TEST(TimeTest, TimeOfDayBootTimeMatchesTheInterruptTime)
    {
        auto emu = create_empty_emulator();
        const auto storage = emu.memory.allocate_memory(0x1000, memory_permission::read_write);
        const syscall_context context{.win_emu = emu, .emu = emu.vcpu(0).cpu, .vcpu = emu.vcpu(0), .proc = emu.process};

        ASSERT_EQ(STATUS_SUCCESS, syscalls::handle_NtQuerySystemInformation(context, SystemTimeOfDayInformation, storage + 0x100,
                                                                            sizeof(SYSTEM_TIMEOFDAY_INFORMATION64), {emu.memory, storage}));
        const auto info = emu.memory.read_memory<SYSTEM_TIMEOFDAY_INFORMATION64>(storage + 0x100);

        const auto current_time = utils::convert_to_ksystem_time(emu.clock().system_now());
        const auto expected_current_time = (static_cast<int64_t>(current_time.High1Time) << 32) | current_time.LowPart;
        const auto interrupt_time = std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, 10'000'000>>>(
                                        emu.clock().steady_now().time_since_epoch())
                                        .count();

        EXPECT_EQ(expected_current_time, info.CurrentTime.QuadPart);
        EXPECT_EQ(interrupt_time, info.CurrentTime.QuadPart - info.BootTime.QuadPart);
        EXPECT_NE(0, info.BootTime.QuadPart);
    }

    TEST(TimeTest, SystemTimeIsAccurate)
    {
        std::string output_buffer{};

        emulator_callbacks callbacks{};
        callbacks.on_stdout = [&output_buffer](const std::string_view data) {
            output_buffer.append(data); //
        };

        const emulator_settings settings{
            .use_relative_time = false,
        };

        auto emu = create_sample_emulator(settings, {.print_time = true}, std::move(callbacks));
        emu.start();

        constexpr auto prefix = "Time: "sv;

        ASSERT_TERMINATED_SUCCESSFULLY(emu);
        ASSERT_TRUE(output_buffer.starts_with(prefix));

        output_buffer = output_buffer.substr(prefix.size());
        while (!output_buffer.empty() && (output_buffer.back() == '\n' || output_buffer.back() == '\r'))
        {
            output_buffer.pop_back();
        }

        const auto time = strtoll(output_buffer.c_str(), nullptr, 10);

        using time_point = std::chrono::system_clock::time_point;

        const time_point::duration time_duration(time);
        const time_point tp(time_duration);

        const auto now = std::chrono::system_clock::now();
        const auto diff = now - tp;

        ASSERT_LE(diff, std::chrono::hours(1));
    }
} // namespace sogen::test
