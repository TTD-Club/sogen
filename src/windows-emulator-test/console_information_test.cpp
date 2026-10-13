#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQueryInformationFile(const syscall_context& c, handle file_handle,
                                           emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block,
                                           uint64_t file_information, uint32_t length, uint32_t info_class);
}

namespace sogen::test
{
    namespace
    {
        struct query_result
        {
            NTSTATUS status{};
            uint64_t information{};
            uint32_t value{};
        };

        query_result query_console(windows_emulator& emu, const handle console, const uint32_t info_class)
        {
            const auto storage = emu.memory.allocate_memory(0x1000, memory_permission::read_write);
            const syscall_context context{.win_emu = emu, .emu = emu.emu(), .vcpu = emu.vcpu(0), .proc = emu.process};
            const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> status{emu.memory, storage};
            const auto information = storage + 0x100;
            const auto result = syscalls::handle_NtQueryInformationFile(context, console, status, information, 0x400, info_class);
            EXPECT_EQ(result, status.read().Status);
            return {.status = result, .information = status.read().Information, .value = emu.emu().read_memory<uint32_t>(information)};
        }
    }

    // As Windows 11 answers for console handles (\Device\ConDrv): a guest that asks for file information about its
    // console must not see an invalid handle, which runtimes (Python's stdio setup) take for a closed stream.
    TEST(ConsoleInformationTest, StandardHandlesAnswerAsConsoleDriverHandles)
    {
        auto emu = create_empty_emulator();
        for (const auto console : {STDOUT_HANDLE, STDIN_HANDLE})
        {
            for (const auto info_class : {FileAllInformation, FileBasicInformation, FileStandardInformation, FileNameInformation})
            {
                const auto result = query_console(emu, console, info_class);
                EXPECT_EQ(STATUS_INVALID_DEVICE_REQUEST, result.status) << info_class;
                EXPECT_EQ(0U, result.information) << info_class;
            }

            const auto access = query_console(emu, console, FileAccessInformation);
            EXPECT_EQ(STATUS_SUCCESS, access.status);
            EXPECT_EQ(sizeof(FILE_ACCESS_INFORMATION), access.information);
            EXPECT_EQ(0x12019FU, access.value);

            const auto mode = query_console(emu, console, FileModeInformation);
            EXPECT_EQ(STATUS_SUCCESS, mode.status);
            EXPECT_EQ(static_cast<uint32_t>(FILE_SYNCHRONOUS_IO_NONALERT), mode.value);

            EXPECT_EQ(STATUS_SUCCESS, query_console(emu, console, FilePositionInformation).status);
            EXPECT_EQ(STATUS_SUCCESS, query_console(emu, console, FileAlignmentInformation).status);
        }
    }
}
