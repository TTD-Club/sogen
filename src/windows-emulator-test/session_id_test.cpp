#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQueryInformationToken(const syscall_context& c, handle token_handle, TOKEN_INFORMATION_CLASS information_class,
                                            uint64_t information, ULONG information_length, emulator_object<ULONG> return_length);
}

namespace sogen::test
{
    TEST(SessionIdTest, ThePebReportsTheSessionOfTheToken)
    {
        auto emu = create_sample_emulator();
        emu.setup_process_if_necessary();
        const auto storage = emu.memory.allocate_memory(0x1000, memory_permission::read_write);
        const syscall_context context{.win_emu = emu, .emu = emu.vcpu(0).cpu, .vcpu = emu.vcpu(0), .proc = emu.process};

        ASSERT_EQ(STATUS_SUCCESS, syscalls::handle_NtQueryInformationToken(context, CURRENT_PROCESS_TOKEN, TokenSessionId, storage + 0x100,
                                                                           sizeof(ULONG), {emu.memory, storage}));
        const auto token_session = emu.memory.read_memory<ULONG>(storage + 0x100);

        EXPECT_NE(0u, token_session);
        EXPECT_EQ(token_session, emu.process.peb64.read().SessionId);
    }

}
