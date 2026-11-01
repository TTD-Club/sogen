#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQueryInformationProcess(const syscall_context& c, handle process_handle, uint32_t process_information_class,
                                              uint64_t process_information, uint32_t process_information_length,
                                              emulator_object<uint32_t> return_length);
    NTSTATUS handle_NtSetInformationProcess(const syscall_context& c, handle process_handle, uint32_t info_class,
                                            uint64_t process_information, uint32_t process_information_length);
}

namespace sogen::test
{
    namespace
    {
        class ProcessPagePriorityTest : public testing::Test
        {
          protected:
            void SetUp() override
            {
                this->storage = this->emu.memory.allocate_memory(0x1000, memory_permission::read_write);
            }

            syscall_context context()
            {
                return {.win_emu = this->emu, .emu = this->emu.vcpu(0).cpu, .vcpu = this->emu.vcpu(0), .proc = this->emu.process};
            }

            NTSTATUS set(const ULONG priority, const uint32_t length = sizeof(ULONG))
            {
                this->emu.memory.write_memory(this->storage, priority);
                return syscalls::handle_NtSetInformationProcess(this->context(), CURRENT_PROCESS, ProcessPagePriority, this->storage,
                                                                length);
            }

            ULONG query()
            {
                const auto status =
                    syscalls::handle_NtQueryInformationProcess(this->context(), CURRENT_PROCESS, ProcessPagePriority, this->storage + 0x100,
                                                               sizeof(ULONG), {this->emu.memory, this->storage + 0x200});
                EXPECT_EQ(STATUS_SUCCESS, status);
                return this->emu.memory.read_memory<ULONG>(this->storage + 0x100);
            }

            windows_emulator emu = create_empty_emulator();
            uint64_t storage{};
        };
    }

    TEST_F(ProcessPagePriorityTest, StartsAtNormalPriority)
    {
        EXPECT_EQ(static_cast<ULONG>(MEMORY_PRIORITY_NORMAL), this->query());
    }

    TEST_F(ProcessPagePriorityTest, ReportsTheStoredPriority)
    {
        ASSERT_EQ(STATUS_SUCCESS, this->set(2));
        EXPECT_EQ(2, this->query());
    }

    TEST_F(ProcessPagePriorityTest, RejectsPrioritiesAboveNormal)
    {
        EXPECT_EQ(STATUS_INVALID_PARAMETER, this->set(MEMORY_PRIORITY_NORMAL + 1));
        EXPECT_EQ(static_cast<ULONG>(MEMORY_PRIORITY_NORMAL), this->query());
    }

    TEST_F(ProcessPagePriorityTest, RejectsLengthsOtherThanAUlong)
    {
        EXPECT_EQ(STATUS_INFO_LENGTH_MISMATCH, this->set(2, sizeof(ULONG64)));
        EXPECT_EQ(static_cast<ULONG>(MEMORY_PRIORITY_NORMAL), this->query());
    }
}
