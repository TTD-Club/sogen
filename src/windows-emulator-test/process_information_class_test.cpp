#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQueryInformationProcess(const syscall_context& c, handle process_handle, uint32_t info_class,
                                              uint64_t process_information, uint32_t process_information_length,
                                              emulator_object<uint32_t> return_length);
}

namespace sogen::test
{
    namespace
    {
        class ProcessInformationClassTest : public testing::Test
        {
          protected:
            void SetUp() override
            {
                this->storage = this->emu.memory.allocate_memory(0x1000, memory_permission::read_write);
            }

            NTSTATUS query(const PROCESSINFOCLASS information_class, const uint32_t length)
            {
                this->emu.memory.set_memory(this->storage + 0x100, 0xCC, 0x100);
                const syscall_context context{
                    .win_emu = this->emu, .emu = this->emu.vcpu(0).cpu, .vcpu = this->emu.vcpu(0), .proc = this->emu.process};
                return syscalls::handle_NtQueryInformationProcess(context, CURRENT_PROCESS, information_class, this->storage + 0x100,
                                                                  length, {this->emu.memory, this->storage});
            }

            template <typename T>
            T result() const
            {
                return this->emu.memory.read_memory<T>(this->storage + 0x100);
            }

            windows_emulator emu = create_empty_emulator();
            uint64_t storage{};
        };
    }

    TEST_F(ProcessInformationClassTest, ReportsTheDefaultsOfAnUnremarkableProcess)
    {
        ASSERT_EQ(STATUS_SUCCESS, this->query(ProcessIoPriority, sizeof(ULONG)));
        EXPECT_EQ(2u, this->result<ULONG>());

        ASSERT_EQ(STATUS_SUCCESS, this->query(ProcessLUIDDeviceMapsEnabled, sizeof(ULONG)));
        EXPECT_EQ(1u, this->result<ULONG>());

        ASSERT_EQ(STATUS_SUCCESS, this->query(ProcessBreakOnTermination, sizeof(ULONG)));
        EXPECT_EQ(0u, this->result<ULONG>());

        ASSERT_EQ(STATUS_SUCCESS, this->query(ProcessProtectionInformation, sizeof(uint8_t)));
        EXPECT_EQ(0u, this->result<uint8_t>());
    }

    TEST_F(ProcessInformationClassTest, RequiresTheExactStructureSize)
    {
        EXPECT_EQ(STATUS_INFO_LENGTH_MISMATCH, this->query(ProcessIoCounters, 40));
        EXPECT_EQ(STATUS_INFO_LENGTH_MISMATCH, this->query(ProcessIoPriority, 8));
        EXPECT_EQ(STATUS_SUCCESS, this->query(ProcessIoCounters, 48));
    }

    TEST_F(ProcessInformationClassTest, RejectsClassesWindowsDoesNotAnswer)
    {
        for (const auto information_class : {ProcessBasePriority, ProcessAccessToken, ProcessTlsInformation, ProcessPriorityClassEx})
        {
            SCOPED_TRACE(static_cast<int>(information_class));
            EXPECT_EQ(STATUS_INVALID_INFO_CLASS, this->query(information_class, sizeof(ULONG)));
        }

        EXPECT_EQ(STATUS_NOT_IMPLEMENTED, this->query(ProcessLdtInformation, sizeof(ULONG)));
    }
}
