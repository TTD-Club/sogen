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
    TEST(ProcessImageInformationTest, DescribesTheImageAsItLiesOnDisk)
    {
        auto emu = create_sample_emulator();
        emu.setup_process_if_necessary();
        const auto storage = emu.memory.allocate_memory(0x1000, memory_permission::read_write);
        const syscall_context context{.win_emu = emu, .emu = emu.vcpu(0).cpu, .vcpu = emu.vcpu(0), .proc = emu.process};

        using information_t = SECTION_IMAGE_INFORMATION<EmulatorTraits<Emu64>>;
        ASSERT_EQ(STATUS_SUCCESS,
                  syscalls::handle_NtQueryInformationProcess(context, CURRENT_PROCESS, ProcessImageInformation, storage + 0x100,
                                                             sizeof(information_t), {emu.memory, storage}));
        const auto information = emu.memory.read_memory<information_t>(storage + 0x100);

        const auto& executable = *emu.mod_manager.executable;
        const auto file_stat = emu.file_sys.stat(executable.module_path);
        ASSERT_TRUE(file_stat.has_value());

        EXPECT_EQ(executable.entry_point, information.TransferAddress);
        EXPECT_EQ(static_cast<ULONG>(file_stat->st_size), information.ImageFileSize);
        EXPECT_EQ(executable.size_of_stack_reserve, information.MaximumStackSize);
        EXPECT_EQ(executable.size_of_stack_commit, information.CommittedStackSize);
    }
}
