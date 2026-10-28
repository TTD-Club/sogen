#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>
#include <gtest/gtest.h>

namespace sogen::syscalls
{
    NTSTATUS handle_NtProtectVirtualMemory(const syscall_context& c, handle process_handle, emulator_object<uint64_t> base_address,
                                           emulator_object<uint64_t> bytes_to_protect, uint32_t protection,
                                           emulator_object<uint32_t> old_protection);
}

namespace sogen::test
{
    namespace
    {
        constexpr uint32_t unwritten_protection = 0xAAAAAAAA;

        struct protect_result
        {
            NTSTATUS status{};
            uint64_t base{};
            uint64_t size{};
            uint32_t old_protection{};
        };

        class ProtectMemoryTest : public testing::Test
        {
          protected:
            void SetUp() override
            {
                emulator_interfaces interfaces{};
                interfaces.ui = std::make_unique<null_ui_backend>();
                interfaces.audio = std::make_unique<null_audio_backend>();
                interfaces.console = std::make_unique<null_console_backend>();
                this->emu = std::make_unique<windows_emulator>(
                    create_x86_64_emulator_from_environment(),
                    emulator_settings{.disable_logging = true, .emulation_root = get_emulator_root(), .load_registry = false},
                    emulator_callbacks{}, std::move(interfaces));
                this->storage = this->emu->memory.allocate_memory(0x10000, memory_permission::read_write);
            }

            protect_result protect(const uint64_t address, const uint64_t size)
            {
                const emulator_object<uint64_t> base{this->emu->memory, this->storage};
                const emulator_object<uint64_t> bytes{this->emu->memory, this->storage + 8};
                const emulator_object<uint32_t> old{this->emu->memory, this->storage + 16};
                base.write(address);
                bytes.write(size);
                old.write(unwritten_protection);
                const syscall_context context{
                    .win_emu = *this->emu, .emu = this->emu->vcpu(0).cpu, .vcpu = this->emu->vcpu(0), .proc = this->emu->process};
                const auto status = syscalls::handle_NtProtectVirtualMemory(context, CURRENT_PROCESS, base, bytes, PAGE_READONLY, old);
                return {.status = status, .base = base.read(), .size = bytes.read(), .old_protection = old.read()};
            }

            std::unique_ptr<windows_emulator> emu;
            uint64_t storage{};
        };
    }

    TEST_F(ProtectMemoryTest, MatchesNativeStatuses)
    {
        auto& memory = this->emu->memory;
        const auto reserved = memory.allocate_memory(0x10000, memory_permission::read_write, true);
        ASSERT_NE(reserved, 0u);

        const auto free_address = memory.allocate_memory(0x10000, memory_permission::read_write, true);
        ASSERT_TRUE(memory.release_memory(free_address, 0));

        auto result = this->protect(free_address + 0x10, 0x10);
        EXPECT_EQ(result.status, STATUS_CONFLICTING_ADDRESSES);
        EXPECT_EQ(result.base, free_address + 0x10);
        EXPECT_EQ(result.size, 0x10u);
        EXPECT_EQ(result.old_protection, static_cast<uint32_t>(PAGE_NOACCESS));

        result = this->protect(reserved + 0x10, 0x10);
        EXPECT_EQ(result.status, STATUS_NOT_COMMITTED);
        EXPECT_EQ(result.base, reserved + 0x10);

        ASSERT_TRUE(memory.commit_memory(reserved, 0x1000, memory_permission::read_write));
        EXPECT_EQ(this->protect(reserved, 0x2000).status, STATUS_NOT_COMMITTED);
        EXPECT_EQ(this->protect(reserved + 0xF000, 0x2000).status, STATUS_CONFLICTING_ADDRESSES);
        EXPECT_EQ(memory.get_region_info(reserved).permissions, nt_memory_permission{memory_permission::read_write});

        result = this->protect(reserved + 0x10, 0x10);
        EXPECT_EQ(result.status, STATUS_SUCCESS);
        EXPECT_EQ(result.base, reserved);
        EXPECT_EQ(result.size, 0x1000u);
        EXPECT_EQ(result.old_protection, static_cast<uint32_t>(PAGE_READWRITE));
        EXPECT_EQ(memory.get_region_info(reserved).permissions, nt_memory_permission{memory_permission::read});
    }

    TEST_F(ProtectMemoryTest, RangeAcrossAllocationsConflicts)
    {
        auto& memory = this->emu->memory;
        const auto first = memory.allocate_memory(0x20000, memory_permission::read_write);
        ASSERT_NE(first, 0u);
        ASSERT_TRUE(memory.release_memory(first + 0x10000, 0x10000));
        ASSERT_TRUE(memory.allocate_memory(first + 0x10000, 0x10000, memory_permission::read_write));

        EXPECT_EQ(this->protect(first + 0xF000, 0x2000).status, STATUS_CONFLICTING_ADDRESSES);
        EXPECT_EQ(this->protect(first + 0xF000, 0x1000).status, STATUS_SUCCESS);
    }
}
