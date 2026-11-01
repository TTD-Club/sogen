#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQuerySystemInformation(const syscall_context& c, uint32_t info_class, uint64_t system_information,
                                             uint32_t system_information_length, emulator_object<uint32_t> return_length);
    NTSTATUS handle_NtQueryInformationProcess(const syscall_context& c, handle process_handle, uint32_t info_class,
                                              uint64_t process_information, uint32_t process_information_length,
                                              emulator_object<uint32_t> return_length);
    NTSTATUS handle_NtOpenProcess(const syscall_context& c, emulator_object<handle> process_handle, ACCESS_MASK desired_access,
                                  emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                  emulator_object<CLIENT_ID64> client_id);
}

namespace sogen::test
{
    namespace
    {
        constexpr ACCESS_MASK process_query_limited_information = 0x1000;
        constexpr ACCESS_MASK process_vm_read = 0x0010;

        class child_process_manager final : public process_manager
        {
          public:
            bool exited{};

            process_create_result create_process(process_create_request) override
            {
                return {.error = process_error::unavailable};
            }

            process_error resume_process(managed_process) override
            {
                return process_error::unavailable;
            }

            process_error terminate_process(managed_process, uint64_t) override
            {
                return process_error::unavailable;
            }

            process_exit_status_result exit_status(managed_process) const override
            {
                if (this->exited)
                {
                    return {.status = process_exit{.code = 0}};
                }
                return {};
            }

            process_memory_result allocate_memory(managed_process, uint64_t, uint64_t, memory_permission, bool, bool) override
            {
                return {.error = process_error::unavailable};
            }

            process_error free_memory(managed_process, uint64_t, uint64_t, bool) override
            {
                return process_error::unavailable;
            }

            process_memory_result protect_memory(managed_process, uint64_t, uint64_t, memory_permission) override
            {
                return {.error = process_error::unavailable};
            }

            process_memory_read_result read_memory(managed_process, uint64_t, uint64_t) const override
            {
                return {.error = process_error::unavailable};
            }

            process_memory_result write_memory(managed_process, uint64_t, std::span<const uint8_t>) override
            {
                return {.error = process_error::unavailable};
            }
        };

        struct listed_process
        {
            uint64_t id{};
            uint64_t parent_id{};
            std::u16string name{};
            uint32_t thread_count{};
            uint32_t session_id{};
        };

        class SystemProcessListTest : public testing::Test
        {
          protected:
            void SetUp() override
            {
                this->emu.setup_process_if_necessary();
                this->buffer = this->emu.memory.allocate_memory(0x20000, memory_permission::read_write);
            }

            syscall_context context()
            {
                return {.win_emu = this->emu, .emu = this->emu.vcpu(0).cpu, .vcpu = this->emu.vcpu(0), .proc = this->emu.process};
            }

            std::u16string read_name(const UNICODE_STRING<EmulatorTraits<Emu64>>& name)
            {
                std::u16string result(name.Length / sizeof(char16_t), u'\0');
                this->emu.memory.read_memory(name.Buffer, result.data(), name.Length);
                return result;
            }

            std::vector<listed_process> query_full_list()
            {
                using proc_t = SYSTEM_PROCESS_INFORMATION<EmulatorTraits<Emu64>>;

                std::vector<listed_process> processes{};
                EXPECT_EQ(STATUS_SUCCESS,
                          syscalls::handle_NtQuerySystemInformation(this->context(), SystemProcessInformation, this->buffer + 0x100,
                                                                    0x10000, {this->emu.memory, this->buffer}));
                auto address = this->buffer + 0x100;
                for (;;)
                {
                    const auto info = this->emu.memory.read_memory<proc_t>(address);
                    processes.push_back({
                        .id = info.UniqueProcessId,
                        .parent_id = info.InheritedFromUniqueProcessId,
                        .name = this->read_name(info.ImageName),
                        .thread_count = info.NumberOfThreads,
                        .session_id = info.SessionId,
                    });
                    if (!info.NextEntryOffset)
                    {
                        break;
                    }
                    address += info.NextEntryOffset;
                }
                return processes;
            }

            std::vector<listed_process> query_basic_list()
            {
                using proc_t = SYSTEM_BASICPROCESS_INFORMATION<EmulatorTraits<Emu64>>;

                std::vector<listed_process> processes{};
                EXPECT_EQ(STATUS_SUCCESS,
                          syscalls::handle_NtQuerySystemInformation(this->context(), SystemBasicProcessInformation, this->buffer + 0x100,
                                                                    0x10000, {this->emu.memory, this->buffer}));
                auto address = this->buffer + 0x100;
                for (;;)
                {
                    const auto info = this->emu.memory.read_memory<proc_t>(address);
                    processes.push_back({
                        .id = info.UniqueProcessId,
                        .parent_id = info.InheritedFromUniqueProcessId,
                        .name = this->read_name(info.ImageName),
                    });
                    if (!info.NextEntryOffset)
                    {
                        break;
                    }
                    address += info.NextEntryOffset;
                }
                return processes;
            }

            NTSTATUS open(const uint64_t process_id, const ACCESS_MASK access, handle& result)
            {
                CLIENT_ID64 client_id{};
                client_id.UniqueProcess = process_id;
                this->emu.memory.write_memory(this->buffer + 0x40, client_id);
                const auto status = syscalls::handle_NtOpenProcess(this->context(), {this->emu.memory, this->buffer + 0x60}, access,
                                                                   {this->emu.memory, 0}, {this->emu.memory, this->buffer + 0x40});
                result = this->emu.memory.read_memory<handle>(this->buffer + 0x60);
                return status;
            }

            static const listed_process* find(const std::vector<listed_process>& processes, const std::u16string_view name)
            {
                const auto entry = std::ranges::find(processes, name, &listed_process::name);
                return entry == processes.end() ? nullptr : &*entry;
            }

            child_process_manager manager{};
            windows_emulator emu = create_sample_emulator(emulator_settings{.use_relative_time = true}, {}, {},
                                                          emulator_interfaces{.processes = &this->manager});
            uint64_t buffer{};
        };
    }

    TEST_F(SystemProcessListTest, ListsTheProcessesEveryWindowsInstallationRuns)
    {
        const auto processes = this->query_full_list();
        ASSERT_GE(processes.size(), 3u);

        EXPECT_EQ(0u, processes[0].id);
        EXPECT_TRUE(processes[0].name.empty());
        EXPECT_NE(0u, processes[0].thread_count);

        const auto* system = find(processes, u"System");
        ASSERT_NE(nullptr, system);
        EXPECT_EQ(4u, system->id);

        for (const auto* name :
             {u"smss.exe", u"csrss.exe", u"wininit.exe", u"services.exe", u"lsass.exe", u"winlogon.exe", u"explorer.exe"})
        {
            EXPECT_NE(nullptr, find(processes, name)) << u16_to_u8(name);
        }
    }

    TEST_F(SystemProcessListTest, TheGuestIsAChildOfExplorerInTheInteractiveSession)
    {
        const auto processes = this->query_full_list();
        const auto* explorer = find(processes, u"explorer.exe");
        ASSERT_NE(nullptr, explorer);

        const auto guest = std::ranges::find(processes, uint64_t{this->emu.process.process_id}, &listed_process::id);
        ASSERT_NE(processes.end(), guest);
        EXPECT_EQ(explorer->id, guest->parent_id);
        EXPECT_EQ(explorer->session_id, guest->session_id);
        EXPECT_NE(0u, guest->session_id);
    }

    TEST_F(SystemProcessListTest, BasicAndFullListsAgree)
    {
        const auto full = this->query_full_list();
        const auto basic = this->query_basic_list();
        ASSERT_EQ(full.size(), basic.size());
        for (size_t i = 0; i < full.size(); ++i)
        {
            EXPECT_EQ(full[i].id, basic[i].id);
            EXPECT_EQ(full[i].parent_id, basic[i].parent_id);
            EXPECT_EQ(full[i].name, basic[i].name);
        }
    }

    TEST_F(SystemProcessListTest, ProcessesOfOtherAccountsCannotBeOpened)
    {
        handle process{};
        EXPECT_EQ(STATUS_ACCESS_DENIED, this->open(4, process_query_limited_information, process));
        EXPECT_EQ(STATUS_INVALID_CID, this->open(0, process_query_limited_information, process));
    }

    TEST_F(SystemProcessListTest, TheUsersOwnProcessesOpenForQueries)
    {
        const auto* explorer = find(this->query_full_list(), u"explorer.exe");
        ASSERT_NE(nullptr, explorer);

        handle process{};
        EXPECT_EQ(STATUS_ACCESS_DENIED, this->open(explorer->id, process_vm_read, process));
        ASSERT_EQ(STATUS_SUCCESS, this->open(explorer->id, process_query_limited_information, process));

        ASSERT_EQ(STATUS_SUCCESS,
                  syscalls::handle_NtQueryInformationProcess(this->context(), process, ProcessImageFileNameWin32, this->buffer + 0x1000,
                                                             0x400, {this->emu.memory, this->buffer}));
        const auto path = this->read_name(this->emu.memory.read_memory<UNICODE_STRING<EmulatorTraits<Emu64>>>(this->buffer + 0x1000));
        EXPECT_EQ(u"C:\\Windows\\explorer.exe", path);
    }

    TEST_F(SystemProcessListTest, RunningChildrenAreListedUnderTheGuest)
    {
        constexpr uint32_t child_id = 0x5000;

        emulator_process child{};
        child.process = managed_process{.value = 1};
        child.id = child_id;
        child.image_name = u"child.exe";
        this->emu.process.processes.store(std::move(child));

        managed_process_thread thread{};
        thread.process = managed_process{.value = 1};
        thread.process_id = child_id;
        thread.thread_id = child_id + 4;
        this->emu.process.managed_threads.store(std::move(thread));

        const auto processes = this->query_full_list();
        const auto* listed = find(processes, u"child.exe");
        ASSERT_NE(nullptr, listed);
        EXPECT_EQ(child_id, listed->id);
        EXPECT_EQ(uint64_t{this->emu.process.process_id}, listed->parent_id);
        EXPECT_EQ(1u, listed->thread_count);

        this->manager.exited = true;
        EXPECT_EQ(nullptr, find(this->query_full_list(), u"child.exe"));
    }
}
