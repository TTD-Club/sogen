#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

#include <fstream>
#include <random>

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
        constexpr uint32_t information_size = sizeof(FILE_NETWORK_OPEN_INFORMATION);

        class FileNetworkOpenInformationTest : public testing::Test
        {
          protected:
            void SetUp() override
            {
                ASSERT_TRUE(std::filesystem::create_directory(this->directory));
                std::ofstream{this->directory / "data.bin", std::ios::binary} << std::string(5000, 'x');

                this->emu.file_sys.map(windows_path{'x', {}}, this->directory);
                this->storage = this->emu.memory.allocate_memory(0x1000, memory_permission::read_write);
            }

            void TearDown() override
            {
                std::error_code error{};
                std::filesystem::remove_all(this->directory, error);
            }

            handle open_file()
            {
                const auto path = windows_path{'x', {u"data.bin"}};
                file f{};
                f.handle = guest_file{this->emu.file_sys, path, u"rb", this->emu.file_sys.open(path, u"rb").file};
                EXPECT_TRUE(f.handle);
                return this->emu.process.files.store(std::move(f));
            }

            handle open_directory()
            {
                file f{};
                f.handle = guest_file{this->emu.file_sys, windows_path{'x', {}}};
                return this->emu.process.files.store(std::move(f));
            }

            emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> status_block()
            {
                return {this->emu.memory, this->storage};
            }

            uint64_t buffer() const
            {
                return this->storage + 0x100;
            }

            NTSTATUS query(const handle file_handle, const uint32_t length = information_size)
            {
                const syscall_context context{
                    .win_emu = this->emu, .emu = this->emu.vcpu(0).cpu, .vcpu = this->emu.vcpu(0), .proc = this->emu.process};
                return syscalls::handle_NtQueryInformationFile(context, file_handle, this->status_block(), this->buffer(), length,
                                                               FileNetworkOpenInformation);
            }

            FILE_NETWORK_OPEN_INFORMATION information() const
            {
                return this->emu.memory.read_memory<FILE_NETWORK_OPEN_INFORMATION>(this->buffer());
            }

            std::filesystem::path directory =
                std::filesystem::temp_directory_path() / ("sogen-file-network-open-test-" + std::to_string(std::random_device{}()));
            windows_emulator emu = create_empty_emulator();
            uint64_t storage{};
        };
    }

    TEST_F(FileNetworkOpenInformationTest, ReportsFileSizesAndAttributes)
    {
        ASSERT_EQ(STATUS_SUCCESS, this->query(this->open_file()));
        EXPECT_EQ(information_size, this->status_block().read().Information);

        const auto info = this->information();
        EXPECT_EQ(5000, info.EndOfFile.QuadPart);
        EXPECT_GE(info.AllocationSize.QuadPart, info.EndOfFile.QuadPart);
        EXPECT_NE(0u, info.FileAttributes);
        EXPECT_EQ(0u, info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        EXPECT_NE(0, info.LastWriteTime.QuadPart);
    }

    TEST_F(FileNetworkOpenInformationTest, ReportsDirectoriesWithoutSize)
    {
        ASSERT_EQ(STATUS_SUCCESS, this->query(this->open_directory()));

        const auto info = this->information();
        EXPECT_EQ(0, info.EndOfFile.QuadPart);
        EXPECT_EQ(0, info.AllocationSize.QuadPart);
        EXPECT_EQ(static_cast<ULONG>(FILE_ATTRIBUTE_DIRECTORY), info.FileAttributes);
    }

    TEST_F(FileNetworkOpenInformationTest, RejectsShortBuffers)
    {
        EXPECT_EQ(STATUS_INFO_LENGTH_MISMATCH, this->query(this->open_file(), information_size - 1));
    }
}
