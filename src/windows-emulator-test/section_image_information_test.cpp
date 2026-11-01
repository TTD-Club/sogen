#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    NTSTATUS handle_NtQuerySection(const syscall_context& c, handle section_handle, SECTION_INFORMATION_CLASS section_information_class,
                                   uint64_t section_information, EmulatorTraits<Emu64>::SIZE_T section_information_length,
                                   emulator_object<EmulatorTraits<Emu64>::SIZE_T> result_length);
}

namespace sogen::test
{
    TEST(SectionImageInformationTest, DescribesTheImageFileLikeWindows)
    {
        auto emu = create_sample_emulator();
        const auto image_path = windows_path{"C:\\test-sample.exe"};
        const auto file_data = emu.file_sys.read_file(image_path);
        ASSERT_FALSE(file_data.empty());

        section image{};
        image.file_name = image_path.u16string();
        image.allocation_attributes = SEC_IMAGE;
        image.cache_image_info_from_filedata(file_data);
        const auto section_handle = emu.process.sections.store(std::move(image));

        const auto storage = emu.memory.allocate_memory(0x1000, memory_permission::read_write);
        const syscall_context context{.win_emu = emu, .emu = emu.vcpu(0).cpu, .vcpu = emu.vcpu(0), .proc = emu.process};

        using information_t = SECTION_IMAGE_INFORMATION<EmulatorTraits<Emu64>>;
        ASSERT_EQ(STATUS_SUCCESS,
                  syscalls::handle_NtQuerySection(context, section_handle, SECTION_INFORMATION_CLASS::SectionImageInformation,
                                                  storage + 0x100, sizeof(information_t), {emu.memory, storage}));
        const auto information = emu.memory.read_memory<information_t>(storage + 0x100);

        const auto dos_header = *reinterpret_cast<const PEDosHeader_t*>(file_data.data());
        const auto nt_headers = *reinterpret_cast<const PENTHeaders_t<uint64_t>*>(file_data.data() + dos_header.e_lfanew);

        EXPECT_EQ(file_data.size(), information.ImageFileSize);
        EXPECT_EQ(nt_headers.OptionalHeader.MajorOperatingSystemVersion, information.MajorOperatingSystemVersion);
        EXPECT_EQ(nt_headers.OptionalHeader.MinorOperatingSystemVersion, information.MinorOperatingSystemVersion);
        EXPECT_EQ(0, information.ImageMappedFlat);
    }
}
