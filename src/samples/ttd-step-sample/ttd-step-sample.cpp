// Fixture for test/ttd_step_test.py: one store and one load of a known global, one syscall that writes its output
// into a known global, code written at runtime and then executed, and a string that only exists transiently. The
// addresses are printed so the test can locate the matching trace events.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include <windows.h>

namespace
{
    volatile uint64_t ttd_value = 0x1111111111111111;
    volatile uint64_t ttd_copy = 0;
    MEMORY_BASIC_INFORMATION ttd_info{};

    // mov eax, 42; ret
    constexpr std::array<uint8_t, 6> generated_code{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};

    constexpr std::string_view transient_text = "SOGEN_TTD_TRANSIENT_STRING_FOR_RECOVERY";
    std::array<volatile char, transient_text.size() + 1> transient{};
}

int main()
{
    auto* code = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!code)
    {
        return 4;
    }

    printf("ttd-value %p\n", const_cast<uint64_t*>(&ttd_value));
    printf("ttd-info %p\n", &ttd_info);
    printf("ttd-code %p\n", code);
    fflush(stdout);

    ttd_value = 0x2222222222222222;
    ttd_copy = ttd_value;
    if (VirtualQuery(&ttd_info, &ttd_info, sizeof(ttd_info)) != sizeof(ttd_info))
    {
        return 2;
    }

    memcpy(code, generated_code.data(), generated_code.size());
    if (reinterpret_cast<int (*)()>(code)() != 42)
    {
        return 3;
    }

    for (size_t i = 0; i < transient_text.size(); ++i)
    {
        transient[i] = transient_text[i];
    }
    transient[transient_text.size()] = 0;
    for (auto& character : transient)
    {
        character = 0;
    }

    return ttd_copy == 0x2222222222222222 ? 0 : 1;
}
