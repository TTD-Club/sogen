// Fixture for test/ttd_step_test.py: one store and one load of a known global, and one syscall that writes its output
// into a known global. The addresses are printed so the test can locate the matching trace events.

#include <cstdint>
#include <cstdio>

#include <windows.h>

namespace
{
    volatile uint64_t ttd_value = 0x1111111111111111;
    volatile uint64_t ttd_copy = 0;
    MEMORY_BASIC_INFORMATION ttd_info{};
}

int main()
{
    printf("ttd-value %p\n", const_cast<uint64_t*>(&ttd_value));
    printf("ttd-info %p\n", &ttd_info);
    fflush(stdout);
    ttd_value = 0x2222222222222222;
    ttd_copy = ttd_value;
    if (VirtualQuery(&ttd_info, &ttd_info, sizeof(ttd_info)) != sizeof(ttd_info))
    {
        return 2;
    }
    return ttd_copy == 0x2222222222222222 ? 0 : 1;
}
