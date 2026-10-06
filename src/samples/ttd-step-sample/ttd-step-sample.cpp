// Fixture for test/ttd_step_test.py: one store and one load of a known global, whose address is printed so the
// test can locate the matching trace events.

#include <cstdint>
#include <cstdio>

namespace
{
    volatile uint64_t ttd_value = 0x1111111111111111;
    volatile uint64_t ttd_copy = 0;
}

int main()
{
    printf("ttd-value %p\n", const_cast<uint64_t*>(&ttd_value));
    fflush(stdout);
    ttd_value = 0x2222222222222222;
    ttd_copy = ttd_value;
    return ttd_copy == 0x2222222222222222 ? 0 : 1;
}
