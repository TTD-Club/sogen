// Deterministic PE workload for checkpoint seek and write-index validation.
// Build with x86_64-w64-mingw32-gcc -O2 -nostdlib -Wl,-e,mainCRTStartup
// -o ttd-large.exe test/ttd_large_sample.c -lkernel32
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);

volatile unsigned long long slots[256];
volatile unsigned long long result;

void mainCRTStartup(void)
{
    unsigned long long sum = 0;
    for (unsigned int i = 0; i < 200000; ++i)
    {
        const unsigned int slot = i & 255;
        const unsigned long long value = (unsigned long long)i * 17 + 3;
        slots[slot] = value;
        sum += value;
    }
    result = sum;
    ExitProcess(0);
}
