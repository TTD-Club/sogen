// Build: x86_64-w64-mingw32-gcc -O2 -nostdlib -Wl,-e,mainCRTStartup
// -o ttd-xor-string.exe test/ttd_xor_string_sample.c -lkernel32
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);

static const unsigned char encoded[] = {0x02, 0x15, 0x08, 0x05, 0x1e, 0x1f, 0x19, 0x15, 0x1e, 0x1f, 0x1e, 0x05,
                                        0x0e, 0x08, 0x1b, 0x14, 0x09, 0x13, 0x1f, 0x14, 0x0e, 0x05, 0x09, 0x1f,
                                        0x19, 0x08, 0x1f, 0x0e, 0x05, 0x6b, 0x68, 0x69, 0x6e, 0x6f, 0x5a};
volatile unsigned char decoded[sizeof(encoded)];

void mainCRTStartup(void)
{
    unsigned int check = 0;
    for (unsigned int i = 0; i < sizeof(encoded); ++i)
    {
        decoded[i] = encoded[i] ^ 0x5a;
        check += decoded[i];
    }
    for (unsigned int i = 0; i < sizeof(encoded); ++i)
    {
        decoded[i] = 0;
    }
    ExitProcess(check == 0 ? 1 : 0);
}
