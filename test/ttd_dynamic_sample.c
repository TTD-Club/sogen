// Build: x86_64-w64-mingw32-gcc -O2 -nostdlib -Wl,-e,mainCRTStartup
// -o ttd-dynamic.exe test/ttd_dynamic_sample.c -lkernel32
__declspec(dllimport) void* __stdcall VirtualAlloc(void*, unsigned long long, unsigned long, unsigned long);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);

volatile unsigned char transient_ascii[64];
volatile unsigned short transient_utf16[64];
volatile unsigned long long result;

void mainCRTStartup(void)
{
    static const unsigned char message[] = "SOGEN_TRANSIENT_BUFFER";
    for (unsigned int i = 0; i < sizeof(message); ++i)
    {
        transient_ascii[i] = message[i];
    }
    for (unsigned int i = 0; i < sizeof(message); ++i)
    {
        transient_utf16[i] = message[i];
    }

    volatile unsigned char* code = (volatile unsigned char*)VirtualAlloc(0, 4096, 0x3000, 0x40);
    if (!code)
    {
        ExitProcess(2);
    }
    const unsigned char body[] = {0xb8, 42, 0, 0, 0, 0xc3};
    for (unsigned int i = 0; i < sizeof(body); ++i)
    {
        code[i] = body[i];
    }
    int (*function)(void) = (int (*)(void))code;
    int first = function();
    code[1] = 43;
    int second = function();
    result = ((unsigned long long)(unsigned int)first << 32) | (unsigned int)second;

    for (unsigned int i = 0; i < sizeof(message); ++i)
    {
        transient_ascii[i] = 0;
    }
    for (unsigned int i = 0; i < sizeof(message); ++i)
    {
        transient_utf16[i] = 0;
    }
    ExitProcess(first == 42 && second == 43 ? 0 : 3);
}
