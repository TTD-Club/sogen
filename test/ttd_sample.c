// Minimal PE for a manual end-to-end trace check; no C runtime is required.
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);

volatile unsigned long long ttd_words[2];

void mainCRTStartup(void)
{
    for (unsigned int i = 0; i < 3; ++i)
    {
        ttd_words[0] = (unsigned long long)i + 1;
    }
    ttd_words[1] = ttd_words[0] + 7;
    ExitProcess(0);
}
