// Fixture for test/ttd_step_test.py: one store and one load of a known global, one syscall that writes its output
// into a known global, code written at runtime and then executed, a ud2 that raises an exception, a string that
// only exists transiently, the attributes of an input file the tests create and delete (live host input), and a
// window that briefly waits for WM_APP (test/ttd_python_test.py injects one). The addresses are printed so the tests
// can locate the matching trace events.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include <windows.h>
#include <intrin.h>

namespace
{
    volatile uint64_t ttd_value = 0x1111111111111111;
    volatile uint64_t ttd_copy = 0;
    volatile uint64_t ttd_ui_value = 0;
    volatile DWORD ttd_input_attributes = 0;
    MEMORY_BASIC_INFORMATION ttd_info{};

    // mov eax, 42; ret
    constexpr std::array<uint8_t, 6> generated_code{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};

    constexpr std::string_view transient_text = "SOGEN_TTD_TRANSIENT_STRING_FOR_RECOVERY";
    std::array<volatile char, transient_text.size() + 1> transient{};

    volatile bool illegal_instruction_raised = false;

    // Skips the two-byte ud2. A vectored handler instead of __try/__except, which MinGW does not support.
    LONG WINAPI skip_illegal_instruction(EXCEPTION_POINTERS* exception)
    {
        if (exception->ExceptionRecord->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        illegal_instruction_raised = true;
#ifdef _WIN64
        exception->ContextRecord->Rip += 2;
#else
        exception->ContextRecord->Eip += 2;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Unicorn cannot decode ud2 and reports no instruction size for it.
    bool raises_illegal_instruction(void* address)
    {
        auto* handler = AddVectoredExceptionHandler(1, skip_illegal_instruction);
        if (!handler)
        {
            return false;
        }
        reinterpret_cast<void (*)()>(address)();
        RemoveVectoredExceptionHandler(handler);
        return illegal_instruction_raised;
    }

    // Live host input: ttd-input.txt next to the executable exists only when a test creates it.
    void read_input_attributes()
    {
        std::array<char, MAX_PATH> path{};
        const auto length = GetModuleFileNameA(nullptr, path.data(), static_cast<DWORD>(path.size()));
        const std::string_view module(path.data(), length);
        const auto directory = module.substr(0, module.find_last_of('\\') + 1);
        constexpr std::string_view input_name = "ttd-input.txt";
        if (directory.size() + input_name.size() >= path.size())
        {
            return;
        }
        memcpy(path.data() + directory.size(), input_name.data(), input_name.size());
        path[directory.size() + input_name.size()] = 0;
        ttd_input_attributes = GetFileAttributesA(path.data());
    }

    // Window input arrives between instruction slices; each Sleep gives the emulator a chance to deliver it.
    void wait_for_window_input()
    {
        WNDCLASSA window_class{};
        window_class.lpfnWndProc = DefWindowProcA;
        window_class.hInstance = GetModuleHandleA(nullptr);
        window_class.lpszClassName = "ttd-step-sample";
        RegisterClassA(&window_class);
        auto* const window = CreateWindowExA(0, window_class.lpszClassName, "ttd-step-sample", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, nullptr,
                                             nullptr, window_class.hInstance, nullptr);
        printf("ttd-window %p\n", static_cast<void*>(window));
        printf("ttd-ui %p\n", static_cast<void*>(const_cast<uint64_t*>(&ttd_ui_value)));
        fflush(stdout);
        for (int i = 0; i < 20 && !ttd_ui_value; ++i)
        {
            MSG message{};
            while (PeekMessageA(&message, nullptr, 0, 0, PM_REMOVE))
            {
                if (message.message == WM_APP)
                {
                    ttd_ui_value = message.wParam;
                }
                DispatchMessageA(&message);
            }
            if (!ttd_ui_value)
            {
                Sleep(1);
            }
        }
        DestroyWindow(window);
    }
}

int main()
{
    auto* code = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    auto* illegal = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!code || !illegal)
    {
        return 4;
    }

    printf("ttd-value %p\n", static_cast<void*>(const_cast<uint64_t*>(&ttd_value)));
    printf("ttd-info %p\n", static_cast<void*>(&ttd_info));
    printf("ttd-code %p\n", static_cast<void*>(code));
    printf("ttd-ud2 %p\n", static_cast<void*>(illegal));
    printf("ttd-input %p\n", static_cast<void*>(const_cast<DWORD*>(&ttd_input_attributes)));
    std::array<int, 4> cpu_info{};
    __cpuid(cpu_info.data(), 1);
    printf("ttd-rdrand %d\n", (cpu_info[2] >> 30) & 1);
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

    // ud2; ret
    illegal[0] = 0x0F;
    illegal[1] = 0x0B;
    illegal[2] = 0xC3;
    if (!raises_illegal_instruction(illegal))
    {
        return 5;
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

    read_input_attributes();
    wait_for_window_input();

    return ttd_copy == 0x2222222222222222 ? 0 : 1;
}
