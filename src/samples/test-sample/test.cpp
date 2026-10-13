#include <cstdint>
#include <cinttypes>
#include <cstring>
#include <string>
#include <fstream>
#include <thread>
#include <atomic>
#include <vector>
#include <optional>
#include <filesystem>
#include <string_view>
#include <array>

#include "../../common/utils/finally.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <intrin.h>

#include <windows.h>
#include <timeapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <shlobj.h>
#include <combaseapi.h>
#include <knownfolders.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <wincrypt.h>

using namespace std::literals;

// Externally visible and potentially modifiable state
// to trick compiler optimizations
__declspec(dllexport) bool do_the_task = true;

namespace
{
    struct tls_struct
    {
        DWORD num = 1337;

        tls_struct()
        {
            num = GetCurrentThreadId();
        }
    };

    thread_local tls_struct tls_var{};

    // getenv is broken right now :(
    std::string read_env(const char* env)
    {
        std::array<char, 0x1000> buffer{};
        if (!GetEnvironmentVariableA(env, buffer.data(), static_cast<DWORD>(buffer.size())))
        {
            return {};
        }

        return buffer.data();
    }

    bool test_threads()
    {
        constexpr auto thread_count = 5ULL;

        std::atomic<uint64_t> counter{0};

        std::vector<std::thread> threads{};
        threads.reserve(thread_count);

        for (auto i = 0ULL; i < thread_count; ++i)
        {
            threads.emplace_back([&counter] {
                ++counter;
                std::this_thread::yield();
                ++counter;
                // Host scheduling/cpu performance can have impact on emulator scheduling
                // std::this_thread::sleep_for(std::chrono::milliseconds(100));
                ++counter;
            });
        }

        for (auto& t : threads)
        {
            t.join();
        }

        return counter == (thread_count * 3ULL);
    }

    bool test_threads_winapi()
    {
        struct ctx_t
        {
            int iterations;
            int result;
        };

        static LPTHREAD_START_ROUTINE thread_proc = [](LPVOID lpParameter) -> DWORD {
            ctx_t& c = *static_cast<ctx_t*>(lpParameter);
            c.result = 0;
            for (int i = 1; i <= c.iterations; i++)
            {
                ++c.result;
            }
            return 0;
        };

        constexpr int thread_count = 5;
        std::array<HANDLE, thread_count> threads = {};
        std::array<ctx_t, thread_count> ctxs = {};

        for (int i = 0; i < thread_count; i++)
        {
            ctxs[i] = {.iterations = 5 * (i + 1), .result = 0};
            threads[i] = CreateThread(nullptr, 0, thread_proc, &ctxs[i], 0, nullptr);
            if (!threads[i])
            {
                return false;
            }
        }

        WaitForMultipleObjects(thread_count, threads.data(), TRUE, INFINITE);

        const std::array<int, thread_count> expected_results = {5, 10, 15, 20, 25};
        for (int i = 0; i < thread_count; i++)
        {
            if (ctxs[i].result != expected_results[i])
            {
                return false;
            }
            CloseHandle(threads[i]);
        }

        return true;
    }

    bool test_tls()
    {
        std::atomic_bool kill{false};
        std::atomic_uint32_t successes{0};
        constexpr uint32_t thread_count = 2;

        std::vector<std::thread> ts{};
        kill = false;

        ts.reserve(thread_count);
        for (size_t i = 0; i < thread_count; ++i)
        {
            ts.emplace_back([&] {
                while (!kill)
                {
                    std::this_thread::yield();
                }

                if (tls_var.num == GetCurrentThreadId())
                {
                    ++successes;
                }
            });
        }

        LoadLibraryA("d3dcompiler_47.dll");
        LoadLibraryA("dsound.dll");
        LoadLibraryA("comctl32.dll");
        /*LoadLibraryA("d3d9.dll");
        LoadLibraryA("dxgi.dll");
        LoadLibraryA("wlanapi.dll");*/

        kill = true;

        for (auto& t : ts)
        {
            if (t.joinable())
            {
                t.join();
            }
        }

        return successes == thread_count;
    }

    bool test_env()
    {
        const auto computername = read_env("COMPUTERNAME");

        SetEnvironmentVariableA("BLUB", "LUL");

        const auto blub = read_env("BLUB");

        return !computername.empty() && blub == "LUL";
    }

    bool test_lookup_account_sid()
    {
        HANDLE token{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            return false;
        }

        const auto close_token = sogen::utils::finally([&] { CloseHandle(token); });

        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(TOKEN_USER))
        {
            return false;
        }

        std::vector<std::byte> buffer(size);
        if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size))
        {
            return false;
        }

        const auto& token_user = *reinterpret_cast<const TOKEN_USER*>(buffer.data());
        if (token_user.User.Sid == nullptr || IsValidSid(token_user.User.Sid) == FALSE)
        {
            return false;
        }

        DWORD name_size = 0;
        DWORD domain_size = 0;
        SID_NAME_USE use = SidTypeUnknown;

        LookupAccountSidW(nullptr, token_user.User.Sid, nullptr, &name_size, nullptr, &domain_size, &use);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || name_size == 0 || domain_size == 0)
        {
            return false;
        }

        std::wstring name(name_size, L'\0');
        std::wstring domain(domain_size, L'\0');

        if (!LookupAccountSidW(nullptr, token_user.User.Sid, name.data(), &name_size, domain.data(), &domain_size, &use))
        {
            return false;
        }

        name.resize(name_size);
        domain.resize(domain_size);

        if (name.empty() || domain.empty() || use != SidTypeUser)
        {
            return false;
        }

        // A well-known group: NT AUTHORITY\INTERACTIVE (S-1-5-4).
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        PSID interactive{};
        if (!AllocateAndInitializeSid(&nt_authority, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &interactive))
        {
            return false;
        }
        const auto free_sid = sogen::utils::finally([&] { FreeSid(interactive); });

        std::array<wchar_t, 64> group_name{};
        std::array<wchar_t, 64> group_domain{};
        auto group_name_size = static_cast<DWORD>(group_name.size());
        auto group_domain_size = static_cast<DWORD>(group_domain.size());
        if (!LookupAccountSidW(nullptr, interactive, group_name.data(), &group_name_size, group_domain.data(), &group_domain_size, &use))
        {
            puts("Looking up a well-known SID failed");
            return false;
        }

        return std::wstring_view(group_name.data()) == L"INTERACTIVE" && use == SidTypeWellKnownGroup;
    }

    // LSA policy queries: the account domain is the computer's (its name and a S-1-5-21 SID); a machine without a domain
    // has no DNS domain.
    bool test_lsa_policy()
    {
        LSA_OBJECT_ATTRIBUTES attributes{};
        LSA_HANDLE policy{};
        if (LsaOpenPolicy(nullptr, &attributes, POLICY_VIEW_LOCAL_INFORMATION, &policy) != 0)
        {
            puts("LsaOpenPolicy failed");
            return false;
        }
        const auto close_policy = sogen::utils::finally([&] { LsaClose(policy); });

        void* account_information{};
        if (LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, &account_information) != 0 || !account_information)
        {
            puts("Querying the account domain failed");
            return false;
        }
        const auto free_account = sogen::utils::finally([&] { LsaFreeMemory(account_information); });

        std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computer{};
        auto computer_size = static_cast<DWORD>(computer.size());
        GetComputerNameW(computer.data(), &computer_size);

        const auto& account = *static_cast<const POLICY_ACCOUNT_DOMAIN_INFO*>(account_information);
        const std::wstring_view domain_name(account.DomainName.Buffer, account.DomainName.Length / sizeof(wchar_t));
        const auto* authority = account.DomainSid ? GetSidIdentifierAuthority(account.DomainSid) : nullptr;
        if (CompareStringOrdinal(domain_name.data(), static_cast<int>(domain_name.size()), computer.data(), static_cast<int>(computer_size),
                                 TRUE) != CSTR_EQUAL ||
            !account.DomainSid || !IsValidSid(account.DomainSid) || authority->Value[5] != 5 ||
            *GetSidSubAuthorityCount(account.DomainSid) != 4 || *GetSidSubAuthority(account.DomainSid, 0) != SECURITY_NT_NON_UNIQUE)
        {
            puts("The account domain is not the computer's");
            return false;
        }

        void* dns_information{};
        if (LsaQueryInformationPolicy(policy, PolicyDnsDomainInformation, &dns_information) != 0 || !dns_information)
        {
            puts("Querying the DNS domain failed");
            return false;
        }
        const auto free_dns = sogen::utils::finally([&] { LsaFreeMemory(dns_information); });

        const auto& dns = *static_cast<const POLICY_DNS_DOMAIN_INFO*>(dns_information);
        if (!dns.Sid && (dns.DnsDomainName.Length != 0 || dns.Name.Length == 0))
        {
            puts("A machine without a domain reported a DNS domain");
            return false;
        }

        return true;
    }

    // whoami's claims check: Kerberos reports Dynamic Access Control disabled outside a domain.
    bool test_lsa_authentication_packages()
    {
        HANDLE lsa{};
        if (LsaConnectUntrusted(&lsa) != 0)
        {
            puts("LsaConnectUntrusted failed");
            return false;
        }

        char kerberos_name[] = "kerberos";
        LSA_STRING kerberos{static_cast<USHORT>(strlen(kerberos_name)), sizeof(kerberos_name), kerberos_name};
        ULONG package = ~0UL;
        char missing_name[] = "NoSuchPackage";
        LSA_STRING missing{static_cast<USHORT>(strlen(missing_name)), sizeof(missing_name), missing_name};
        ULONG missing_package{};
        constexpr NTSTATUS status_no_such_package = static_cast<NTSTATUS>(0xC00000FE);
        if (LsaLookupAuthenticationPackage(lsa, &kerberos, &package) != 0 || package != 2 ||
            LsaLookupAuthenticationPackage(lsa, &missing, &missing_package) != status_no_such_package)
        {
            printf("Looking up packages failed (Kerberos is %lu)\n", package);
            LsaDeregisterLogonProcess(lsa);
            return false;
        }

        // KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST and _RESPONSE (not in every SDK).
        struct
        {
            ULONG message_type;
            ULONG flags;
            UNICODE_STRING domain_name;
        } request{.message_type = 32, .flags = 0, .domain_name = {}};

        struct extended_policies
        {
            ULONG message_type;
            ULONG flags;
            ULONG extended_policies;
            ULONG ds_flags;
        };

        void* response{};
        ULONG response_length{};
        NTSTATUS protocol_status{};
        const auto status =
            LsaCallAuthenticationPackage(lsa, package, &request, sizeof(request), &response, &response_length, &protocol_status);
        const auto* policies = static_cast<const extended_policies*>(response);
        constexpr ULONG dac_disabled = 1;
        const auto ok = status == 0 && protocol_status == 0 && response_length == sizeof(extended_policies) && policies &&
                        policies->message_type == 32 && policies->flags == dac_disabled;
        if (response)
        {
            LsaFreeReturnBuffer(response);
        }

        if (!ok)
        {
            printf("Kerberos extended policies: status %lX, protocol %lX, length %lu\n", static_cast<ULONG>(status),
                   static_cast<ULONG>(protocol_status), response_length);
        }

        return LsaDeregisterLogonProcess(lsa) == 0 && ok;
    }

    bool test_file_path_io(const std::filesystem::path& filename)
    {
        std::error_code ec{};
        const auto absolute_file = absolute(filename, ec);
        (void)absolute_file;

        if (ec)
        {
            puts("Getting absolute path failed");
            return false;
        }

        const auto canonical_file = canonical(filename, ec);
        (void)canonical_file;

        if (ec)
        {
            puts("Getting canonical path failed");
            return false;
        }

        return true;
    }

    bool test_io()
    {
        const std::filesystem::path filename1 = "a.txt";
        const std::filesystem::path filename2 = "A.tXt";

        FILE* fp{};
        (void)fopen_s(&fp, filename1.string().c_str(), "wb");

        if (!fp)
        {
            puts("Bad file");
            return false;
        }

        const std::string text = "Blub";

        (void)fwrite(text.data(), 1, text.size(), fp);
        (void)fclose(fp);

        if (!test_file_path_io(filename1))
        {
            return false;
        }

        std::ifstream t(filename2);
        t.seekg(0, std::ios::end);
        const size_t size = static_cast<size_t>(t.tellg());
        std::string buffer(size, ' ');
        t.seekg(0);
        t.read(buffer.data(), static_cast<std::streamsize>(size));

        return text == buffer;
    }

    bool test_file_locking()
    {
        const auto filename = std::filesystem::absolute("a.txt");
        constexpr DWORD pending_byte = 0x40000000UL;

        const auto cleanup_file = sogen::utils::finally([&] { DeleteFileW(filename.c_str()); });

        HANDLE first = CreateFileW(filename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (first == INVALID_HANDLE_VALUE)
        {
            puts("Failed to create first lock handle");
            return false;
        }

        const auto cleanup_first = sogen::utils::finally([&] { CloseHandle(first); });

        OVERLAPPED first_lock{};
        first_lock.Offset = pending_byte;
        if (!LockFileEx(first, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &first_lock))
        {
            puts("Failed to acquire first file lock");
            return false;
        }

        if (!UnlockFileEx(first, 0, 1, 0, &first_lock))
        {
            puts("Failed to unlock first file lock");
            return false;
        }

        OVERLAPPED second_lock{};
        second_lock.Offset = pending_byte + 1;
        if (!LockFileEx(first, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &second_lock))
        {
            puts("Failed to reacquire file lock");
            return false;
        }

        if (!UnlockFileEx(first, 0, 1, 0, &second_lock))
        {
            puts("Failed to unlock reacquired file lock");
            return false;
        }

        constexpr DWORD negative_length_low = 0xFFFFFFFFUL;
        constexpr DWORD negative_length_high = 0xFFFFFFFFUL;

        OVERLAPPED negative_lock{};
        if (!LockFileEx(first, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, negative_length_low, negative_length_high,
                        &negative_lock))
        {
            puts("Failed to acquire negative-length file lock");
            return false;
        }

        if (!UnlockFileEx(first, 0, negative_length_low, negative_length_high, &negative_lock))
        {
            puts("Failed to unlock negative-length file lock");
            return false;
        }

        return true;
    }

    bool test_working_directory()
    {
        std::error_code ec{};

        const auto current_dir = std::filesystem::current_path(ec);
        if (ec)
        {
            puts("Failed to get current path");
            return false;
        }

        const std::filesystem::path sys32 = "C:/windows/system32";
        current_path(sys32, ec);

        if (ec)
        {
            puts("Failed to update working directory");
            return false;
        }

        const auto new_current_dir = std::filesystem::current_path();
        if (sys32 != new_current_dir)
        {
            puts("Updated directory is wrong!");
            return false;
        }

        if (!std::ifstream("ntdll.dll"))
        {
            puts("Working directory is not active!");
            return false;
        }

        current_path(current_dir);
        return std::filesystem::current_path() == current_dir;
    }

    bool test_dir_io()
    {
        size_t count = 0;

        for (auto i : std::filesystem::directory_iterator(R"(C:\Windows\System32\)"))
        {
            ++count;
            if (count > 30)
            {
                return true;
            }
        }

        return count > 30;
    }

    std::optional<std::string> read_registry_string(const HKEY root, const char* path, const char* value)
    {
        HKEY key{};
        if (RegOpenKeyExA(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        std::array<char, MAX_PATH> data{};
        auto length = static_cast<DWORD>(data.size());
        const auto res = RegQueryValueExA(key, value, nullptr, nullptr, reinterpret_cast<uint8_t*>(data.data()), &length);

        if (RegCloseKey(key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        if (res != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        if (length == 0)
        {
            return "";
        }

        return {std::string(data.data(), std::min(static_cast<size_t>(length - 1), data.size()))};
    }

    std::optional<std::vector<std::string>> get_all_registry_keys(const HKEY root, const char* path)
    {
        HKEY key{};
        if (RegOpenKeyExA(root, path, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        std::vector<std::string> keys;
        std::vector<char> name_buffer(MAX_PATH + 1);

        for (DWORD i = 0;; ++i)
        {
            auto name_buffer_len = static_cast<DWORD>(name_buffer.size());
            const LSTATUS status = RegEnumKeyExA(key, i, name_buffer.data(), &name_buffer_len, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_SUCCESS)
            {
                keys.emplace_back(name_buffer.data(), name_buffer_len);
            }
            else if (status == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                keys.clear();
                break;
            }
        }

        if (keys.empty())
        {
            RegCloseKey(key);
            return std::nullopt;
        }

        if (RegCloseKey(key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        return keys;
    }

    std::optional<std::vector<std::string>> get_all_registry_values(const HKEY root, const char* path)
    {
        HKEY key{};
        if (RegOpenKeyExA(root, path, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        std::vector<std::string> values;
        std::vector<char> name_buffer(MAX_PATH + 1);

        for (DWORD i = 0;; ++i)
        {
            auto name_buffer_len = static_cast<DWORD>(name_buffer.size());
            const auto status = RegEnumValueA(key, i, name_buffer.data(), &name_buffer_len, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_SUCCESS)
            {
                values.emplace_back(name_buffer.data(), name_buffer_len);
            }
            else if (status == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                values.clear();
                break;
            }
        }

        if (values.empty())
        {
            RegCloseKey(key);
            return std::nullopt;
        }

        if (RegCloseKey(key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        return values;
    }

    // Registry values and keys can be deleted (a key only without sub keys), and a hive's root key opens.
    bool test_registry_deletion()
    {
        HKEY root{};
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &root) != ERROR_SUCCESS)
        {
            puts("Opening HKLM\\SOFTWARE failed");
            return false;
        }
        RegCloseKey(root);

        const auto parent_name = L"Software\\SogenDeletion" + std::to_wstring(GetCurrentProcessId());
        const auto child_name = parent_name + L"\\Child";
        HKEY child{};
        if (RegCreateKeyExW(HKEY_CURRENT_USER, child_name.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &child, nullptr) !=
            ERROR_SUCCESS)
        {
            return false;
        }

        constexpr DWORD value = 42;
        DWORD size = sizeof(value);
        const auto value_deleted =
            RegSetValueExW(child, L"Value", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), size) == ERROR_SUCCESS &&
            RegDeleteValueW(child, L"Value") == ERROR_SUCCESS &&
            RegQueryValueExW(child, L"Value", nullptr, nullptr, nullptr, &size) == ERROR_FILE_NOT_FOUND &&
            RegDeleteValueW(child, L"Value") == ERROR_FILE_NOT_FOUND;
        RegCloseKey(child);

        // The parent still has its child; deleting the child first works, and the parent goes after.
        const auto parent_refused = RegDeleteKeyW(HKEY_CURRENT_USER, parent_name.c_str()) != ERROR_SUCCESS;
        const auto child_deleted = RegDeleteKeyW(HKEY_CURRENT_USER, child_name.c_str()) == ERROR_SUCCESS;
        const auto parent_deleted = RegDeleteKeyW(HKEY_CURRENT_USER, parent_name.c_str()) == ERROR_SUCCESS;
        HKEY gone{};
        const auto parent_gone = RegOpenKeyExW(HKEY_CURRENT_USER, parent_name.c_str(), 0, KEY_READ, &gone) == ERROR_FILE_NOT_FOUND;

        if (!value_deleted || !parent_refused || !child_deleted || !parent_deleted || !parent_gone)
        {
            printf("Registry deletion: value %d, parent refused %d, child %d, parent %d, gone %d\n", value_deleted, parent_refused,
                   child_deleted, parent_deleted, parent_gone);
            return false;
        }

        return true;
    }

    std::wstring scratch_directory();

    // File mappings: a second mapping of the same name shares the memory, a view outlives its closed section, a shared
    // writable view of a file writes back to it, and a mapped file does not shrink.
    bool test_file_mappings()
    {
        const auto name = L"Local\\SogenMapping" + std::to_wstring(GetCurrentProcessId());
        auto* const first = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0x1000, name.c_str());
        auto* const second = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0x1000, name.c_str());
        const auto second_existed = GetLastError() == ERROR_ALREADY_EXISTS;
        auto* const first_view = static_cast<char*>(MapViewOfFile(first, FILE_MAP_WRITE, 0, 0, 0));
        auto* const second_view = static_cast<char*>(MapViewOfFile(second, FILE_MAP_WRITE, 0, 0, 0));
        if (!first_view || !second_view)
        {
            printf("Mapping named sections failed (%lu)\n", GetLastError());
            return false;
        }

        first_view[0] = 'm';
        const auto shared = second_existed && second_view[0] == 'm';
        CloseHandle(first);
        CloseHandle(second);
        // Both section handles are closed; the views still hold the memory.
        first_view[1] = 'n';
        const auto outlived = second_view[1] == 'n';
        UnmapViewOfFile(first_view);
        UnmapViewOfFile(second_view);
        if (!shared || !outlived)
        {
            printf("Named mappings: shared %d, views outlive the section %d\n", shared, outlived);
            return false;
        }

        const auto path = scratch_directory() + L"Mapped" + std::to_wstring(GetCurrentProcessId()) + L".bin";
        auto* const file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                       CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            printf("Creating the mapped file failed (%lu)\n", GetLastError());
            return false;
        }
        const auto close_file = sogen::utils::finally([&] { CloseHandle(file); });

        constexpr std::string_view original = "aaaaaaaaaa";
        DWORD transferred{};
        WriteFile(file, original.data(), static_cast<DWORD>(original.size()), &transferred, nullptr);
        auto* const mapping = CreateFileMappingW(file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
        auto* const view = static_cast<char*>(mapping ? MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0) : nullptr);
        if (!view)
        {
            printf("Mapping the file failed (%lu)\n", GetLastError());
            return false;
        }

        std::memset(view, 'c', original.size());
        FlushViewOfFile(view, 0);
        std::array<char, 16> contents{};
        SetFilePointer(file, 0, nullptr, FILE_BEGIN);
        const auto written_back = ReadFile(file, contents.data(), static_cast<DWORD>(contents.size()), &transferred, nullptr) &&
                                  std::string_view(contents.data(), transferred) == "cccccccccc";

        SetFilePointer(file, 2, nullptr, FILE_BEGIN);
        const auto shrink_refused = !SetEndOfFile(file) && GetLastError() == ERROR_USER_MAPPED_FILE;
        UnmapViewOfFile(view);
        CloseHandle(mapping);
        if (!written_back || !shrink_refused)
        {
            printf("File mappings: written back %d, shrink refused %d\n", written_back, shrink_refused);
            return false;
        }

        return true;
    }

    // The environment names the program directories, WaitNamedPipe finds a free instance, and short and long path names
    // round-trip (whether or not the volume keeps 8.3 names).
    bool test_environment_and_names()
    {
        std::array<wchar_t, MAX_PATH> program_files{};
        if (!GetEnvironmentVariableW(L"ProgramFiles", program_files.data(), static_cast<DWORD>(program_files.size())) ||
            !GetEnvironmentVariableW(L"ProgramData", nullptr, 0) || !GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0))
        {
            puts("ProgramFiles, ProgramData or LOCALAPPDATA is not set");
            return false;
        }

        const auto pipe_name = L"\\\\.\\pipe\\LOCAL\\SogenWait" + std::to_wstring(GetCurrentProcessId());
        const auto missing_refused = !WaitNamedPipeW(pipe_name.c_str(), 0) && GetLastError() == ERROR_FILE_NOT_FOUND;
        auto* const pipe = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 2, 32, 32, 0, nullptr);
        const auto free_found = pipe != INVALID_HANDLE_VALUE && WaitNamedPipeW(pipe_name.c_str(), 0);
        CloseHandle(pipe);
        if (!missing_refused || !free_found)
        {
            printf("WaitNamedPipe: missing refused %d, free instance found %d\n", missing_refused, free_found);
            return false;
        }

        // Program Files where it exists (emulation roots may lack it), otherwise the system directory.
        auto directory = program_files;
        if (GetFileAttributesW(directory.data()) == INVALID_FILE_ATTRIBUTES)
        {
            GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
        }

        std::array<wchar_t, MAX_PATH> short_path{};
        std::array<wchar_t, MAX_PATH> long_path{};
        if (!GetShortPathNameW(directory.data(), short_path.data(), static_cast<DWORD>(short_path.size())) ||
            !GetLongPathNameW(short_path.data(), long_path.data(), static_cast<DWORD>(long_path.size())) ||
            CompareStringOrdinal(long_path.data(), -1, directory.data(), -1, TRUE) != CSTR_EQUAL)
        {
            printf("Short and long path names do not round-trip: %ls -> %ls -> %ls (%lu)\n", directory.data(), short_path.data(),
                   long_path.data(), GetLastError());
            return false;
        }

        return true;
    }

    // A junction and a symbolic link lead to their targets, show as reparse points, and removing the junction leaves its
    // target.
    bool test_reparse_points()
    {
        std::array<wchar_t, MAX_PATH> full{};
        const auto relative = scratch_directory() + L"Reparse" + std::to_wstring(GetCurrentProcessId());
        GetFullPathNameW(relative.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
        const std::wstring base = full.data();
        const auto target = base + L"\\target";
        const auto junction = base + L"\\junction";
        const auto inner = target + L"\\inner.txt";
        const auto link = base + L"\\link.txt";

        const auto cleanup = sogen::utils::finally([&] {
            DeleteFileW(link.c_str());
            RemoveDirectoryW(junction.c_str());
            DeleteFileW(inner.c_str());
            RemoveDirectoryW(target.c_str());
            RemoveDirectoryW(base.c_str());
        });

        if (!CreateDirectoryW(base.c_str(), nullptr) || !CreateDirectoryW(target.c_str(), nullptr) ||
            !CreateDirectoryW(junction.c_str(), nullptr))
        {
            return false;
        }

        auto* const file = CreateFileW(inner.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
        DWORD transferred{};
        WriteFile(file, "data", 4, &transferred, nullptr);
        CloseHandle(file);

        // REPARSE_DATA_BUFFER for a mount point: tag, data length, reserved, substitute name offset/length, print name
        // offset/length, then "\??\<target>" and "<target>", each followed by a NUL.
        const auto substitute = L"\\??\\" + target;
        std::vector<uint8_t> buffer(16 + (substitute.size() + 1 + target.size() + 1) * sizeof(wchar_t));
        const auto put16 = [&](const size_t offset, const size_t value) {
            const auto v = static_cast<uint16_t>(value);
            memcpy(buffer.data() + offset, &v, sizeof(v));
        };
        constexpr DWORD mount_point_tag = IO_REPARSE_TAG_MOUNT_POINT;
        memcpy(buffer.data(), &mount_point_tag, sizeof(mount_point_tag));
        put16(4, buffer.size() - 8);
        put16(8, 0);
        put16(10, substitute.size() * sizeof(wchar_t));
        put16(12, (substitute.size() + 1) * sizeof(wchar_t));
        put16(14, target.size() * sizeof(wchar_t));
        memcpy(buffer.data() + 16, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
        memcpy(buffer.data() + 16 + (substitute.size() + 1) * sizeof(wchar_t), target.c_str(), (target.size() + 1) * sizeof(wchar_t));

        auto* const junction_handle = CreateFileW(junction.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        const auto set = DeviceIoControl(junction_handle, FSCTL_SET_REPARSE_POINT, buffer.data(), static_cast<DWORD>(buffer.size()),
                                         nullptr, 0, &transferred, nullptr);
        std::array<uint8_t, 1024> read_back{};
        DWORD tag{};
        const auto got = DeviceIoControl(junction_handle, FSCTL_GET_REPARSE_POINT, nullptr, 0, read_back.data(),
                                         static_cast<DWORD>(read_back.size()), &transferred, nullptr);
        memcpy(&tag, read_back.data(), sizeof(tag));
        CloseHandle(junction_handle);
        if (!set || !got || tag != IO_REPARSE_TAG_MOUNT_POINT)
        {
            printf("Setting a junction failed: set %d, get %d, tag %lX (%lu)\n", set, got, tag, GetLastError());
            return false;
        }

        const auto read_through = [&](const std::wstring& path) {
            std::array<char, 8> contents{};
            auto* const handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            DWORD read{};
            const auto ok = handle != INVALID_HANDLE_VALUE &&
                            ReadFile(handle, contents.data(), static_cast<DWORD>(contents.size()), &read, nullptr) &&
                            std::string_view(contents.data(), read) == "data";
            CloseHandle(handle);
            return ok;
        };

        WIN32_FIND_DATAW entry{};
        auto* const find = FindFirstFileW((base + L"\\junc*").c_str(), &entry);
        const auto listed = find != INVALID_HANDLE_VALUE && (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                            entry.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT;
        FindClose(find);
        const auto attributes = GetFileAttributesW(junction.c_str());
        if (!read_through(junction + L"\\inner.txt") || !listed || attributes == INVALID_FILE_ATTRIBUTES ||
            !(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            printf("Junction: read through %d, listed %d, attributes %lX\n", read_through(junction + L"\\inner.txt"), listed, attributes);
            return false;
        }

        // A relative file link, where the host lets this process create one.
        if (CreateSymbolicLinkW(link.c_str(), L"target\\inner.txt", SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) && !read_through(link))
        {
            puts("Reading through a relative symbolic link failed");
            return false;
        }

        if (!RemoveDirectoryW(junction.c_str()) || GetFileAttributesW(junction.c_str()) != INVALID_FILE_ATTRIBUTES || !read_through(inner))
        {
            puts("Removing a junction did not leave its target alone");
            return false;
        }

        return true;
    }

    // An app execution alias (IO_REPARSE_TAG_APPEXECLINK) opens only as itself; following it fails with
    // ERROR_CANT_ACCESS_FILE. Skipped where the user has no aliases (an emulation root).
    bool test_app_execution_alias()
    {
        std::array<wchar_t, MAX_PATH> local_app_data{};
        if (!GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data.data(), static_cast<DWORD>(local_app_data.size())))
        {
            return true;
        }

        const std::wstring directory = std::wstring(local_app_data.data()) + L"\\Microsoft\\WindowsApps\\";
        WIN32_FIND_DATAW entry{};
        auto* const find = FindFirstFileW((directory + L"*.exe").c_str(), &entry);
        if (find == INVALID_HANDLE_VALUE)
        {
            return true;
        }

        std::wstring alias{};
        do
        {
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && entry.dwReserved0 == IO_REPARSE_TAG_APPEXECLINK)
            {
                alias = directory + entry.cFileName;
                break;
            }
        } while (FindNextFileW(find, &entry));
        FindClose(find);

        if (alias.empty())
        {
            return true;
        }

        auto* const followed = CreateFileW(alias.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        const auto follow_error = GetLastError();
        if (followed != INVALID_HANDLE_VALUE)
        {
            CloseHandle(followed);
        }

        auto* const handle = CreateFileW(alias.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            printf("Opening the alias itself failed (%lu)\n", GetLastError());
            return false;
        }

        FILE_ATTRIBUTE_TAG_INFO tag_info{};
        const auto got_tag = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag_info, sizeof(tag_info));
        CloseHandle(handle);

        const auto attributes = GetFileAttributesW(alias.c_str());
        if (followed != INVALID_HANDLE_VALUE || follow_error != ERROR_CANT_ACCESS_FILE || !got_tag ||
            tag_info.ReparseTag != IO_REPARSE_TAG_APPEXECLINK || attributes == INVALID_FILE_ATTRIBUTES ||
            !(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            printf("Alias: follow error %lu, tag %d %lX, attributes %lX\n", follow_error, got_tag, tag_info.ReparseTag, attributes);
            return false;
        }

        return true;
    }

    // Reads right after a write, and writes right after a read, continue at the file position.
    bool test_read_after_write()
    {
        const auto file = scratch_directory() + L"ReadAfterWrite" + std::to_wstring(GetCurrentProcessId()) + L".bin";
        auto* const handle =
            CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const auto close_file = sogen::utils::finally([&] { CloseHandle(handle); });

        const std::vector<char> data(10000, 'a');
        DWORD count{};
        WriteFile(handle, data.data(), static_cast<DWORD>(data.size()), &count, nullptr);
        SetFilePointer(handle, 0, nullptr, FILE_BEGIN);
        WriteFile(handle, data.data(), 8193, &count, nullptr);

        std::vector<char> buffer(8192);
        DWORD read{};
        ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr);
        const auto after_read = SetFilePointer(handle, 0, nullptr, FILE_CURRENT);

        SetFilePointer(handle, 100, nullptr, FILE_BEGIN);
        ReadFile(handle, buffer.data(), 10, &count, nullptr);
        WriteFile(handle, "b", 1, &count, nullptr);
        const auto after_write = SetFilePointer(handle, 0, nullptr, FILE_CURRENT);
        SetFilePointer(handle, 110, nullptr, FILE_BEGIN);
        char written{};
        ReadFile(handle, &written, 1, &count, nullptr);

        if (read != 1807 || after_read != 10000 || after_write != 111 || written != 'b')
        {
            printf("Read after write: read %lu, at %lu; write after read at %lu, wrote %c\n", read, after_read, after_write, written);
            return false;
        }

        // Another handle of the file sees each write at once, also after it read the file before.
        const auto other_file = file + L".shared";
        auto* const writer = CreateFileW(other_file.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                         CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        auto* const reader = CreateFileW(other_file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                         OPEN_EXISTING, 0, nullptr);
        std::array<char, 16> shared{};
        DWORD first_read{};
        DWORD second_read{};
        WriteFile(writer, "foo\n", 4, &count, nullptr);
        ReadFile(reader, shared.data(), static_cast<DWORD>(shared.size()), &first_read, nullptr);
        WriteFile(writer, "bar\n", 4, &count, nullptr);
        ReadFile(reader, shared.data() + first_read, static_cast<DWORD>(shared.size()) - first_read, &second_read, nullptr);
        CloseHandle(reader);
        CloseHandle(writer);
        if (first_read != 4 || second_read != 4 || std::string_view(shared.data(), 8) != "foo\nbar\n")
        {
            printf("Shared file: first read %lu, second read %lu\n", first_read, second_read);
            return false;
        }

        // NUL is an empty file: it seeks to its end at 0 (CPython opens os.devnull with mode 'a').
        auto* const nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        LARGE_INTEGER end{.QuadPart = -1};
        const auto seeked = nul != INVALID_HANDLE_VALUE && SetFilePointerEx(nul, {}, &end, FILE_END);
        CloseHandle(nul);
        if (!seeked || end.QuadPart != 0)
        {
            printf("NUL seek to end: %lld, error %lu\n", end.QuadPart, GetLastError());
            return false;
        }

        return true;
    }

    // A read-only file says so and is not deleted until it is writable again; a handle names its file in the case the file
    // system keeps, whatever the case it was opened with.
    bool test_read_only_and_final_names()
    {
        const auto base = scratch_directory() + L"ReadOnly" + std::to_wstring(GetCurrentProcessId());
        const auto file = base + L"\\MixedCase.txt";
        const auto cleanup = sogen::utils::finally([&] {
            SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(file.c_str());
            RemoveDirectoryW(base.c_str());
        });

        if (!CreateDirectoryW(base.c_str(), nullptr))
        {
            return false;
        }
        CloseHandle(CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));

        const auto marked =
            SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_READONLY) && (GetFileAttributesW(file.c_str()) & FILE_ATTRIBUTE_READONLY);
        const auto delete_refused = !DeleteFileW(file.c_str()) && GetLastError() == ERROR_ACCESS_DENIED;
        const auto cleared =
            SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL) && !(GetFileAttributesW(file.c_str()) & FILE_ATTRIBUTE_READONLY);
        if (!marked || !delete_refused || !cleared)
        {
            printf("Read-only: marked %d, delete refused %d, cleared %d\n", marked, delete_refused, cleared);
            return false;
        }

        // Opened with another case, named with the created one.
        std::wstring lower_case = file;
        std::ranges::transform(lower_case, lower_case.begin(), [](const wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
        auto* const handle = CreateFileW(lower_case.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        std::array<wchar_t, MAX_PATH> final_name{};
        const auto length = GetFinalPathNameByHandleW(handle, final_name.data(), static_cast<DWORD>(final_name.size()), 0);
        CloseHandle(handle);
        if (length == 0 || !std::wstring_view(final_name.data(), length).ends_with(L"\\MixedCase.txt"))
        {
            printf("Final name: %ls\n", final_name.data());
            return false;
        }

        return true;
    }

    // A directory is not replaced (moving a file onto it fails and leaves both), while a directory may replace a file.
    bool test_replace_refusals()
    {
        const auto base = scratch_directory() + L"Replace" + std::to_wstring(GetCurrentProcessId());
        const auto file = base + L"\\file.txt";
        const auto directory = base + L"\\dir";
        const auto cleanup = sogen::utils::finally([&] {
            DeleteFileW(file.c_str());
            RemoveDirectoryW(file.c_str());
            RemoveDirectoryW(directory.c_str());
            RemoveDirectoryW(base.c_str());
        });

        if (!CreateDirectoryW(base.c_str(), nullptr) || !CreateDirectoryW(directory.c_str(), nullptr))
        {
            return false;
        }
        CloseHandle(CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));

        const auto file_onto_directory =
            !MoveFileExW(file.c_str(), directory.c_str(), MOVEFILE_REPLACE_EXISTING) && GetLastError() == ERROR_ACCESS_DENIED;
        const auto both_left = GetFileAttributesW(file.c_str()) != INVALID_FILE_ATTRIBUTES &&
                               (GetFileAttributesW(directory.c_str()) & FILE_ATTRIBUTE_DIRECTORY);
        const auto directory_onto_file = MoveFileExW(directory.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING) &&
                                         (GetFileAttributesW(file.c_str()) & FILE_ATTRIBUTE_DIRECTORY) &&
                                         GetFileAttributesW(directory.c_str()) == INVALID_FILE_ATTRIBUTES;
        if (!file_onto_directory || !both_left || !directory_onto_file)
        {
            printf("Replace: file onto directory refused %d, both left %d, directory onto file %d\n", file_onto_directory, both_left,
                   directory_onto_file);
            return false;
        }

        return true;
    }

    // The drives are listed, a volume's name leads back to its drive, and a directory has a file index.
    bool test_drives_and_volumes()
    {
        std::array<wchar_t, MAX_PATH> system{};
        GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
        const std::wstring root(system.data(), 3);

        std::array<wchar_t, 512> drives{};
        const auto drives_length = GetLogicalDriveStringsW(static_cast<DWORD>(drives.size()), drives.data());
        auto drive_listed = false;
        for (const auto* drive = drives.data(); drive < drives.data() + drives_length && *drive; drive += wcslen(drive) + 1)
        {
            drive_listed |= CompareStringOrdinal(drive, -1, root.c_str(), -1, TRUE) == CSTR_EQUAL;
        }

        std::array<wchar_t, MAX_PATH> volume{};
        std::array<wchar_t, MAX_PATH> paths{};
        DWORD paths_length{};
        const auto volume_found =
            GetVolumeNameForVolumeMountPointW(root.c_str(), volume.data(), static_cast<DWORD>(volume.size())) &&
            GetVolumePathNamesForVolumeNameW(volume.data(), paths.data(), static_cast<DWORD>(paths.size()), &paths_length) &&
            CompareStringOrdinal(paths.data(), -1, root.c_str(), -1, TRUE) == CSTR_EQUAL;

        auto* const directory = CreateFileW(system.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        BY_HANDLE_FILE_INFORMATION information{};
        const auto indexed = directory != INVALID_HANDLE_VALUE && GetFileInformationByHandle(directory, &information) &&
                             (information.nFileIndexHigh != 0 || information.nFileIndexLow != 0);
        CloseHandle(directory);

        if (!drive_listed || !volume_found || !indexed)
        {
            printf("Drives listed %d, volume leads back %d, directory indexed %d\n", drive_listed, volume_found, indexed);
            return false;
        }

        return true;
    }

    // The volume of a path is its drive's root.
    bool test_volume_path()
    {
        std::array<wchar_t, MAX_PATH> executable{};
        GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        std::array<wchar_t, MAX_PATH> system{};
        GetSystemDirectoryW(system.data(), static_cast<DWORD>(system.size()));

        for (const auto* path : {executable.data(), system.data()})
        {
            std::array<wchar_t, MAX_PATH> volume{};
            if (!GetVolumePathNameW(path, volume.data(), static_cast<DWORD>(volume.size())) ||
                std::wstring_view(volume.data()) != std::wstring_view(path, 3))
            {
                printf("GetVolumePathNameW did not return the drive's root (%lu)\n", GetLastError());
                return false;
            }
        }

        return true;
    }

    // Case mapping covers more than ASCII.
    bool test_case_mapping()
    {
        // A-diaeresis, L-stroke and Psi, as code units (the source is not read as UTF-8).
        constexpr std::array<wchar_t, 3> upper{0x00C4, 0x0141, 0x03A8};
        constexpr std::array<wchar_t, 3> expected{0x00E4, 0x0142, 0x03C8};
        std::array<wchar_t, 8> lower{};
        const auto length = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, upper.data(), static_cast<int>(upper.size()),
                                          lower.data(), static_cast<int>(lower.size()), nullptr, nullptr, 0);
        if (length != 3 || !std::equal(expected.begin(), expected.end(), lower.begin()))
        {
            printf("Lowercasing beyond ASCII failed: %d %04X %04X %04X (%lu)\n", length, lower[0], lower[1], lower[2], GetLastError());
            return false;
        }

        return true;
    }

    bool test_registry()
    {
#ifdef _WIN64
        const std::string_view progDir = "C:\\Program Files";
#else
        const std::string_view progDir = "C:\\Program Files (x86)";
#endif

        // Basic Reading Test
        const auto prog_files_dir =
            read_registry_string(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows\CurrentVersion)", "ProgramFilesDir");
        if (!prog_files_dir || *prog_files_dir != progDir)
        {
            return false;
        }

        // WOW64 Redirection Test
        const auto pst_display = read_registry_string(
            HKEY_LOCAL_MACHINE, R"(SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Time Zones\Pacific Standard Time)", "Display");
        if (!pst_display || pst_display->empty())
        {
            return false;
        }

        // Key Sub-keys Enumeration Test
        const auto subkeys_opt = get_all_registry_keys(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)");
        if (!subkeys_opt)
        {
            return false;
        }

        bool found_fonts = false;
        for (const auto& key_name : *subkeys_opt)
        {
            if (key_name == "Fonts")
            {
                found_fonts = true;
                break;
            }
        }

        (void)found_fonts;
#ifdef _WIN64
        if (!found_fonts)
        {
            return false;
        }
#endif

        // Key Values Enumeration Test
        const auto values_opt = get_all_registry_values(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)");
        if (!values_opt)
        {
            return false;
        }

        bool found_product_name = false;
        for (const auto& val_name : *values_opt)
        {
            if (val_name == "ProductName")
            {
                found_product_name = true;
                break;
            }
        }
        if (!found_product_name)
        {
            return false;
        }

        return true;
    }

    bool test_system_info()
    {
        std::array<char, MAX_PATH> sys_dir{};
        if (GetSystemDirectoryA(sys_dir.data(), static_cast<DWORD>(sys_dir.size())) == 0)
        {
            return false;
        }
        if (strlen(sys_dir.data()) != 19)
        {
            return false;
        }

        // TODO: This currently doesn't work.
        /*
        char username[256];
        DWORD username_len = sizeof(username);
        if (!GetUserNameA(username, &username_len))
        {
            return false;
        }
        if (username_len <= 1)
        {
            return false;
        }
        */

        return true;
    }

    bool validate_primary_monitor(MONITORINFOEXA& mi)
    {
        if (std::string_view(mi.szDevice) != R"(\\.\DISPLAY1)")
        {
            return false;
        }

        if (mi.rcMonitor.left != 0 || mi.rcMonitor.top != 0 || mi.rcMonitor.right != 1920 || mi.rcMonitor.bottom != 1080)
        {
            return false;
        }

        if (!(mi.dwFlags & MONITORINFOF_PRIMARY))
        {
            return false;
        }

        return true;
    }

    bool test_monitor_info()
    {
        const POINT pt = {0, 0};
        auto* const hMonitor = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
        if (!hMonitor)
        {
            return false;
        }

        MONITORINFOEXA mi;
        mi.cbSize = sizeof(mi);

        if (!GetMonitorInfoA(hMonitor, &mi))
        {
            return false;
        }

        return validate_primary_monitor(mi);
    }

    BOOL CALLBACK monitor_enum_proc(HMONITOR hMonitor, HDC, LPRECT, LPARAM dwData)
    {
        auto* valid = reinterpret_cast<bool*>(dwData);

        MONITORINFOEXA mi;
        mi.cbSize = sizeof(mi);

        if (!GetMonitorInfoA(hMonitor, &mi))
        {
            return FALSE;
        }

        *valid = validate_primary_monitor(mi);

        return *valid ? TRUE : FALSE;
    }

    bool test_user_callback()
    {
        bool valid = false;
        if (!EnumDisplayMonitors(nullptr, nullptr, monitor_enum_proc, reinterpret_cast<LPARAM>(&valid)))
        {
            return false;
        }

        return valid;
    }

    bool test_time_zone()
    {
        DYNAMIC_TIME_ZONE_INFORMATION current_dtzi = {};
        DWORD result = GetDynamicTimeZoneInformation(&current_dtzi);

        if (result == TIME_ZONE_ID_INVALID)
        {
            return false;
        }

        if (current_dtzi.Bias != -60 || current_dtzi.StandardBias != 0 || current_dtzi.DaylightBias != -60 ||
            current_dtzi.DynamicDaylightTimeDisabled != FALSE)
        {
            return false;
        }

        if (wcscmp(current_dtzi.StandardName, L"W. Europe Standard Time") != 0 ||
            wcscmp(current_dtzi.DaylightName, L"W. Europe Daylight Time") != 0 ||
            wcscmp(current_dtzi.TimeZoneKeyName, L"W. Europe Standard Time") != 0)
        {
            return false;
        }

        if (current_dtzi.StandardDate.wYear != 0 || current_dtzi.StandardDate.wMonth != 10 || current_dtzi.StandardDate.wDayOfWeek != 0 ||
            current_dtzi.StandardDate.wDay != 5 || current_dtzi.StandardDate.wHour != 3 || current_dtzi.StandardDate.wMinute != 0 ||
            current_dtzi.StandardDate.wSecond != 0 || current_dtzi.StandardDate.wMilliseconds != 0)
        {
            return false;
        }

        if (current_dtzi.DaylightDate.wYear != 0 || current_dtzi.DaylightDate.wMonth != 3 || current_dtzi.DaylightDate.wDayOfWeek != 0 ||
            current_dtzi.DaylightDate.wDay != 5 || current_dtzi.DaylightDate.wHour != 2 || current_dtzi.DaylightDate.wMinute != 0 ||
            current_dtzi.DaylightDate.wSecond != 0 || current_dtzi.DaylightDate.wMilliseconds != 0)
        {
            return false;
        }

        return true;
    }

    void throw_exception()
    {
        if (do_the_task)
        {
            throw std::runtime_error("OK");
        }
    }

    bool test_exceptions()
    {
        try
        {
            throw_exception();
            return false;
        }
        catch (const std::exception& e)
        {
            return e.what() == std::string("OK");
        }
    }

    struct wsa_initializer
    {
        wsa_initializer()
        {
            WSADATA wsa_data;
            if (WSAStartup(MAKEWORD(2, 2), &wsa_data))
            {
                throw std::runtime_error("Unable to initialize WSA");
            }
        }

        ~wsa_initializer()
        {
            WSACleanup();
        }
    };

    bool test_dns()
    {
        wsa_initializer _{};
        constexpr auto hostname = "google.com";

        PDNS_RECORDA records = nullptr;
        const auto query_status = DnsQuery_A(hostname, DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
        if (query_status != ERROR_SUCCESS)
        {
            printf("DnsQuery_A failed: %ld\n", query_status);
            return false;
        }

        const auto free_records = sogen::utils::finally([&] {
            if (records)
            {
                DnsRecordListFree(records, DnsFreeRecordList);
            }
        });

        auto has_ipv4_record = false;
        for (auto* current = records; current != nullptr; current = current->pNext)
        {
            if (current->wType == DNS_TYPE_A)
            {
                has_ipv4_record = true;
                break;
            }
        }

        if (!has_ipv4_record)
        {
            puts("DnsQuery_A returned no A records");
            return false;
        }

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* results = nullptr;
        const auto resolve_status = getaddrinfo(hostname, "80", &hints, &results);
        if (resolve_status != 0)
        {
            puts("getaddrinfo failed");
            return false;
        }

        const auto free_results = sogen::utils::finally([&] {
            if (results)
            {
                freeaddrinfo(results);
            }
        });

        for (auto* current = results; current != nullptr; current = current->ai_next)
        {
            if (current->ai_family == AF_INET || current->ai_family == AF_INET6)
            {
                return true;
            }
        }

        puts("getaddrinfo returned no usable addresses");
        return false;
    }

    bool test_socket()
    {
        wsa_initializer _{};
        constexpr std::string_view send_data = "Hello World";

        const auto sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        const auto receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sender == INVALID_SOCKET || receiver == INVALID_SOCKET)
        {
            puts("Socket creation failed");
            return false;
        }

        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        destination.sin_port = htons(28970);

        if (bind(receiver, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) == SOCKET_ERROR)
        {
            puts("Failed to bind socket!");
            return false;
        }

        const auto sent_bytes = sendto(sender, send_data.data(), static_cast<int>(send_data.size()), 0,
                                       reinterpret_cast<sockaddr*>(&destination), sizeof(destination));

        if (static_cast<size_t>(sent_bytes) != send_data.size())
        {
            puts("Failed to send data!");
            return false;
        }

        std::array<char, 100> buffer = {};
        sockaddr_in sender_addr{};
        int sender_length = sizeof(sender_addr);

        const auto len = recvfrom(receiver, buffer.data(), static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&sender_addr),
                                  &sender_length);
        const auto ulen = static_cast<size_t>(len);

        if (ulen != send_data.size())
        {
            puts("Failed to receive data!");
            return false;
        }

        return send_data == std::string_view(buffer.data(), ulen);
    }

#ifndef __MINGW64__
    void throw_access_violation()
    {
        if (do_the_task)
        {
            *reinterpret_cast<int*>(1) = 1;
        }
    }

    bool test_access_violation_exception()
    {
        __try
        {
            throw_access_violation();
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode() == STATUS_ACCESS_VIOLATION;
        }
    }

    bool test_ud2_exception(void* address)
    {
        __try
        {
            reinterpret_cast<void (*)()>(address)();
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode() == STATUS_ILLEGAL_INSTRUCTION;
        }
    }

    bool test_unhandled_exception()
    {
        thread_local bool caught{};
        caught = false;

        auto* old = SetUnhandledExceptionFilter([](struct _EXCEPTION_POINTERS* info) -> LONG {
            caught = true;

#ifdef _WIN64
            info->ContextRecord->Rip += 1;
#else
            info->ContextRecord->Eip += 1;
#endif

            return EXCEPTION_CONTINUE_EXECUTION;
        });

        DebugBreak();
        SetUnhandledExceptionFilter(old);

        return caught;
    }

    bool test_illegal_instruction_exception()
    {
        auto* const address = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!address)
        {
            return false;
        }

        memcpy(address, "\x0F\x0B", 2); // ud2

        const auto res = test_ud2_exception(address);

        VirtualFree(address, 0x1000, MEM_RELEASE);

        return res;
    }

    INT32 test_guard_page_seh_filter(LPVOID address, DWORD code, struct _EXCEPTION_POINTERS* ep)
    {
        // We are only looking for guard page exceptions.
        if (code != STATUS_GUARD_PAGE_VIOLATION)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // The number of defined elements in the ExceptionInformation array for
        // a guard page violation should be 2.
        if (ep->ExceptionRecord->NumberParameters != 2)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // The ExceptionInformation array specifies additional arguments that
        // describe the exception.
        auto* exception_information = ep->ExceptionRecord->ExceptionInformation;

        // If this value is zero, the thread attempted to read the inaccessible
        // data. If this value is 1, the thread attempted to write to an
        // inaccessible address.
        if (exception_information[0] != 1)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // The second array element specifies the virtual address of the
        // inaccessible data.
        if (exception_information[1] != reinterpret_cast<ULONG_PTR>(address))
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        return EXCEPTION_EXECUTE_HANDLER;
    }

    bool test_guard_page_exception()
    {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);

        // Allocate a guarded memory region with the length of the system page
        // size.
        auto* addr = static_cast<LPBYTE>(VirtualAlloc(nullptr, sys_info.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD));
        if (addr == nullptr)
        {
            puts("Failed to allocate guard page");
            return false;
        }

        bool success = false;

        // We want to access some arbitrary offset into the guarded page, to
        // ensure that ExceptionInformation correctly contains the virtual
        // address of the inaccessible data, not the base address of the region.
        constexpr size_t offset = 10;

        // Trigger a guard page violation
        __try
        {
            addr[offset] = 255;
        }
        // If the filter function returns EXCEPTION_CONTINUE_SEARCH, the
        // exception contains all of the correct information.
        __except (test_guard_page_seh_filter(addr + offset, GetExceptionCode(), GetExceptionInformation()))
        {
            success = true;
        }

        // The page guard should be lifted, so no exception should be raised.
        __try
        {
            // The previous write should not have went through, this is probably
            // superflous.
            if (addr[offset] == 255)
            {
                success = false;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            puts("Failed to read from page after guard exception!");
            success = false;
        }

        // Free the allocated memory
        if (!VirtualFree(addr, 0, MEM_RELEASE))
        {
            puts("Failed to free allocated region");
            success = false;
        }

        return success;
    }

    bool test_native_exceptions()
    {
        return test_access_violation_exception()       //
               && test_illegal_instruction_exception() //
               && test_unhandled_exception()           //
#ifdef _WIN64
               && test_guard_page_exception();
#else
            ;
#endif
    }
#endif

    thread_local bool trap_flag_cleared = false;
    constexpr DWORD TRAP_FLAG_MASK = 0x100;

    LONG NTAPI single_step_handler(PEXCEPTION_POINTERS exception_info)
    {
        if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            PCONTEXT context = exception_info->ContextRecord;
            trap_flag_cleared = (context->EFlags & TRAP_FLAG_MASK) == 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool test_interrupts()
    {
        trap_flag_cleared = false;

        PVOID veh_handle = AddVectoredExceptionHandler(1, single_step_handler);
        if (!veh_handle)
        {
            return false;
        }

        __writeeflags(__readeflags() | TRAP_FLAG_MASK);

#ifdef __MINGW64__
        asm("nop");
#else
        __nop();
#endif

        RemoveVectoredExceptionHandler(veh_handle);

        return trap_flag_cleared;
    }

    void print_time()
    {
        const auto epoch_time = std::chrono::system_clock::now().time_since_epoch();
        printf("Time: %" PRId64 "\n", std::chrono::duration_cast<std::chrono::nanoseconds>(epoch_time).count());
    }

    bool test_apis()
    {
        if (VirtualProtect(nullptr, 0, 0, nullptr))
        {
            return false;
        }

        std::array<wchar_t, 0x100> buffer{};
        auto size = static_cast<DWORD>(buffer.size() / 2);
        if (!GetComputerNameExW(ComputerNameNetBIOS, buffer.data(), &size))
        {
            return false;
        }

        PWSTR path{};
        const auto hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path);
        if (FAILED(hr))
        {
            return false;
        }

        CoTaskMemFree(path);
        return true;
    }

    bool test_apc()
    {
        int executions = 0;

        PAPCFUNC apc_func = [](const ULONG_PTR param) {
            *reinterpret_cast<int*>(param) += 1; //
        };

        QueueUserAPC(apc_func, GetCurrentThread(), reinterpret_cast<ULONG_PTR>(&executions));
        QueueUserAPC(apc_func, GetCurrentThread(), reinterpret_cast<ULONG_PTR>(&executions));

        Sleep(1);

        if (executions != 0)
        {
            return false;
        }

        SleepEx(1, TRUE);
        return executions == 2;
    }

    bool test_window_geometry()
    {
        WNDCLASSEXA wc{};
        wc.cbSize = sizeof(wc);
        wc.lpszClassName = "TestWindowNonclientClass";
        wc.hInstance = GetModuleHandleA(nullptr);
        wc.lpfnWndProc = DefWindowProcA;

        if (!RegisterClassExA(&wc))
        {
            puts("Failed to register window class");
            return false;
        }

        const auto unregister_class = sogen::utils::finally([&] { UnregisterClassA(wc.lpszClassName, wc.hInstance); });

        struct window_case
        {
            DWORD style;
            DWORD ex_style;
        };

        constexpr std::array cases = {
            window_case{.style = WS_POPUP | WS_THICKFRAME, .ex_style = 0},
            window_case{.style = WS_POPUP | WS_CAPTION, .ex_style = 0},
            window_case{.style = WS_POPUP | WS_DLGFRAME, .ex_style = 0},
            window_case{.style = WS_POPUP, .ex_style = WS_EX_CLIENTEDGE},
        };

        for (const auto& test : cases)
        {
            constexpr LONG expected_client_height = 123;
            constexpr LONG expected_client_width = 321;

            RECT adjusted_rect{0, 0, expected_client_width, expected_client_height};
            const BOOL adjusted = test.ex_style ? AdjustWindowRectEx(&adjusted_rect, test.style, FALSE, test.ex_style)
                                                : AdjustWindowRect(&adjusted_rect, test.style, FALSE);
            if (!adjusted)
            {
                puts("Failed to calculate nonclient insets");
                return false;
            }

            const auto adjusted_width = adjusted_rect.right - adjusted_rect.left;
            const auto adjusted_height = adjusted_rect.bottom - adjusted_rect.top;

            const HWND hwnd = CreateWindowExA(test.ex_style, wc.lpszClassName, nullptr, test.style, 0, 0, adjusted_width, adjusted_height,
                                              nullptr, nullptr, wc.hInstance, nullptr);
            if (!hwnd)
            {
                puts("Failed to create test window");
                return false;
            }

            const auto destroy_window = sogen::utils::finally([&] { DestroyWindow(hwnd); });

            RECT window_rect{};
            RECT client_rect{};
            if (!GetWindowRect(hwnd, &window_rect) || !GetClientRect(hwnd, &client_rect))
            {
                return false;
            }

            const auto window_width = window_rect.right - window_rect.left;
            const auto window_height = window_rect.bottom - window_rect.top;
            const auto client_width = client_rect.right - client_rect.left;
            const auto client_height = client_rect.bottom - client_rect.top;

            if (window_width != adjusted_width || window_height != adjusted_height)
            {
                puts("Window size does not match AdjustWindowRect result");
                return false;
            }

            if (client_width != expected_client_width || client_height != expected_client_height)
            {
                puts("AdjustWindowRect round-trip failed");
                return false;
            }
        }

        return true;
    }

    bool test_message_queue()
    {
        thread_local UINT wnd_proc_num = 0;
        thread_local UINT destroy_count = 0;
        static const UINT wnd_msg_id = WM_APP + 2;

        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpszClassName = "TestMsgQueueClass";
        wc.hInstance = GetModuleHandleA(nullptr);
        wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> LRESULT {
            if (msg == WM_CREATE)
            {
                auto* const cs = reinterpret_cast<CREATESTRUCTA*>(lp);
                if (cs->lpCreateParams == reinterpret_cast<void*>(0x1337))
                {
                    wnd_proc_num += 1;
                }
            }
            else if (msg == wnd_msg_id)
            {
                if (wp == 123 && lp == 456)
                {
                    wnd_proc_num += 1;
                    return 777;
                }
            }
            else if (msg == WM_CLOSE)
            {
                wnd_proc_num += 1;
                if (wnd_proc_num == 2)
                {
                    return 0;
                }
            }
            else if (msg == WM_DESTROY)
            {
                ++destroy_count;
                PostQuitMessage(42);
            }
            return DefWindowProcA(hwnd, msg, wp, lp);
        };

        if (!RegisterClassExA(&wc))
        {
            puts("Failed to register window class");
            return false;
        }

        const auto unregister_class = sogen::utils::finally([&] { UnregisterClassA(wc.lpszClassName, wc.hInstance); });

        HWND hwnd = CreateWindowExA(0, wc.lpszClassName, nullptr, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance,
                                    reinterpret_cast<void*>(0x1337));
        if (!hwnd || wnd_proc_num != 1)
        {
            puts("Failed to create message window");
            return false;
        }

        const auto destroy_window = sogen::utils::finally([&] { DestroyWindow(hwnd); });

        const LRESULT send_res = SendMessageA(hwnd, wnd_msg_id, 123, 456);

        if (send_res != 777 || wnd_proc_num != 2)
        {
            puts("SendMessage failed");
            return false;
        }

        wnd_proc_num = 0;
        if (!PostMessageA(hwnd, wnd_msg_id, 123, 456))
        {
            puts("PostMessage failed");
            return false;
        }

        MSG msg = {};
        if (GetMessageA(&msg, hwnd, 0, 0) <= 0)
        {
            puts("GetMessage failed or returned WM_QUIT unexpectedly");
            return false;
        }

        if (msg.message != wnd_msg_id)
        {
            puts("Retrieved message is not the expected custom message");
            return false;
        }

        TranslateMessage(&msg);
        DispatchMessageA(&msg);

        if (wnd_proc_num != 1)
        {
            puts("Posted window message did not execute WndProc");
            return false;
        }

        SendMessageA(hwnd, WM_CLOSE, 0, 0);
        if (!IsWindow(hwnd) || destroy_count != 0)
        {
            puts("WndProc unexpectedly destroyed the window on cancelled WM_CLOSE");
            return false;
        }

        SendMessageA(hwnd, WM_CLOSE, 0, 0);
        if (IsWindow(hwnd) || destroy_count != 1)
        {
            puts("DefWindowProc did not destroy the window on WM_CLOSE");
            return false;
        }
        hwnd = nullptr;

        const BOOL quit_result = GetMessageA(&msg, nullptr, 0, 0);
        if (quit_result != 0)
        {
            puts("GetMessage did not return 0 for WM_QUIT");
            return false;
        }

        if (msg.message != WM_QUIT)
        {
            puts("Message is not WM_QUIT");
            return false;
        }

        if (msg.wParam != 42)
        {
            puts("WM_QUIT exit code mismatch");
            return false;
        }

        return true;
    }

    bool test_paint_message_queue()
    {
        struct paint_state
        {
            HWND window{};
            int ncpaint{};
            int erase{};
            int paint{};
        };

        thread_local paint_state* active_paint_state{};

        WNDCLASSEXA wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpszClassName = "TestPaintMsgQueueClass";
        wc.hInstance = GetModuleHandleA(nullptr);
        wc.lpfnWndProc = [](const HWND hwnd, const UINT message, const WPARAM w_param, const LPARAM l_param) -> LRESULT {
            if (active_paint_state && hwnd == active_paint_state->window)
            {
                if (message == WM_NCPAINT)
                {
                    ++active_paint_state->ncpaint;
                }
                else if (message == WM_ERASEBKGND)
                {
                    ++active_paint_state->erase;
                    RECT client_rect{};
                    GetClientRect(hwnd, &client_rect);
                    FillRect(reinterpret_cast<HDC>(w_param), &client_rect, reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1));
                    return TRUE;
                }
                else if (message == WM_PAINT)
                {
                    ++active_paint_state->paint;
                    PAINTSTRUCT paint{};
                    BeginPaint(hwnd, &paint);
                    EndPaint(hwnd, &paint);
                    return 0;
                }
            }

            return DefWindowProcA(hwnd, message, w_param, l_param);
        };

        if (!RegisterClassExA(&wc))
        {
            puts("Failed to register paint window class");
            return false;
        }

        const auto unregister_class = sogen::utils::finally([&] { UnregisterClassA(wc.lpszClassName, wc.hInstance); });

        const HWND hwnd =
            CreateWindowExA(0, wc.lpszClassName, nullptr, WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);
        if (!hwnd)
        {
            puts("Failed to create paint window");
            return false;
        }

        const auto destroy_window = sogen::utils::finally([&] { DestroyWindow(hwnd); });

        paint_state state{.window = hwnd};
        active_paint_state = &state;
        const auto clear_paint_state = sogen::utils::finally([&] { active_paint_state = nullptr; });

        ShowWindow(hwnd, SW_SHOWDEFAULT);

        RECT update_rect{};
        if (state.ncpaint != 1 || state.erase != 1)
        {
            puts("ShowWindow did not synthesize nonclient and background paint");
            return false;
        }
        if (state.paint != 0 || !GetUpdateRect(hwnd, &update_rect, FALSE))
        {
            puts("ShowWindow background paint unexpectedly validated the window");
            return false;
        }
        if (!UpdateWindow(hwnd) || state.paint != 1 || GetUpdateRect(hwnd, &update_rect, FALSE))
        {
            puts("UpdateWindow did not paint and validate the window after ShowWindow");
            return false;
        }

        RedrawWindow(hwnd, nullptr, nullptr, RDW_NOINTERNALPAINT | RDW_VALIDATE);
        ValidateRect(hwnd, nullptr);

        MSG msg = {};
        while (PeekMessageA(&msg, hwnd, WM_PAINT, WM_PAINT, PM_REMOVE))
        {
            ValidateRect(hwnd, nullptr);
        }

        if (!RedrawWindow(hwnd, nullptr, nullptr, RDW_INTERNALPAINT))
        {
            puts("Failed to request internal paint");
            return false;
        }

        if (!PeekMessageA(&msg, hwnd, WM_PAINT, WM_PAINT, PM_NOREMOVE))
        {
            puts("Internal WM_PAINT was not available");
            return false;
        }

        if (PeekMessageA(&msg, hwnd, WM_PAINT, WM_PAINT, PM_NOREMOVE))
        {
            puts("PM_NOREMOVE did not consume internal WM_PAINT");
            return false;
        }

        InvalidateRect(hwnd, nullptr, FALSE);
        RedrawWindow(hwnd, nullptr, nullptr, RDW_INTERNALPAINT);

        if (!PeekMessageA(&msg, hwnd, WM_PAINT, WM_PAINT, PM_REMOVE))
        {
            puts("Combined WM_PAINT was not available");
            return false;
        }

        if (!PeekMessageA(&msg, hwnd, WM_PAINT, WM_PAINT, PM_NOREMOVE))
        {
            puts("PM_REMOVE consumed the invalid update region");
            return false;
        }

        ValidateRect(hwnd, nullptr);

        return true;
    }

    bool test_mutable_callbacks()
    {
        struct test_state
        {
            int changing_count{};
            int size_width{};
            int size_height{};
            UINT changed_flags{};
            bool mutate{true};
            bool saw_size{};
            bool saw_changed{};
        };

        thread_local test_state* active_state{};
        test_state state{};
        active_state = &state;

        WNDCLASSEXA wc{};
        wc.cbSize = sizeof(wc);
        wc.lpszClassName = "TestMutMsgQueueClass";
        wc.hInstance = GetModuleHandleA(nullptr);
        wc.lpfnWndProc = [](HWND hwnd, const UINT msg, const WPARAM wp, const LPARAM lp) -> LRESULT {
            if (active_state && msg == WM_WINDOWPOSCHANGING && active_state->mutate)
            {
                auto& position = *reinterpret_cast<WINDOWPOS*>(lp);
                position.x = -123;
                position.y = -456;
                position.cx = 800;
                position.cy = 600;
                position.flags &= ~(SWP_NOMOVE | SWP_NOSIZE);
                ++active_state->changing_count;
            }
            else if (active_state && msg == WM_WINDOWPOSCHANGED)
            {
                active_state->changed_flags = reinterpret_cast<const WINDOWPOS*>(lp)->flags;
                active_state->saw_changed = true;
            }
            else if (active_state && msg == WM_SIZE)
            {
                active_state->size_width = LOWORD(lp);
                active_state->size_height = HIWORD(lp);
                active_state->saw_size = true;
            }

            return DefWindowProcA(hwnd, msg, wp, lp);
        };

        if (!RegisterClassExA(&wc))
        {
            active_state = nullptr;
            return false;
        }

        HWND hwnd{};
        const auto cleanup = sogen::utils::finally([&] {
            state.mutate = false;
            if (hwnd)
            {
                DestroyWindow(hwnd);
            }
            UnregisterClassA(wc.lpszClassName, wc.hInstance);
            active_state = nullptr;
        });

        hwnd = CreateWindowExA(0, wc.lpszClassName, nullptr, WS_OVERLAPPEDWINDOW | WS_VISIBLE, 10, 20, 320, 240, nullptr, nullptr,
                               wc.hInstance, nullptr);
        state.mutate = false;
        if (!hwnd)
        {
            return false;
        }

        RECT window_rect{};
        RECT client_rect{};
        if (!GetWindowRect(hwnd, &window_rect) || !GetClientRect(hwnd, &client_rect))
        {
            return false;
        }

        const auto window_width = window_rect.right - window_rect.left;
        const auto window_height = window_rect.bottom - window_rect.top;
        const auto client_width = client_rect.right - client_rect.left;
        const auto client_height = client_rect.bottom - client_rect.top;

        return state.changing_count == 2 && state.saw_changed && (state.changed_flags & SWP_SHOWWINDOW) != 0 && state.saw_size &&
               window_rect.left == -123 && window_rect.top == -456 && window_width == 800 && window_height == 600 &&
               client_width < window_width && client_height < window_height && state.size_width == client_width &&
               state.size_height == client_height;
    }

    bool test_private_namespace()
    {
        auto create_boundary_descriptor = [](const wchar_t* name) -> HANDLE {
            auto* hBoundaryDescriptor = CreateBoundaryDescriptorW(name, 0);
            if (hBoundaryDescriptor == nullptr)
            {
                puts("Failed to create boundary descriptor");
                return nullptr;
            }

            PSID pLocalAdmin{};
            if (ConvertStringSidToSidW(L"S-1-1-0", &pLocalAdmin) == FALSE)
            {
                puts("ConvertStringSidToSid failed");
                return nullptr;
            }

            auto res = AddSIDToBoundaryDescriptor(&hBoundaryDescriptor, pLocalAdmin);
            LocalFree(pLocalAdmin);

            if (res == FALSE)
            {
                puts("AddSIDToBoundaryDescriptor failed");
                return nullptr;
            }

            return hBoundaryDescriptor;
        };

        std::array<HANDLE, 2> boundary{};
        std::array<HANDLE, 5> ns{};

        const auto _ = sogen::utils::finally([&]() {
            for (auto* elem : boundary)
            {
                if (elem)
                {
                    DeleteBoundaryDescriptor(elem);
                }
            }

            for (auto* elem : ns)
            {
                if (elem)
                {
                    ClosePrivateNamespace(elem, 0);
                }
            }
        });

        boundary[0] = create_boundary_descriptor(L"boundary1");
        if (boundary[0] == nullptr)
        {
            return false;
        }

        ns[0] = CreatePrivateNamespaceW(nullptr, boundary[0], L"ns");
        if (ns[0] == nullptr)
        {
            puts("CreatePrivateNamespaceW failed");
            return false;
        }

        ns[1] = CreatePrivateNamespaceW(nullptr, boundary[0], L"alt_ns");
        if (ns[1] != nullptr)
        {
            puts("CreatePrivateNamespaceW did not refuse to associate another prefix with existing namespace");
            return false;
        }

        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            puts("GetLastError did not return ERROR_ALREADY_EXISTS");
            return false;
        }

        boundary[1] = create_boundary_descriptor(L"boundary2");
        if (boundary[1] == nullptr)
        {
            return false;
        }

        ns[2] = CreatePrivateNamespaceW(nullptr, boundary[1], L"ns");
        if (ns[2] != nullptr)
        {
            puts("CreatePrivateNamespaceW did not refuse to create another namespace associated with existing prefix");
            return false;
        }

        if (GetLastError() != ERROR_DUP_NAME)
        {
            puts("GetLastError did not return ERROR_DUP_NAME");
            return false;
        }

        auto* mutex = CreateMutexW(nullptr, FALSE, L"ns\\mutex");
        if (mutex == nullptr)
        {
            puts("CreateMutex failed to create mutex in private namespace");
            return false;
        }

        CloseHandle(mutex);

        ns[3] = OpenPrivateNamespaceW(boundary[0], L"alt_ns");
        if (ns[3] == nullptr)
        {
            puts("OpenPrivateNamespaceW failed to open existing namespace and associate it with different prefix");
            return false;
        }

        ns[4] = OpenPrivateNamespaceW(boundary[0], L"ns");
        if (ns[4])
        {
            puts("OpenPrivateNamespaceW did not refuse to open existing namespace and associate it with existing prefix");
            return false;
        }

        DeleteBoundaryDescriptor(boundary[0]);
        boundary[0] = nullptr;

        if (!ClosePrivateNamespace(ns[3], 0))
        {
            puts("ClosePrivateNamespace failed");
            return false;
        }

        ns[3] = nullptr;

        if (!ClosePrivateNamespace(ns[0], PRIVATE_NAMESPACE_FLAG_DESTROY))
        {
            puts("ClosePrivateNamespace (with destroy flag) failed");
            return false;
        }

        ns[0] = nullptr;

        return true;
    }

    bool test_actctx()
    {
        ACTCTXA actctx{};
        actctx.cbSize = sizeof(actctx);
        actctx.dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID;
        actctx.hModule = GetModuleHandleW(nullptr);
        actctx.lpResourceName = CREATEPROCESS_MANIFEST_RESOURCE_ID;

        auto* ctx = CreateActCtxA(&actctx);
        if (ctx == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        ReleaseActCtx(ctx);
        return true;
    }

    bool test_mmio()
    {
        const auto t0 = timeGetTime();

        // waste a bit of time
        auto dummy = std::thread([] {
            for (int i = 0; i < 1024; i++)
            {
                std::this_thread::yield();
            }
        });
        dummy.join();

        const auto t1 = timeGetTime();

        return t1 != t0;
    }

    bool test_settimer()
    {
        MSG msg = {};
        while (PeekMessageA(&msg, nullptr, WM_TIMER, WM_TIMER, PM_REMOVE))
        {
        }

        HANDLE dummy_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!dummy_event)
        {
            puts("CreateEventW failed");
            return false;
        }

        const auto cleanup_event = sogen::utils::finally([&] { CloseHandle(dummy_event); });

        const UINT_PTR timer_id = SetTimer(nullptr, 0, 10, nullptr);
        if (!timer_id)
        {
            puts("SetTimer failed");
            return false;
        }

        const auto cleanup_timer = sogen::utils::finally([&] { KillTimer(nullptr, timer_id); });

        const DWORD wait_result = MsgWaitForMultipleObjects(1, &dummy_event, FALSE, 1000, QS_TIMER);

        if (wait_result != WAIT_OBJECT_0 + 1)
        {
            printf("MsgWaitForMultipleObjects returned unexpected result: %lu\n", wait_result);
            return false;
        }

        if (!PeekMessageA(&msg, nullptr, WM_TIMER, WM_TIMER, PM_REMOVE))
        {
            puts("Expected WM_TIMER message was not available");
            return false;
        }

        if (msg.message != WM_TIMER)
        {
            puts("Received message was not WM_TIMER");
            return false;
        }

        if (msg.hwnd != nullptr)
        {
            puts("Expected a thread timer, but WM_TIMER had a window handle");
            return false;
        }

        if (msg.wParam != timer_id)
        {
            puts("WM_TIMER timer id mismatch");
            return false;
        }

        return true;
    }

    bool test_handle_tag_bits()
    {
        using nt_close_t = LONG(NTAPI*)(HANDLE);
        const auto nt_close =
            reinterpret_cast<nt_close_t>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose")));
        if (!nt_close)
        {
            puts("ntdll!NtClose not found");
            return false;
        }

        const auto open_file = [](const char* path) {
            return CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        };

        const auto is_open = [](const HANDLE file) {
            char byte{};
            DWORD read{};
            return ReadFile(file, &byte, sizeof(byte), &read, nullptr) != FALSE;
        };

        bool valid = true;

        for (uint32_t tag = 0; tag < 4; ++tag)
        {
            const HANDLE before = open_file(R"(C:\Windows\System32\ntdll.dll)");
            const HANDLE target = open_file(R"(C:\Windows\System32\kernel32.dll)");
            const HANDLE after = open_file(R"(C:\Windows\System32\kernelbase.dll)");

            if (before == INVALID_HANDLE_VALUE || target == INVALID_HANDLE_VALUE || after == INVALID_HANDLE_VALUE)
            {
                puts("Failed to open the probe files");
                return false;
            }

            auto* const tagged = reinterpret_cast<HANDLE>((reinterpret_cast<ULONG_PTR>(target) & ~ULONG_PTR{3}) | tag);
            const auto status = nt_close(tagged);

            if (status != 0 || !is_open(before) || is_open(target) || !is_open(after))
            {
                printf("NtClose(%p) with tag %u did not close exactly %p (status 0x%08lX)\n", tagged, tag, target, status);
                valid = false;
                CloseHandle(target);
            }

            CloseHandle(before);
            CloseHandle(after);
        }

        return valid;
    }

    bool test_gdi()
    {
        const wchar_t* cursor_path = L"C:\\Windows\\Cursors\\aero_arrow.cur";

        const auto attrs = GetFileAttributesW(cursor_path);
        if (attrs == INVALID_FILE_ATTRIBUTES)
        {
            puts("aero_arrow.cur does not exist");
            return false;
        }

        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            puts("aero_arrow.cur is not a file");
            return false;
        }

        const HCURSOR cursor = LoadCursorFromFileW(cursor_path);
        if (!cursor)
        {
            puts("LoadCursorFromFileW failed to load aero_arrow.cur");
            return false;
        }

        DestroyCursor(cursor);
        return true;
    }

    namespace
    {
        INT_PTR CALLBACK dialog_table_proc(const HWND hwnd, const UINT msg, const WPARAM wp, const LPARAM lp)
        {
            (void)hwnd;
            (void)msg;
            (void)wp;
            (void)lp;
            return FALSE;
        }
    }

    bool test_dialog_table()
    {
        alignas(DWORD) static const std::array<uint8_t, 28> template_bytes = {
            0x00, 0x00, 0xC8, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x64, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        const HWND hwnd = CreateDialogIndirectParamW(GetModuleHandleW(nullptr), reinterpret_cast<const DLGTEMPLATE*>(template_bytes.data()),
                                                     nullptr, dialog_table_proc, 0);
        if (!hwnd)
        {
            puts("CreateDialogIndirectParamW failed");
            return false;
        }

        DestroyWindow(hwnd);
        return true;
    }

    bool test_bcrypt_hash()
    {
        struct hash_vector
        {
            const wchar_t* algorithm;
            std::vector<UCHAR> digest;
        };

        const std::array<hash_vector, 2> vectors{{
            {.algorithm = BCRYPT_MD5_ALGORITHM,
             .digest = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72}},
            {.algorithm = BCRYPT_SHA256_ALGORITHM,
             .digest = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}},
        }};

        std::array<UCHAR, 3> input{'a', 'b', 'c'};

        for (const auto& vector : vectors)
        {
            BCRYPT_ALG_HANDLE algorithm{};
            const auto open_status = BCryptOpenAlgorithmProvider(&algorithm, vector.algorithm, nullptr, 0);
            if (!BCRYPT_SUCCESS(open_status))
            {
                printf("BCryptOpenAlgorithmProvider(%ls) failed: 0x%08lX\n", vector.algorithm, open_status);
                return false;
            }

            const auto close_algorithm = sogen::utils::finally([&] { BCryptCloseAlgorithmProvider(algorithm, 0); });

            std::vector<UCHAR> digest(vector.digest.size());
            const auto hash_status = BCryptHash(algorithm, nullptr, 0, input.data(), static_cast<ULONG>(input.size()), digest.data(),
                                                static_cast<ULONG>(digest.size()));
            if (!BCRYPT_SUCCESS(hash_status) || digest != vector.digest)
            {
                printf("BCryptHash(%ls) failed: 0x%08lX\n", vector.algorithm, hash_status);
                return false;
            }
        }

        return true;
    }

    bool test_crypt_protect()
    {
        auto roundtrip = [](const std::vector<BYTE>& plain, const std::vector<BYTE>& entropy, const LPCWSTR descr) {
            DATA_BLOB input{};
            BYTE empty{};
            input.cbData = static_cast<DWORD>(plain.size());
            // crypt32 returns ERROR_INVALID_PARAMETER when pbData is NULL, including cbData == 0.
            input.pbData = plain.empty() ? &empty : const_cast<BYTE*>(plain.data());

            DATA_BLOB entropy_blob{};
            DATA_BLOB* entropy_ptr = nullptr;
            if (!entropy.empty())
            {
                entropy_blob.cbData = static_cast<DWORD>(entropy.size());
                entropy_blob.pbData = const_cast<BYTE*>(entropy.data());
                entropy_ptr = &entropy_blob;
            }

            DATA_BLOB protected_blob{};
            if (!CryptProtectData(&input, descr, entropy_ptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &protected_blob))
            {
                printf("CryptProtectData failed: %lu\n", GetLastError());
                return false;
            }

            const auto free_protected = sogen::utils::finally([&] { LocalFree(protected_blob.pbData); });

            LPWSTR out_descr = nullptr;
            DATA_BLOB unprotected{};
            if (!CryptUnprotectData(&protected_blob, descr ? &out_descr : nullptr, entropy_ptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                                    &unprotected))
            {
                printf("CryptUnprotectData failed: %lu\n", GetLastError());
                return false;
            }

            const auto free_unprotected = sogen::utils::finally([&] { LocalFree(unprotected.pbData); });
            const auto free_descr = sogen::utils::finally([&] { LocalFree(out_descr); });

            if (unprotected.cbData != input.cbData)
            {
                puts("CryptUnprotectData length mismatch");
                return false;
            }

            if (input.cbData != 0 && memcmp(unprotected.pbData, input.pbData, input.cbData) != 0)
            {
                puts("CryptUnprotectData data mismatch");
                return false;
            }

            if (descr)
            {
                if (!out_descr || wcscmp(out_descr, descr) != 0)
                {
                    puts("CryptUnprotectData description mismatch");
                    return false;
                }
            }

            return true;
        };

        if (!roundtrip({}, {}, nullptr))
        {
            return false;
        }

        if (!roundtrip({0x61, 0x62, 0x63}, {}, nullptr))
        {
            return false;
        }

        if (!roundtrip({0x61, 0x62, 0x63}, {0x01, 0x02, 0x03, 0x04}, nullptr))
        {
            return false;
        }

        if (!roundtrip({0x61, 0x62, 0x63}, {}, L"sogen-test"))
        {
            return false;
        }

        return true;
    }

    bool test_set_dib_bits_to_device()
    {
        constexpr int width = 4;
        constexpr int height = 1;

        struct
        {
            BITMAPINFOHEADER header;
            std::array<RGBQUAD, 4> colors;
        } info{};

        info.header.biSize = sizeof(BITMAPINFOHEADER);
        info.header.biWidth = width;
        info.header.biHeight = -height;
        info.header.biPlanes = 1;
        info.header.biCompression = BI_RGB;
        info.header.biClrUsed = 4;
        info.colors[0] = {.rgbBlue = 0, .rgbGreen = 0, .rgbRed = 255, .rgbReserved = 0};
        info.colors[1] = {.rgbBlue = 0, .rgbGreen = 255, .rgbRed = 0, .rgbReserved = 0};
        info.colors[2] = {.rgbBlue = 255, .rgbGreen = 0, .rgbRed = 0, .rgbReserved = 0};
        info.colors[3] = {.rgbBlue = 255, .rgbGreen = 255, .rgbRed = 255, .rgbReserved = 0};

        const std::array<COLORREF, 4> palette = {RGB(255, 0, 0), RGB(0, 255, 0), RGB(0, 0, 255), RGB(255, 255, 255)};

        struct dib
        {
            WORD bpp;
            std::array<uint8_t, 8> bits;
            std::array<uint8_t, width> expected_index;
        };

        const std::array<dib, 4> dibs = {
            dib{.bpp = 1, .bits = {0x50}, .expected_index = {0, 1, 0, 1}},
            dib{.bpp = 4, .bits = {0x01, 0x23}, .expected_index = {0, 1, 2, 3}},
            dib{.bpp = 8, .bits = {0, 1, 2, 3}, .expected_index = {0, 1, 2, 3}},
            dib{.bpp = 16, .bits = {0x00, 0x7C, 0xE0, 0x03, 0x1F, 0x00, 0xFF, 0x7F}, .expected_index = {0, 1, 2, 3}},
        };

        const HDC dc = CreateCompatibleDC(nullptr);
        const HBITMAP bitmap = CreateBitmap(width, height, 1, 32, nullptr);
        const HGDIOBJ previous = SelectObject(dc, bitmap);
        const auto cleanup = sogen::utils::finally([&] {
            SelectObject(dc, previous);
            DeleteObject(bitmap);
            DeleteDC(dc);
        });

        for (const auto& d : dibs)
        {
            info.header.biBitCount = d.bpp;
            for (int x = 0; x < width; ++x)
            {
                SetPixel(dc, x, 0, RGB(0, 0, 0));
            }

            const int copied = SetDIBitsToDevice(dc, 0, 0, width, height, 0, 0, 0, height, d.bits.data(),
                                                 reinterpret_cast<const BITMAPINFO*>(&info), DIB_RGB_COLORS);
            if (copied != height)
            {
                printf("SetDIBitsToDevice(%ubpp) copied %d scanlines\n", d.bpp, copied);
                return false;
            }

            for (int x = 0; x < width; ++x)
            {
                const COLORREF actual = GetPixel(dc, x, 0);
                const COLORREF expected = palette[d.expected_index[x]];
                if (actual != expected)
                {
                    printf("SetDIBitsToDevice(%ubpp) pixel %d is %06lX, expected %06lX\n", d.bpp, x, static_cast<unsigned long>(actual),
                           static_cast<unsigned long>(expected));
                    return false;
                }
            }
        }

        return true;
    }

    bool test_console_write()
    {
        auto* const output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode{};
        if (!GetConsoleMode(output, &mode))
        {
            return true;
        }

        constexpr std::wstring_view wide_text = L"[console] ";
        DWORD written{};
        if (!WriteConsoleW(output, wide_text.data(), static_cast<DWORD>(wide_text.size()), &written, nullptr) ||
            written != wide_text.size())
        {
            return false;
        }

        constexpr std::string_view text = "[console] ";
        written = 0;
        return WriteConsoleA(output, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) && written == text.size();
    }

    bool test_anonymous_pipe()
    {
        HANDLE read_end{};
        HANDLE write_end{};
        if (!CreatePipe(&read_end, &write_end, nullptr, 0))
        {
            return false;
        }

        HANDLE duplicate{};
        auto* const current_process = GetCurrentProcess();
        const auto duplicated = DuplicateHandle(current_process, write_end, current_process, &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);
        const auto closed_write_end = CloseHandle(write_end);
        const auto closed_duplicate = duplicated && CloseHandle(duplicate);
        const auto closed_read_end = CloseHandle(read_end);
        return duplicated && closed_write_end && closed_duplicate && closed_read_end;
    }

    // Data written to one end of a pipe is read at the other; a non-blocking read of an empty pipe fails with
    // ERROR_NO_DATA, and once the write end is closed, reads report the end of the data (ERROR_BROKEN_PIPE).
    bool test_pipe_data()
    {
        HANDLE read_end{};
        HANDLE write_end{};
        if (!CreatePipe(&read_end, &write_end, nullptr, 0))
        {
            return false;
        }

        const auto close_read_end = sogen::utils::finally([&] { CloseHandle(read_end); });
        auto close_write_end = sogen::utils::finally([&] { CloseHandle(write_end); });

        DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        std::array<char, 16> buffer{};
        DWORD transferred{};
        if (!SetNamedPipeHandleState(read_end, &mode, nullptr, nullptr) ||
            ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), &transferred, nullptr) || GetLastError() != ERROR_NO_DATA)
        {
            puts("Non-blocking read of an empty pipe did not fail with ERROR_NO_DATA");
            return false;
        }

        DWORD state{};
        if (!GetNamedPipeHandleStateW(read_end, &state, nullptr, nullptr, nullptr, nullptr, 0) || !(state & PIPE_NOWAIT))
        {
            puts("Pipe state lost PIPE_NOWAIT");
            return false;
        }

        constexpr std::string_view message = "pipe data";
        if (!WriteFile(write_end, message.data(), static_cast<DWORD>(message.size()), &transferred, nullptr) ||
            transferred != message.size() || !ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), &transferred, nullptr) ||
            std::string_view(buffer.data(), transferred) != message)
        {
            puts("Pipe data did not arrive at the read end");
            return false;
        }

        close_write_end.cancel();
        CloseHandle(write_end);
        if (ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), &transferred, nullptr) ||
            GetLastError() != ERROR_BROKEN_PIPE)
        {
            puts("Read of a pipe without a write end did not report its end");
            return false;
        }

        return true;
    }

    // A client open needs a server instance without a client: no such pipe is not found, and a busy one is busy.
    bool test_pipe_open()
    {
        const auto name = L"\\\\.\\pipe\\sogen-open-test-" + std::to_wstring(GetCurrentProcessId());
        const auto open_client = [&](const std::wstring& pipe) {
            return CreateFileW(pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        };

        auto* const missing = open_client(name + L"-missing");
        const auto missing_error = GetLastError();

        auto* const server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        if (server == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        auto* const first = open_client(name);
        auto* const second = open_client(name);
        const auto second_error = GetLastError();
        // The pipe allows one instance.
        auto* const extra = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        const auto extra_error = GetLastError();

        CloseHandle(extra);
        CloseHandle(second);
        CloseHandle(first);
        CloseHandle(server);

        if (missing != INVALID_HANDLE_VALUE || missing_error != ERROR_FILE_NOT_FOUND || first == INVALID_HANDLE_VALUE ||
            second != INVALID_HANDLE_VALUE || second_error != ERROR_PIPE_BUSY || extra != INVALID_HANDLE_VALUE ||
            extra_error != ERROR_PIPE_BUSY)
        {
            printf("Pipe open: missing error %lu, first ok %d, second error %lu, extra instance error %lu\n", missing_error,
                   first != INVALID_HANDLE_VALUE, second_error, extra_error);
            return false;
        }

        return true;
    }

    // ConnectNamedPipe waits for a client (overlapped: pending until one opens the pipe; blocking: in its thread), reports
    // one that is there already, and DisconnectNamedPipe drops the client so the next one can connect.
    bool test_pipe_connect()
    {
        const auto name = L"\\\\.\\pipe\\sogen-connect-test-" + std::to_wstring(GetCurrentProcessId());
        const auto open_client = [&] {
            return CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        };

        auto* const server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096,
                                              4096, 0, nullptr);
        auto* const event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (server == INVALID_HANDLE_VALUE || !event)
        {
            return false;
        }

        OVERLAPPED overlapped{};
        overlapped.hEvent = event;
        const auto pending = !ConnectNamedPipe(server, &overlapped) && GetLastError() == ERROR_IO_PENDING;
        const auto waited_before_client = WaitForSingleObject(event, 0) == WAIT_TIMEOUT;
        auto* const client = open_client();
        DWORD transferred{};
        const auto connected = GetOverlappedResult(server, &overlapped, &transferred, TRUE);
        overlapped = {};
        overlapped.hEvent = event;
        const auto already = !ConnectNamedPipe(server, &overlapped) && GetLastError() == ERROR_PIPE_CONNECTED;

        DWORD count{};
        const auto client_wrote = WriteFile(client, "ping", 4, &count, nullptr);
        const auto disconnected = DisconnectNamedPipe(server);
        const auto write_after_disconnect = WriteFile(client, "ping", 4, &count, nullptr);
        CloseHandle(client);
        CloseHandle(event);
        // The pipe allows one instance: close it before the next one.
        CloseHandle(server);

        if (!pending || !waited_before_client || !connected || !already || !client_wrote || !disconnected || write_after_disconnect)
        {
            printf("Pipe connect: pending %d, waited %d, connected %d, already %d, wrote %d, disconnected %d, write after %d\n", pending,
                   waited_before_client, connected, already, client_wrote, disconnected, write_after_disconnect);
            return false;
        }

        // A blocking ConnectNamedPipe returns once another thread opened the pipe.
        auto* const blocking = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        if (blocking == INVALID_HANDLE_VALUE)
        {
            printf("Pipe blocking connect: create error %lu\n", GetLastError());
            return false;
        }

        HANDLE second_client = INVALID_HANDLE_VALUE;
        std::thread opener([&] {
            Sleep(10);
            second_client = open_client();
        });
        const auto blocking_connected = ConnectNamedPipe(blocking, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED;
        opener.join();
        const auto opened = second_client != INVALID_HANDLE_VALUE;
        CloseHandle(second_client);
        CloseHandle(blocking);

        if (!blocking_connected || !opened)
        {
            printf("Pipe blocking connect: connected %d, opened %d\n", blocking_connected, opened);
            return false;
        }

        return true;
    }

    // A non-blocking write that does not fit in the room left in the pipe's buffer writes nothing (also in byte mode);
    // once a read made room it fits again.
    bool test_pipe_quota()
    {
        HANDLE read_end{};
        HANDLE write_end{};
        if (!CreatePipe(&read_end, &write_end, nullptr, 0))
        {
            return false;
        }
        const auto close_ends = sogen::utils::finally([&] {
            CloseHandle(read_end);
            CloseHandle(write_end);
        });

        DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        SetNamedPipeHandleState(write_end, &mode, nullptr, nullptr);

        // The default buffer holds 4096 bytes; a write that does not fit writes nothing (also in byte mode).
        const std::vector<char> data(64 * 1024, 'q');
        DWORD too_big = 1;
        DWORD fits = 0;
        DWORD no_room = 1;
        const auto wrote = WriteFile(write_end, data.data(), static_cast<DWORD>(data.size()), &too_big, nullptr) &&
                           WriteFile(write_end, data.data(), 4000, &fits, nullptr) &&
                           WriteFile(write_end, data.data(), 200, &no_room, nullptr);

        std::vector<char> buffer(data.size());
        DWORD read{};
        ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr);
        DWORD after_read{};
        const auto wrote_after_read = WriteFile(write_end, data.data(), 200, &after_read, nullptr);

        if (!wrote || too_big != 0 || fits != 4000 || no_room != 0 || read != 4000 || !wrote_after_read || after_read != 200)
        {
            printf("Pipe quota: too big %lu, fits %lu, no room %lu, read %lu, after read %lu\n", too_big, fits, no_room, read, after_read);
            return false;
        }

        // A pipe can seek to its end (CPython's open(fd, 'a')).
        LARGE_INTEGER end{.QuadPart = -1};
        if (!SetFilePointerEx(write_end, {}, &end, FILE_END) || end.QuadPart != 0)
        {
            printf("Pipe seek to end: %lld, error %lu\n", end.QuadPart, GetLastError());
            return false;
        }

        return true;
    }

    // A blocking read of an empty pipe waits for the other end to write, and then for it to close; an overlapped read
    // is pending until the data arrives.
    bool test_pipe_waits()
    {
        HANDLE read_end{};
        HANDLE write_end{};
        if (!CreatePipe(&read_end, &write_end, nullptr, 0))
        {
            return false;
        }

        const auto close_read_end = sogen::utils::finally([&] { CloseHandle(read_end); });
        auto close_write_end = sogen::utils::finally([&] { CloseHandle(write_end); });

        constexpr std::string_view message = "late data";
        std::atomic_bool wrote{false};
        // Pauses wait on an event nothing signals (the Python bindings test expects Sleep only with 0 or 1).
        auto* const never = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const auto close_never = sogen::utils::finally([&] { CloseHandle(never); });
        std::thread writer([&] {
            WaitForSingleObject(never, 50);
            wrote = true;
            DWORD written{};
            WriteFile(write_end, message.data(), static_cast<DWORD>(message.size()), &written, nullptr);
            WaitForSingleObject(never, 50);
            close_write_end.cancel();
            CloseHandle(write_end);
        });

        std::array<char, 16> buffer{};
        DWORD transferred{};
        const auto first = ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), &transferred, nullptr);
        const auto first_was_late = wrote.load();
        const auto second = ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr, nullptr);
        const auto second_error = GetLastError();
        writer.join();

        if (!first || !first_was_late || std::string_view(buffer.data(), transferred) != message)
        {
            puts("Blocking pipe read did not wait for the data");
            return false;
        }
        if (second || second_error != ERROR_BROKEN_PIPE)
        {
            puts("Blocking pipe read did not wait for the write end to close");
            return false;
        }

        const auto name = L"\\\\.\\pipe\\sogen-test-pipe-waits-" + std::to_wstring(GetCurrentProcessId());
        auto* const server =
            CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 64, 64, 0, nullptr);
        if (server == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const auto close_server = sogen::utils::finally([&] { CloseHandle(server); });

        auto* const client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (client == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const auto close_client = sogen::utils::finally([&] { CloseHandle(client); });

        auto* const event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const auto close_event = sogen::utils::finally([&] { CloseHandle(event); });
        OVERLAPPED overlapped{};
        overlapped.hEvent = event;
        if (ReadFile(server, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr, &overlapped) ||
            GetLastError() != ERROR_IO_PENDING || WaitForSingleObject(event, 0) != WAIT_TIMEOUT)
        {
            puts("Overlapped read of an empty pipe was not pending");
            return false;
        }

        DWORD written{};
        if (!WriteFile(client, message.data(), static_cast<DWORD>(message.size()), &written, nullptr) ||
            !GetOverlappedResult(server, &overlapped, &transferred, TRUE) || std::string_view(buffer.data(), transferred) != message)
        {
            puts("Overlapped pipe read did not complete with the data");
            return false;
        }

        return true;
    }

    bool test_directory_name_collision()
    {
        // Several identical instances of this sample may run in one directory at once, so the check uses this
        // executable, which exists throughout and which no instance deletes.
        std::array<wchar_t, MAX_PATH> executable{};
        GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        return !CreateDirectoryW(executable.data(), nullptr) && GetLastError() == ERROR_ALREADY_EXISTS;
    }

    // Where a test creates files, followed by a separator. Several instances of this sample can run in one directory
    // at once: natively their process ids differ (tests add them to names), and the emulator tests give each emulated
    // instance (all with one process id) its own C:\sogen-test-scratch.
    std::wstring scratch_directory()
    {
        const auto scratch = GetFileAttributesW(L"C:\\sogen-test-scratch");
        return scratch != INVALID_FILE_ATTRIBUTES && (scratch & FILE_ATTRIBUTE_DIRECTORY) ? L"C:\\sogen-test-scratch\\" : L"";
    }

    // Opens refuse what other handles of the file do not share: deleting a file held without FILE_SHARE_DELETE,
    // writing one held without FILE_SHARE_WRITE.
    bool test_file_sharing()
    {
        const auto path = scratch_directory() + L"Shared" + std::to_wstring(GetCurrentProcessId()) + L".txt";
        auto* const held = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
        if (held == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        auto close_held = sogen::utils::finally([&] { CloseHandle(held); });
        const auto cleanup = sogen::utils::finally([&] { DeleteFileW(path.c_str()); });

        if (DeleteFileW(path.c_str()) || GetLastError() != ERROR_SHARING_VIOLATION)
        {
            puts("Deleted a file another handle holds without FILE_SHARE_DELETE");
            return false;
        }

        auto* const writer =
            CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (writer != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION)
        {
            if (writer != INVALID_HANDLE_VALUE)
            {
                CloseHandle(writer);
            }
            puts("Opened for writing a file another handle holds without FILE_SHARE_WRITE");
            return false;
        }

        // Reading is shared, and an open that neither reads, writes, nor deletes never conflicts.
        auto* const reader =
            CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        auto* const attributes = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        const auto opened = reader != INVALID_HANDLE_VALUE && attributes != INVALID_HANDLE_VALUE;
        if (reader != INVALID_HANDLE_VALUE)
        {
            CloseHandle(reader);
        }
        if (attributes != INVALID_HANDLE_VALUE)
        {
            CloseHandle(attributes);
        }
        if (!opened)
        {
            puts("Refused a compatible open");
            return false;
        }

        close_held.cancel();
        CloseHandle(held);
        return DeleteFileW(path.c_str()) != FALSE;
    }

    // Created and renamed entries keep the case they were given. Sogen on a case-sensitive host (Linux, macOS)
    // stores names in lower case, which this accepts too; on Windows hosts and natively the case must match exactly.
    bool test_created_name_case()
    {
        const auto leaf = L"NameCase" + std::to_wstring(GetCurrentProcessId());
        const auto directory = scratch_directory() + leaf;
        const auto file = directory + L"\\Inner.Py";
        const auto renamed = directory + L"\\Renamed.TXT";

        const auto to_lower = [](std::wstring text) {
            std::ranges::transform(text, text.begin(), [](const wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
            return text;
        };
        const auto spelled = [&](const std::wstring& found, const std::wstring& expected) {
            return found == expected || found == to_lower(expected);
        };
        const auto list = [](const std::wstring& pattern) {
            std::vector<std::wstring> names{};
            WIN32_FIND_DATAW data{};
            auto* const search = FindFirstFileW(pattern.c_str(), &data);
            if (search == INVALID_HANDLE_VALUE)
            {
                return names;
            }
            do
            {
                if (wcscmp(data.cFileName, L".") != 0 && wcscmp(data.cFileName, L"..") != 0)
                {
                    names.emplace_back(data.cFileName);
                }
            } while (FindNextFileW(search, &data));
            FindClose(search);
            return names;
        };

        if (!CreateDirectoryW(directory.c_str(), nullptr))
        {
            return false;
        }

        const auto cleanup = sogen::utils::finally([&] {
            DeleteFileW(file.c_str());
            DeleteFileW(renamed.c_str());
            RemoveDirectoryW(directory.c_str());
        });

        auto* const handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        CloseHandle(handle);

        // Creating below a missing directory, or below a file, fails with a missing path.
        for (const auto& below : {directory + L"\\Missing\\New.txt", file + L"\\New.txt"})
        {
            auto* const created = CreateFileW(below.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (created != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PATH_NOT_FOUND)
            {
                if (created != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(created);
                }
                puts("Created a file below a missing directory or a file");
                return false;
            }
        }

        const auto directories = list(directory);
        auto files = list(directory + L"\\*");
        if (directories.size() != 1 || !spelled(directories[0], leaf) || files.size() != 1 || !spelled(files[0], L"Inner.Py"))
        {
            puts("Created names lost their case");
            return false;
        }

        if (!MoveFileW(file.c_str(), renamed.c_str()))
        {
            return false;
        }

        files = list(directory + L"\\*");
        if (files.size() != 1 || !spelled(files[0], L"Renamed.TXT"))
        {
            puts("Renamed file lost its case");
            return false;
        }

        // A directory cannot move below itself.
        const auto below_itself = directory + L"\\Sub";
        if (MoveFileW(directory.c_str(), below_itself.c_str()) || GetLastError() != ERROR_INVALID_PARAMETER)
        {
            puts("Moved a directory below itself");
            return false;
        }

        return true;
    }

    bool test_file_ids_by_name()
    {
        // FILE_STAT_BASIC_INFORMATION; older SDKs lack it and GetFileInformationByName.
        struct stat_basic_information
        {
            LARGE_INTEGER FileId;
            LARGE_INTEGER CreationTime;
            LARGE_INTEGER LastAccessTime;
            LARGE_INTEGER LastWriteTime;
            LARGE_INTEGER ChangeTime;
            LARGE_INTEGER AllocationSize;
            LARGE_INTEGER EndOfFile;
            ULONG FileAttributes;
            ULONG ReparseTag;
            ULONG NumberOfLinks;
            ULONG DeviceType;
            ULONG DeviceCharacteristics;
            ULONG Reserved;
            LARGE_INTEGER VolumeSerialNumber;
            std::array<uint8_t, 16> FileId128;
        };

        using get_file_information_by_name_t = BOOL(WINAPI*)(PCWSTR, int, PVOID, ULONG);
        const auto get_file_information_by_name = reinterpret_cast<get_file_information_by_name_t>(
            GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "GetFileInformationByName"));
        if (!get_file_information_by_name)
        {
            return true;
        }

        constexpr int file_stat_basic_by_name_info = 3;
        const auto query = [&](const HMODULE module, stat_basic_information& info) {
            std::array<wchar_t, MAX_PATH> path{};
            GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
            return get_file_information_by_name(path.data(), file_stat_basic_by_name_info, &info, sizeof(info));
        };

        stat_basic_information executable{};
        stat_basic_information kernel32{};
        return query(nullptr, executable) && query(GetModuleHandleW(L"kernel32.dll"), kernel32) && executable.FileId.QuadPart != 0 &&
               executable.FileId.QuadPart != kernel32.FileId.QuadPart && executable.FileId128 != kernel32.FileId128;
    }

    bool test_device_file_types()
    {
        HANDLE read_end{};
        HANDLE write_end{};
        if (!CreatePipe(&read_end, &write_end, nullptr, 0))
        {
            return false;
        }

        auto* const null_device = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        const auto cleanup = sogen::utils::finally([&] {
            CloseHandle(read_end);
            CloseHandle(write_end);
            CloseHandle(null_device);
        });

        return null_device != INVALID_HANDLE_VALUE && GetFileType(read_end) == FILE_TYPE_PIPE && GetFileType(null_device) == FILE_TYPE_CHAR;
    }

    std::vector<uint8_t> query_token_information(const HANDLE token, const TOKEN_INFORMATION_CLASS information_class)
    {
        DWORD length = 0;
        if (GetTokenInformation(token, information_class, nullptr, 0, &length) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            return {};
        }

        std::vector<uint8_t> buffer(length);
        if (!GetTokenInformation(token, information_class, buffer.data(), length, &length))
        {
            return {};
        }

        return buffer;
    }

    // Privilege names and values through LSA, and enabling a held privilege (shutdown, which every interactive user
    // holds) while one no user holds (create token) stays unassigned.
    bool test_privileges()
    {
        LUID shutdown{};
        std::array<wchar_t, 64> name{};
        auto name_length = static_cast<DWORD>(name.size());
        std::array<wchar_t, 128> display_name{};
        auto display_length = static_cast<DWORD>(display_name.size());
        DWORD language{};
        LUID change_notify{.LowPart = 23, .HighPart = 0};
        if (!LookupPrivilegeValueW(nullptr, L"seshutdownprivilege", &shutdown) || shutdown.LowPart != 19 || shutdown.HighPart != 0 ||
            !LookupPrivilegeNameW(nullptr, &change_notify, name.data(), &name_length) ||
            std::wstring_view(name.data()) != L"SeChangeNotifyPrivilege" ||
            !LookupPrivilegeDisplayNameW(nullptr, L"SeShutdownPrivilege", display_name.data(), &display_length, &language) ||
            display_length == 0)
        {
            puts("Privilege lookups failed");
            return false;
        }

        LUID unknown{};
        if (LookupPrivilegeValueW(nullptr, L"SeNoSuchPrivilege", &unknown) || GetLastError() != ERROR_NO_SUCH_PRIVILEGE)
        {
            puts("Looked up a privilege that does not exist");
            return false;
        }

        HANDLE token{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            return false;
        }
        const auto close_token = sogen::utils::finally([&] { CloseHandle(token); });

        const auto shutdown_enabled = [&] {
            const auto data = query_token_information(token, TokenPrivileges);
            const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(data.data());
            for (DWORD i = 0; data.size() >= sizeof(TOKEN_PRIVILEGES) && i < privileges->PrivilegeCount; ++i)
            {
                if (privileges->Privileges[i].Luid.LowPart == shutdown.LowPart && privileges->Privileges[i].Luid.HighPart == 0)
                {
                    return (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                }
            }
            return false;
        };

        TOKEN_PRIVILEGES enable{.PrivilegeCount = 1, .Privileges = {{.Luid = shutdown, .Attributes = SE_PRIVILEGE_ENABLED}}};
        TOKEN_PRIVILEGES previous{};
        DWORD previous_length{};
        if (!AdjustTokenPrivileges(token, FALSE, &enable, sizeof(previous), &previous, &previous_length) ||
            GetLastError() != ERROR_SUCCESS || !shutdown_enabled())
        {
            puts("Enabling a held privilege failed");
            return false;
        }

        AdjustTokenPrivileges(token, FALSE, &previous, 0, nullptr, nullptr);
        if (shutdown_enabled())
        {
            puts("Restoring a privilege's previous state failed");
            return false;
        }

        TOKEN_PRIVILEGES create_token{.PrivilegeCount = 1,
                                      .Privileges = {{.Luid = {.LowPart = 2, .HighPart = 0}, .Attributes = SE_PRIVILEGE_ENABLED}}};
        if (!AdjustTokenPrivileges(token, FALSE, &create_token, 0, nullptr, nullptr) || GetLastError() != ERROR_NOT_ALL_ASSIGNED)
        {
            puts("Enabled a privilege the token does not hold");
            return false;
        }

        return true;
    }

    bool test_token_information()
    {
        HANDLE token{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            return false;
        }
        const auto close_token = sogen::utils::finally([&] { CloseHandle(token); });

        // SE_CHANGE_NOTIFY_PRIVILEGE from wdm.h; every user token holds it, enabled.
        constexpr DWORD change_notify_privilege = 23;
        const auto privileges_data = query_token_information(token, TokenPrivileges);
        if (privileges_data.size() < sizeof(TOKEN_PRIVILEGES))
        {
            return false;
        }

        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(privileges_data.data());
        bool change_notify_enabled = false;
        for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
        {
            const auto& privilege = privileges->Privileges[i];
            if (privilege.Luid.LowPart == change_notify_privilege && privilege.Luid.HighPart == 0)
            {
                change_notify_enabled = (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0;
            }
        }

        const auto claims_data = query_token_information(token, TokenUserClaimAttributes);
        return change_notify_enabled && claims_data.size() >= sizeof(CLAIM_SECURITY_ATTRIBUTES_INFORMATION) &&
               reinterpret_cast<const CLAIM_SECURITY_ATTRIBUTES_INFORMATION*>(claims_data.data())->Version ==
                   CLAIM_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1;
    }

    bool test_high_resolution_timer()
    {
        auto* const timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        if (!timer)
        {
            return false;
        }

        const auto close_timer = sogen::utils::finally([&] { CloseHandle(timer); });

        LARGE_INTEGER due_time{};
        due_time.QuadPart = -10000;
        return SetWaitableTimerEx(timer, &due_time, 0, nullptr, nullptr, nullptr, 0) && WaitForSingleObject(timer, 5000) == WAIT_OBJECT_0;
    }

    bool test_waitable_timer_semantics(const DWORD flags)
    {
        const auto manual_reset = (flags & CREATE_WAITABLE_TIMER_MANUAL_RESET) != 0;
        auto* const timer = CreateWaitableTimerExW(nullptr, nullptr, flags, TIMER_ALL_ACCESS);
        if (!timer)
        {
            return false;
        }

        const auto close_timer = sogen::utils::finally([&] { CloseHandle(timer); });

        // An unset timer is not signaled, and one due in a minute does not expire early.
        LARGE_INTEGER due_time{};
        due_time.QuadPart = -600'000'000;
        if (WaitForSingleObject(timer, 0) != WAIT_TIMEOUT || !SetWaitableTimer(timer, &due_time, 0, nullptr, nullptr, FALSE) ||
            WaitForSingleObject(timer, 20) != WAIT_TIMEOUT)
        {
            puts("Timer signaled before its due time");
            return false;
        }

        // A cancelled timer never fires.
        due_time.QuadPart = -10'000;
        if (!SetWaitableTimer(timer, &due_time, 0, nullptr, nullptr, FALSE) || !CancelWaitableTimer(timer) ||
            WaitForSingleObject(timer, 20) != WAIT_TIMEOUT)
        {
            puts("Cancelled timer signaled");
            return false;
        }

        // Synchronization timers release one wait; notification timers stay signaled.
        if (!SetWaitableTimer(timer, &due_time, 0, nullptr, nullptr, FALSE) || WaitForSingleObject(timer, 5000) != WAIT_OBJECT_0)
        {
            puts("Timer did not signal");
            return false;
        }

        if (WaitForSingleObject(timer, 0) != (manual_reset ? WAIT_OBJECT_0 : WAIT_TIMEOUT))
        {
            puts("Timer kept the wrong signal state after a wait");
            return false;
        }

        return true;
    }

    bool test_waitable_timers()
    {
        if (!test_waitable_timer_semantics(0) || !test_waitable_timer_semantics(CREATE_WAITABLE_TIMER_MANUAL_RESET) ||
            !test_waitable_timer_semantics(CREATE_WAITABLE_TIMER_HIGH_RESOLUTION) ||
            !test_waitable_timer_semantics(CREATE_WAITABLE_TIMER_MANUAL_RESET | CREATE_WAITABLE_TIMER_HIGH_RESOLUTION))
        {
            return false;
        }

        // A periodic timer re-arms and queues its completion routine to the setting thread.
        auto* const timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
        if (!timer)
        {
            return false;
        }

        const auto close_timer = sogen::utils::finally([&] { CloseHandle(timer); });

        int apc_count = 0;
        const PTIMERAPCROUTINE on_timer = [](void* context, DWORD, DWORD) { ++*static_cast<int*>(context); };

        // The period must outlast running the routine: under the emulator's relative clock an instruction takes a
        // millisecond, and a timer that is due again whenever its APC returns starves the thread (as on Windows).
        LARGE_INTEGER due_time{};
        due_time.QuadPart = -10'000;
        if (!SetWaitableTimer(timer, &due_time, 500, on_timer, &apc_count, FALSE))
        {
            return false;
        }

        for (int i = 0; i < 100 && apc_count < 3; ++i)
        {
            SleepEx(1000, TRUE);
        }

        CancelWaitableTimer(timer);
        if (apc_count < 3)
        {
            puts("Periodic timer did not run its completion routine");
            return false;
        }

        // Thread pool timers wait on a timer through a wait completion packet.
        auto* const fired = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!fired)
        {
            return false;
        }

        const auto close_event = sogen::utils::finally([&] { CloseHandle(fired); });

        auto* pool_timer =
            CreateThreadpoolTimer([](PTP_CALLBACK_INSTANCE, void* context, PTP_TIMER) { SetEvent(context); }, fired, nullptr);
        if (!pool_timer)
        {
            return false;
        }

        FILETIME pool_due_time{};
        pool_due_time.dwLowDateTime = static_cast<DWORD>(-10'000);
        pool_due_time.dwHighDateTime = static_cast<DWORD>(-1);
        SetThreadpoolTimer(pool_timer, &pool_due_time, 0, 0);

        const auto result = WaitForSingleObject(fired, 5000);
        if (result != WAIT_OBJECT_0)
        {
            puts("Thread pool timer did not fire");
        }
        SetThreadpoolTimer(pool_timer, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(pool_timer, TRUE);
        CloseThreadpoolTimer(pool_timer);

        return result == WAIT_OBJECT_0;
    }

    struct long_callback_state
    {
        HANDLE release_first{};
        LONG may_run_long_count{};
        LONG finished{};
    };

    // A callback that announces it may run long (NtReleaseWorkerFactoryWorker) lets other work proceed, here the
    // work item it waits for.
    bool test_thread_pool_long_callbacks()
    {
        constexpr LONG rounds = 5;

        long_callback_state state{};
        state.release_first = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!state.release_first)
        {
            return false;
        }

        const auto close_event = sogen::utils::finally([&] { CloseHandle(state.release_first); });

        auto* const waiter = CreateThreadpoolWork(
            [](PTP_CALLBACK_INSTANCE instance, void* context, PTP_WORK) {
                auto& s = *static_cast<long_callback_state*>(context);
                if (CallbackMayRunLong(instance))
                {
                    InterlockedIncrement(&s.may_run_long_count);
                }

                // Long enough for a new worker to start under the emulator's relative clock, where an instruction
                // takes a millisecond.
                if (WaitForSingleObject(s.release_first, 100'000) == WAIT_OBJECT_0)
                {
                    InterlockedIncrement(&s.finished);
                }
            },
            &state, nullptr);

        auto* const releaser = CreateThreadpoolWork(
            [](PTP_CALLBACK_INSTANCE instance, void* context, PTP_WORK) {
                auto& s = *static_cast<long_callback_state*>(context);
                CallbackMayRunLong(instance);
                SetEvent(s.release_first);
            },
            &state, nullptr);

        if (!waiter || !releaser)
        {
            return false;
        }

        for (LONG i = 0; i < rounds; ++i)
        {
            ResetEvent(state.release_first);
            SubmitThreadpoolWork(waiter);
            SubmitThreadpoolWork(releaser);
            WaitForThreadpoolWorkCallbacks(waiter, FALSE);
            WaitForThreadpoolWorkCallbacks(releaser, FALSE);
        }

        CloseThreadpoolWork(waiter);
        CloseThreadpoolWork(releaser);

        if (state.finished != rounds)
        {
            printf("%ld of %ld long callbacks finished\n", state.finished, rounds);
            return false;
        }

        return state.may_run_long_count > 0;
    }

    // Handle flags read back as set, DUPLICATE_CLOSE_SOURCE leaves the handle count as it was, and file times set with
    // SetFileTime read back.
    bool test_handles_and_file_times()
    {
        auto* const event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event)
        {
            return false;
        }

        DWORD flags{};
        if (!GetHandleInformation(event, &flags) || flags != 0 || !SetHandleInformation(event, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
            !GetHandleInformation(event, &flags) || flags != HANDLE_FLAG_INHERIT)
        {
            CloseHandle(event);
            puts("Handle flags did not read back");
            return false;
        }

        const auto handle_count = [] {
            DWORD count{};
            GetProcessHandleCount(GetCurrentProcess(), &count);
            return count;
        };

        const auto before = handle_count();
        HANDLE moved{};
        auto* const current_process = GetCurrentProcess();
        if (!DuplicateHandle(current_process, event, current_process, &moved, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE) ||
            handle_count() != before)
        {
            puts("DUPLICATE_CLOSE_SOURCE did not close the source");
            return false;
        }
        CloseHandle(moved);

        const auto path = scratch_directory() + L"Times" + std::to_wstring(GetCurrentProcessId()) + L".txt";
        auto* const file =
            CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const auto close_file = sogen::utils::finally([&] { CloseHandle(file); });

        // 2001-02-03 04:05:06.7 UTC.
        constexpr uint64_t time_value = 126257475067000000;
        const FILETIME time{.dwLowDateTime = static_cast<DWORD>(time_value), .dwHighDateTime = static_cast<DWORD>(time_value >> 32)};
        if (!SetFileTime(file, nullptr, &time, &time))
        {
            puts("SetFileTime failed");
            return false;
        }

        // With relative time the emulator reports every file time as 2023-11-14 00:00 UTC, so there is nothing to read back.
        constexpr uint64_t deterministic_value = 133444736000000000;
        FILETIME creation{};
        FILETIME access{};
        FILETIME write{};
        if (!GetFileTime(file, &creation, &access, &write))
        {
            return false;
        }
        if (((static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime) == deterministic_value)
        {
            return true;
        }
        if (CompareFileTime(&write, &time) != 0 || CompareFileTime(&access, &time) != 0)
        {
            puts("File times did not read back");
            return false;
        }

        return true;
    }

    // Win32 paths drop a trailing space or dot from their last component, \\?\ paths keep it: "dir " and "dir." are other
    // names than "dir" there.
    bool test_trailing_space_paths()
    {
        const auto relative = scratch_directory() + L"Trail" + std::to_wstring(GetCurrentProcessId());
        std::array<wchar_t, MAX_PATH> full{};
        if (!GetFullPathNameW(relative.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr))
        {
            return false;
        }

        const std::wstring directory = full.data();
        if (!CreateDirectoryW(directory.c_str(), nullptr))
        {
            return false;
        }
        const auto remove_directory = sogen::utils::finally([&] { RemoveDirectoryW(directory.c_str()); });

        const auto exists = [](const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; };
        const auto extended = L"\\\\?\\" + directory;
        if (!exists(directory + L" ") || !exists(directory + L".") || !exists(extended))
        {
            puts("Win32 paths with a trailing space or dot did not find the directory");
            return false;
        }
        if (exists(extended + L" ") || exists(extended + L"."))
        {
            puts("Extended-length paths with a trailing space or dot found the directory");
            return false;
        }

        return true;
    }

    // A thread's description reads back as it was set, including from another thread through a handle.
    bool test_thread_description()
    {
        PWSTR initial{};
        if (FAILED(GetThreadDescription(GetCurrentThread(), &initial)))
        {
            return false;
        }
        LocalFree(initial);

        bool success = false;
        std::thread([&] {
            const wchar_t* const name = L"Sogen Worker";
            if (FAILED(SetThreadDescription(GetCurrentThread(), name)))
            {
                return;
            }

            PWSTR description{};
            if (SUCCEEDED(GetThreadDescription(GetCurrentThread(), &description)))
            {
                success = description && std::wstring_view(name) == description;
                LocalFree(description);
            }
        }).join();

        return success;
    }

    bool test_stack_guarantee()
    {
        bool success = false;
        std::thread([&] {
            ULONG initial = 0;
            ULONG requested = 0x10000;
            ULONG current = 0;
            success = SetThreadStackGuarantee(&initial) && initial == 0 && SetThreadStackGuarantee(&requested) &&
                      SetThreadStackGuarantee(&current) && current == 0x10000;
        }).join();
        return success;
    }

    bool test_system_random()
    {
        std::array<uint8_t, 32> first{};
        std::array<uint8_t, 32> second{};
        return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, first.data(), static_cast<ULONG>(first.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
               BCRYPT_SUCCESS(
                   BCryptGenRandom(nullptr, second.data(), static_cast<ULONG>(second.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
               first != second;
    }

    bool test_memory_priority()
    {
        MEMORY_PRIORITY_INFORMATION priority{.MemoryPriority = MEMORY_PRIORITY_NORMAL};
        MEMORY_PRIORITY_INFORMATION queried{};
        return SetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &priority, sizeof(priority)) &&
               !SetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &priority, sizeof(priority) + 1) &&
               GetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &queried, sizeof(queried)) &&
               queried.MemoryPriority == MEMORY_PRIORITY_NORMAL;
    }

    bool test_oem_conversion()
    {
        const char* const text = "Sogen /? 123";
        std::array<char, 32> oem{};
        std::array<char, 32> ansi{};
        return CharToOemA(text, oem.data()) && std::string_view(oem.data()) == text && OemToCharA(oem.data(), ansi.data()) &&
               std::string_view(ansi.data()) == text;
    }
}

#define RUN_TEST(func, name)                 \
    {                                        \
        printf("Running test '" name "': "); \
        const auto res = func();             \
        valid &= res;                        \
        puts(res ? "Success" : "Fail");      \
    }

int main(const int argc, const char* argv[])
{
    if (argc == 2 && argv[1] == "-time"sv)
    {
        print_time();
        return 0;
    }

    if (argc == 2 && argv[1] == "-fail-fast"sv)
    {
        EXCEPTION_RECORD record{};
        record.ExceptionCode = 0xE0001234;
        RaiseFailFastException(&record, nullptr, 0);
    }

    bool valid = true;

#ifdef _WIN64
    RUN_TEST(test_dns, "DNS")
#endif
    RUN_TEST(test_io, "I/O")
    RUN_TEST(test_file_locking, "File Locking")
    RUN_TEST(test_dir_io, "Dir I/O")
    RUN_TEST(test_apis, "APIs")
    RUN_TEST(test_console_write, "Console Write")
    RUN_TEST(test_oem_conversion, "OEM Conversion")
    RUN_TEST(test_anonymous_pipe, "Anonymous Pipe")
    RUN_TEST(test_pipe_data, "Pipe Data")
    RUN_TEST(test_pipe_waits, "Pipe Waits")
    RUN_TEST(test_pipe_quota, "Pipe Quota")
    RUN_TEST(test_pipe_open, "Pipe Open")
    RUN_TEST(test_pipe_connect, "Pipe Connect")
    RUN_TEST(test_device_file_types, "Device File Types")
    RUN_TEST(test_file_ids_by_name, "File IDs by Name")
    RUN_TEST(test_directory_name_collision, "Directory Name Collision")
    RUN_TEST(test_created_name_case, "Created Name Case")
    RUN_TEST(test_file_sharing, "File Sharing")
    RUN_TEST(test_token_information, "Token Information")
    RUN_TEST(test_privileges, "Privileges")
    RUN_TEST(test_lsa_policy, "LSA Policy")
    RUN_TEST(test_lsa_authentication_packages, "LSA Authentication Packages")
    RUN_TEST(test_memory_priority, "Memory Priority")
    RUN_TEST(test_system_random, "System Random")
    RUN_TEST(test_stack_guarantee, "Stack Guarantee")
    RUN_TEST(test_thread_description, "Thread Description")
    RUN_TEST(test_handles_and_file_times, "Handle Flags and File Times")
    RUN_TEST(test_trailing_space_paths, "Trailing Space Paths")
    RUN_TEST(test_high_resolution_timer, "High Resolution Timer")
    RUN_TEST(test_waitable_timers, "Waitable Timers")
    RUN_TEST(test_thread_pool_long_callbacks, "Thread Pool Long Callbacks")
#ifdef _WIN64
    RUN_TEST(test_working_directory, "Working Directory")
#endif
    RUN_TEST(test_registry, "Registry")
    RUN_TEST(test_registry_deletion, "Registry Deletion")
    RUN_TEST(test_case_mapping, "Case Mapping")
    RUN_TEST(test_volume_path, "Volume Path")
    RUN_TEST(test_drives_and_volumes, "Drives and Volumes")
    RUN_TEST(test_replace_refusals, "Replace Refusals")
    RUN_TEST(test_read_only_and_final_names, "Read-Only and Final Names")
    RUN_TEST(test_read_after_write, "Read After Write")
    RUN_TEST(test_file_mappings, "File Mappings")
    RUN_TEST(test_environment_and_names, "Environment and Names")
    RUN_TEST(test_reparse_points, "Reparse Points")
    RUN_TEST(test_app_execution_alias, "App Execution Alias")
    RUN_TEST(test_system_info, "System Info")
    RUN_TEST(test_monitor_info, "Monitor Info")
    RUN_TEST(test_time_zone, "Time Zone")
    RUN_TEST(test_threads, "Threads")
    RUN_TEST(test_threads_winapi, "Threads WinAPI")
    RUN_TEST(test_env, "Environment")
    RUN_TEST(test_lookup_account_sid, "LSA")
    RUN_TEST(test_exceptions, "Exceptions")
#ifndef __MINGW64__
    RUN_TEST(test_native_exceptions, "Native Exceptions")
#endif
    if (!getenv("EMULATOR_ICICLE"))
    {
        RUN_TEST(test_interrupts, "Interrupts")
    }
    RUN_TEST(test_tls, "TLS")
    RUN_TEST(test_socket, "Socket")
    RUN_TEST(test_apc, "APC")
    RUN_TEST(test_window_geometry, "Window Geometry")
    RUN_TEST(test_user_callback, "User Callback")
    RUN_TEST(test_mutable_callbacks, "Mutable User Callback")
    RUN_TEST(test_message_queue, "Message Queue (General)")
    RUN_TEST(test_paint_message_queue, "Message Queue (Paint)")
    RUN_TEST(test_settimer, "User Timer")
    RUN_TEST(test_private_namespace, "Private Namespace")
    RUN_TEST(test_handle_tag_bits, "Handle Tag Bits")
    RUN_TEST(test_actctx, "Activation Context")
    RUN_TEST(test_mmio, "MMIO")
    RUN_TEST(test_gdi, "GDI")
    RUN_TEST(test_dialog_table, "Dialog Table")
    RUN_TEST(test_bcrypt_hash, "BCrypt Hash")
    RUN_TEST(test_crypt_protect, "CryptProtect")
    RUN_TEST(test_set_dib_bits_to_device, "GDI DIB")

    return valid ? 0 : 1;
}
