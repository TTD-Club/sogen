#include "../std_include.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

#include <limits>

namespace sogen
{

    namespace syscalls
    {
        namespace
        {
            constexpr uint32_t token_authentication_id = 0x1000;
            constexpr uint32_t token_id = 0x1001;
            constexpr uint32_t token_modified_id = 0x1002;
            constexpr uint32_t token_source_id = 0x1003;
            constexpr uint32_t system_logon_id = 0x3E7;

            struct token_source
            {
                std::array<char, 8> name{};
                uint32_t identifier_low{};
                int32_t identifier_high{};
            };

            struct empty_token_groups
            {
                ULONG group_count{};
                ULONG padding{};
            };

            // TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN
            constexpr ULONG default_mandatory_policy = 0x3;
            // SE_GROUP_LOGON_ID | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            constexpr ULONG logon_sid_attributes = 0xC0000007;

            // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED.
            constexpr uint32_t group_enabled = 0x7;
            constexpr uint32_t group_logon_id = 0xC0000000;
            constexpr uint32_t group_owner = 0x8;
            // SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED.
            constexpr uint32_t group_integrity = 0x60;

            // The binary SID S-1-<authority>-<sub authorities>.
            std::vector<uint8_t> make_sid(const uint8_t authority, const std::initializer_list<uint32_t> sub_authorities)
            {
                std::vector<uint8_t> sid{1, static_cast<uint8_t>(sub_authorities.size()), 0, 0, 0, 0, 0, authority};
                for (const auto sub_authority : sub_authorities)
                {
                    const auto* bytes = reinterpret_cast<const uint8_t*>(&sub_authority);
                    sid.insert(sid.end(), bytes, bytes + sizeof(sub_authority));
                }
                return sid;
            }

            struct token_group
            {
                std::vector<uint8_t> sid{};
                uint32_t attributes{};
            };

            // The groups of a medium-integrity local user's token, in Windows' order: the account domain's None group
            // (for an S-1-5-21 user), Everyone, BUILTIN\Users, INTERACTIVE, CONSOLE LOGON, Authenticated Users, This
            // Organization, Local account, the logon session, LOCAL, NTLM Authentication, and the integrity label. An
            // elevated token also holds BUILTIN\Administrators, as its owner, and has high integrity.
            std::vector<token_group> token_groups(const process_context& process, const bool elevated)
            {
                std::vector<token_group> groups{};
                const auto& user = process.sid;
                constexpr uint32_t security_nt_non_unique = 21;
                if (user.size() >= 12 && user[1] >= 2 && user[7] == 5 && user[8] == security_nt_non_unique && user[9] == 0 &&
                    user[10] == 0 && user[11] == 0)
                {
                    // The user's SID with its RID replaced by DOMAIN_GROUP_RID_USERS (513).
                    auto none_group = user;
                    constexpr uint32_t domain_group_rid_users = 513;
                    memcpy(none_group.data() + none_group.size() - sizeof(uint32_t), &domain_group_rid_users, sizeof(uint32_t));
                    groups.push_back({.sid = std::move(none_group), .attributes = group_enabled});
                }

                groups.push_back({.sid = make_sid(1, {0}), .attributes = group_enabled});
                if (elevated)
                {
                    groups.push_back({.sid = make_sid(5, {32, 544}), .attributes = group_enabled | group_owner});
                }
                groups.push_back({.sid = make_sid(5, {32, 545}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(5, {4}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(2, {1}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(5, {11}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(5, {15}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(5, {113}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(5, {5, 0, token_authentication_id}), .attributes = group_enabled | group_logon_id});
                groups.push_back({.sid = make_sid(2, {0}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(5, {64, 10}), .attributes = group_enabled});
                groups.push_back({.sid = make_sid(16, {elevated ? 0x3000u : 0x2000u}), .attributes = group_integrity});
                return groups;
            }

            struct token_privilege
            {
                LUID Luid;
                DWORD Attributes;
            };

            static_assert(sizeof(token_privilege) == 12);

            constexpr DWORD privilege_enabled = 0x2;
            constexpr DWORD privilege_removed = 0x4;
            constexpr NTSTATUS status_not_all_assigned = 0x00000106;

            // The token's privileges (process_context::token_privileges) as LUID_AND_ATTRIBUTES entries.
            std::vector<token_privilege> held_privileges(const process_context& process)
            {
                std::vector<token_privilege> privileges{};
                privileges.reserve(process.token_privileges.size());
                for (const auto& [luid, attributes] : process.token_privileges)
                {
                    privileges.push_back({.Luid = {.LowPart = luid, .HighPart = 0}, .Attributes = attributes});
                }
                return privileges;
            }

            constexpr std::array<uint8_t, 12> anonymous_sid{1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0};

            // Windows 11 26200 answers classes up to 0x3A, past the last one TOKEN_INFORMATION_CLASS names.
            constexpr ULONG last_token_information_class = 0x3A;

            handle resolve_token(const syscall_context& c, const handle token)
            {
                if (token == CURRENT_THREAD_TOKEN || token == CURRENT_THREAD_EFFECTIVE_TOKEN)
                {
                    const auto impersonation = c.vcpu.active_thread ? c.vcpu.active_thread->impersonation_token : handle{};
                    if (impersonation != 0 || token == CURRENT_THREAD_TOKEN)
                    {
                        return impersonation;
                    }
                    return CURRENT_PROCESS_TOKEN;
                }
                return token;
            }

            bool sid_matches(const memory_manager& memory, const uint64_t address, const std::span<const uint8_t> expected)
            {
                std::array<uint8_t, 8> header{};
                memory.read_memory(address, header.data(), header.size());
                const auto size = 8 + static_cast<size_t>(header[1]) * sizeof(uint32_t);
                if (size != expected.size())
                {
                    return false;
                }

                std::vector<uint8_t> sid(size);
                memory.read_memory(address, sid.data(), sid.size());
                return std::ranges::equal(sid, expected);
            }

            ACCESS_MASK map_generic_access(ACCESS_MASK access, const EMU_GENERIC_MAPPING& mapping)
            {
                constexpr ACCESS_MASK generic_read = 0x80000000;
                constexpr ACCESS_MASK generic_write = 0x40000000;
                constexpr ACCESS_MASK generic_execute = 0x20000000;
                constexpr ACCESS_MASK generic_all = 0x10000000;

                if (access & generic_read)
                {
                    access = (access & ~generic_read) | mapping.GenericRead;
                }
                if (access & generic_write)
                {
                    access = (access & ~generic_write) | mapping.GenericWrite;
                }
                if (access & generic_execute)
                {
                    access = (access & ~generic_execute) | mapping.GenericExecute;
                }
                if (access & generic_all)
                {
                    access = (access & ~generic_all) | mapping.GenericAll;
                }
                return access;
            }
        }

        TOKEN_TYPE get_token_type(const handle token_handle)
        {
            const auto impersonation = token_handle == DUMMY_IMPERSONATION_TOKEN || token_handle == ANONYMOUS_IMPERSONATION_TOKEN;
            return impersonation ? TokenImpersonation : TokenPrimary;
        }

        NTSTATUS handle_NtDuplicateToken(const syscall_context& c, const handle requested_token, ACCESS_MASK /*desired_access*/,
                                         const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>>
                                         /*object_attributes*/,
                                         const BOOLEAN /*effective_only*/, const TOKEN_TYPE type,
                                         const emulator_object<handle> new_token_handle)
        {
            const auto existing_token_handle = resolve_token(c, requested_token);
            if (existing_token_handle != CURRENT_PROCESS_TOKEN && existing_token_handle != DUMMY_IMPERSONATION_TOKEN &&
                existing_token_handle != ANONYMOUS_IMPERSONATION_TOKEN)
            {
                return existing_token_handle != 0 ? STATUS_INVALID_HANDLE : STATUS_NO_TOKEN;
            }
            if (type != TokenPrimary && type != TokenImpersonation)
            {
                return STATUS_INVALID_PARAMETER;
            }
            if (existing_token_handle == ANONYMOUS_IMPERSONATION_TOKEN && type == TokenPrimary)
            {
                return STATUS_NOT_SUPPORTED;
            }
            if (get_token_type(existing_token_handle) == type)
            {
                new_token_handle.write(existing_token_handle);
            }
            else if (type == TokenPrimary)
            {
                new_token_handle.write(CURRENT_PROCESS_TOKEN);
            }
            else
            {
                new_token_handle.write(DUMMY_IMPERSONATION_TOKEN);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtQueryInformationToken(const syscall_context& c, const handle requested_token,
                                                const TOKEN_INFORMATION_CLASS token_information_class, const uint64_t token_information,
                                                const ULONG token_information_length, const emulator_object<ULONG> return_length)
        {
            if (token_information_class < TokenUser || static_cast<ULONG>(token_information_class) > last_token_information_class)
            {
                c.win_emu.log.error("Unsupported NtQueryInformationToken info class: 0x%X\n",
                                    static_cast<uint32_t>(token_information_class));
                return STATUS_INVALID_INFO_CLASS;
            }

            const auto token_handle = resolve_token(c, requested_token);
            if (token_handle == 0 && requested_token == CURRENT_THREAD_TOKEN)
            {
                return STATUS_NO_TOKEN;
            }
            if (token_handle != CURRENT_PROCESS_TOKEN && token_handle != CURRENT_THREAD_TOKEN &&
                token_handle != CURRENT_THREAD_EFFECTIVE_TOKEN && token_handle != DUMMY_IMPERSONATION_TOKEN &&
                token_handle != ANONYMOUS_IMPERSONATION_TOKEN)
            {
                return STATUS_NOT_SUPPORTED;
            }

            if (token_information_class == TokenAppContainerSid)
            {
                constexpr auto required_size = sizeof(EmulatorTraits<Emu64>::PVOID);
                return_length.write_if_valid(required_size);
                if (token_information_length < required_size)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                emulator_object<EmulatorTraits<Emu64>::PVOID>{c.emu, token_information}.write(0);
                return STATUS_SUCCESS;
            }

            const auto anonymous = token_handle == ANONYMOUS_IMPERSONATION_TOKEN;
            const auto sid = anonymous ? std::span<const uint8_t>{anonymous_sid} : std::span<const uint8_t>{c.proc.sid};

            if (anonymous && token_information_class == TokenPrivileges)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);
                if (token_information_length < required_size)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                emulator_object<ULONG>{c.emu, token_information}.write(0);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenUser)
            {
                const auto required_size = sizeof(TOKEN_USER64) + sid.size();
                return_length.write(static_cast<ULONG>(required_size));

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_USER64 user{};
                user.User.Attributes = 0;
                user.User.Sid = token_information + sizeof(TOKEN_USER64);

                emulator_object<TOKEN_USER64>{c.emu, token_information}.write(user);
                c.emu.write_memory(token_information + sizeof(TOKEN_USER64), sid.data(), sid.size());
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenGroups)
            {
                if (anonymous)
                {
                    return_length.write(sizeof(ULONG));
                    if (token_information_length < sizeof(ULONG))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                    c.emu.write_memory(token_information, ULONG{0});
                    return STATUS_SUCCESS;
                }

                // TOKEN_GROUPS: the count, the SID_AND_ATTRIBUTES entries, then the SIDs they point to.
                const auto groups = token_groups(c.proc, c.win_emu.runs_elevated());
                const auto entries_offset = offsetof(TOKEN_GROUPS64, Groups);
                auto required_size = entries_offset + groups.size() * sizeof(SID_AND_ATTRIBUTES64);
                for (const auto& group : groups)
                {
                    required_size += group.sid.size();
                }
                return_length.write(static_cast<ULONG>(required_size));

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                c.emu.write_memory(token_information, static_cast<ULONG>(groups.size()));
                auto sid_address = token_information + entries_offset + groups.size() * sizeof(SID_AND_ATTRIBUTES64);
                for (size_t i = 0; i < groups.size(); ++i)
                {
                    const SID_AND_ATTRIBUTES64 entry{.Sid = sid_address, .Attributes = groups[i].attributes};
                    c.emu.write_memory(token_information + entries_offset + i * sizeof(SID_AND_ATTRIBUTES64), entry);
                    c.emu.write_memory(sid_address, groups[i].sid.data(), groups[i].sid.size());
                    sid_address += groups[i].sid.size();
                }
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenPrivileges)
            {
                const auto privileges = held_privileges(c.proc);
                const auto privileges_size = privileges.size() * sizeof(token_privilege);
                const auto required_size = sizeof(DWORD) + privileges_size;
                return_length.write(static_cast<ULONG>(required_size));

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                c.emu.write_memory(token_information, static_cast<DWORD>(privileges.size()));
                c.emu.write_memory(token_information + sizeof(DWORD), privileges.data(), privileges_size);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenOwner)
            {
                const auto required_size = sizeof(TOKEN_OWNER64) + sid.size();
                return_length.write(static_cast<ULONG>(required_size));

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_OWNER64 owner{};
                owner.Owner = token_information + sizeof(TOKEN_OWNER64);

                emulator_object<TOKEN_OWNER64>{c.emu, token_information}.write(owner);
                c.emu.write_memory(token_information + sizeof(TOKEN_OWNER64), sid.data(), sid.size());
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenPrimaryGroup)
            {
                const auto required_size = sizeof(TOKEN_PRIMARY_GROUP64) + sid.size();
                return_length.write(static_cast<ULONG>(required_size));

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_PRIMARY_GROUP64 primary_group{};
                primary_group.PrimaryGroup = token_information + sizeof(TOKEN_PRIMARY_GROUP64);

                emulator_object<TOKEN_PRIMARY_GROUP64>{c.emu, token_information}.write(primary_group);
                c.emu.write_memory(token_information + sizeof(TOKEN_PRIMARY_GROUP64), sid.data(), sid.size());
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenDefaultDacl)
            {
                const auto acl_size = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sid.size() - sizeof(ULONG);
                const auto required_size = sizeof(TOKEN_DEFAULT_DACL64) + acl_size;
                return_length.write(static_cast<ULONG>(required_size));

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_DEFAULT_DACL64 default_dacl{};
                default_dacl.DefaultDacl = token_information + sizeof(TOKEN_DEFAULT_DACL64);

                emulator_object<TOKEN_DEFAULT_DACL64>{c.emu, token_information}.write(default_dacl);

                const auto acl_offset = token_information + sizeof(TOKEN_DEFAULT_DACL64);
                ACL acl{};
                acl.AclRevision = 2; // ACL_REVISION
                acl.Sbz1 = 0;
                acl.AclSize = static_cast<USHORT>(acl_size);
                acl.AceCount = 1;
                acl.Sbz2 = 0;

                c.emu.write_memory(acl_offset, acl);

                const auto ace_offset = acl_offset + sizeof(ACL);
                ACCESS_ALLOWED_ACE ace{};
                ace.Header.AceType = 0; // ACCESS_ALLOWED_ACE_TYPE
                ace.Header.AceFlags = 0;
                ace.Header.AceSize = static_cast<USHORT>(sizeof(ACCESS_ALLOWED_ACE) + sid.size() - sizeof(ULONG));
                ace.Mask = GENERIC_ALL;

                c.emu.write_memory(ace_offset, ace);

                const auto sid_offset = ace_offset + sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG);
                c.emu.write_memory(sid_offset, sid.data(), sid.size());

                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenType)
            {
                constexpr auto required_size = sizeof(TOKEN_TYPE);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                emulator_object<TOKEN_TYPE>{c.emu, token_information}.write(get_token_type(token_handle));
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenImpersonationLevel)
            {
                if (get_token_type(token_handle) != TokenImpersonation)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                constexpr auto required_size = sizeof(SECURITY_IMPERSONATION_LEVEL);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto level = anonymous ? SecurityAnonymous : SecurityImpersonation;
                emulator_object<SECURITY_IMPERSONATION_LEVEL>{c.emu, token_information}.write(level);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenSessionId)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                emulator_object<ULONG>{c.emu, token_information}.write(1);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenPrivateNameSpace)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                emulator_object<ULONG>{c.emu, token_information}.write(0);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenUIAccess)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                emulator_object<ULONG>{c.emu, token_information}.write(1);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenElevation)
            {
                constexpr auto required_size = sizeof(TOKEN_ELEVATION);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                c.emu.write_memory(token_information, TOKEN_ELEVATION{
                                                          .TokenIsElevated = !anonymous && c.win_emu.runs_elevated() ? 1u : 0u,
                                                      });
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenElevationType)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                // TokenElevationTypeDefault: no UAC split token, as for the built-in Administrator (RID 500) the token
                // belongs to.
                emulator_object<ULONG>{c.emu, token_information}.write(1);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenSandBoxInert || token_information_class == TokenHasRestrictions ||
                token_information_class == TokenIsAppContainer || token_information_class == TokenIsAppSilo)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                emulator_object<ULONG>{c.emu, token_information}.write(0);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenIsSandboxed || token_information_class == TokenIsAppSilo)
            {
                constexpr auto required_size = sizeof(ULONG);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                emulator_object<ULONG>{c.emu, token_information}.write(0);
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenStatistics)
            {
                constexpr auto required_size = sizeof(TOKEN_STATISTICS);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                // NOLINTNEXTLINE(bugprone-invalid-enum-default-initialization)
                TOKEN_STATISTICS stats{};
                stats.TokenId.LowPart = token_id;
                stats.AuthenticationId.LowPart = token_authentication_id;
                stats.ExpirationTime.QuadPart = std::numeric_limits<LONGLONG>::max();
                stats.TokenType = get_token_type(token_handle);
                stats.ImpersonationLevel = !anonymous && stats.TokenType == TokenImpersonation ? SecurityImpersonation : SecurityAnonymous;
                stats.GroupCount = anonymous ? 0 : static_cast<DWORD>(token_groups(c.proc, c.win_emu.runs_elevated()).size());
                stats.PrivilegeCount = anonymous ? 0 : static_cast<DWORD>(c.proc.token_privileges.size());
                stats.ModifiedId.LowPart = token_modified_id;

                c.emu.write_memory(token_information, stats);

                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenUserClaimAttributes || token_information_class == TokenDeviceClaimAttributes ||
                token_information_class == TokenSecurityAttributes || token_information_class == TokenSingletonAttributes)
            {
                constexpr auto required_size = sizeof(TOKEN_SECURITY_ATTRIBUTES_INFORMATION);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                constexpr USHORT token_security_attributes_information_version_v1 = 1;
                c.emu.write_memory(token_information, TOKEN_SECURITY_ATTRIBUTES_INFORMATION{
                                                          .Version = token_security_attributes_information_version_v1,
                                                          .Reserved = {},
                                                          .AttributeCount = 0,
                                                          .Attribute = {},
                                                      });

                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenIntegrityLevel)
            {
                // S-1-16-8192 (medium) or S-1-16-12288 (high)
                std::array<uint8_t, 20> integrity_sid = {
                    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                };
                if (!anonymous && c.win_emu.runs_elevated())
                {
                    integrity_sid[9] = 0x30;
                }

                constexpr auto required_size = sizeof(integrity_sid) + sizeof(TOKEN_MANDATORY_LABEL64);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_MANDATORY_LABEL64 label{};
                label.Label.Attributes = 0x60;
                label.Label.Sid = token_information + sizeof(TOKEN_MANDATORY_LABEL64);

                emulator_object<TOKEN_MANDATORY_LABEL64>{c.emu, token_information}.write(label);
                c.emu.write_memory(token_information + sizeof(TOKEN_MANDATORY_LABEL64), integrity_sid.data(), integrity_sid.size());
                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenProcessTrustLevel)
            {
                constexpr auto required_size = sizeof(TOKEN_PROCESS_TRUST_LEVEL64);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                c.emu.write_memory(token_information, TOKEN_PROCESS_TRUST_LEVEL64{
                                                          .TrustLevelSid = 0,
                                                      });

                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenBnoIsolation)
            {
                constexpr auto required_size = sizeof(TOKEN_BNO_ISOLATION_INFORMATION64);
                return_length.write(required_size);

                if (required_size > token_information_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_BNO_ISOLATION_INFORMATION64 info{};
                memset(&info, 0, sizeof(info));
                info.IsolationPrefix = 0;
                info.IsolationEnabled = FALSE;
                c.emu.write_memory(token_information, info);

                return STATUS_SUCCESS;
            }

            if (token_information_class == TokenSessionReference || token_information_class == TokenRestrictedUserClaimAttributes ||
                token_information_class == TokenRestrictedDeviceClaimAttributes || token_information_class == TokenRestrictedDeviceGroups ||
                token_information_class == TokenChildProcessFlags || token_information_class == TokenIsLessPrivilegedAppContainer)
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (token_information_class == TokenAuditPolicy)
            {
                return STATUS_PRIVILEGE_NOT_HELD;
            }

            // The token is not split by UAC (see TokenElevationType), so it has no linked token.
            if (token_information_class == TokenLinkedToken)
            {
                return STATUS_NO_SUCH_LOGON_SESSION;
            }

            const auto write_value = [&](const auto& value) {
                constexpr auto required_size = static_cast<ULONG>(sizeof(value));
                return_length.write(required_size);
                if (token_information_length < required_size)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                c.emu.write_memory(token_information, value);
                return STATUS_SUCCESS;
            };

            switch (token_information_class)
            {
            case TokenSource:
                return write_value(token_source{
                    .name = {'U', 's', 'e', 'r', '3', '2', ' ', '\0'},
                    .identifier_low = token_source_id,
                });
            case TokenOrigin:
                return write_value(LUID{.LowPart = system_logon_id, .HighPart = 0});
            case TokenVirtualizationAllowed:
                return write_value(ULONG{1});
            case TokenVirtualizationEnabled:
            case TokenAppContainerNumber:
            case TokenIsRestricted:
                return write_value(ULONG{0});
            case TokenMandatoryPolicy:
                return write_value(default_mandatory_policy);
            case TokenRestrictedSids:
            case TokenCapabilities:
                return write_value(empty_token_groups{});
            case TokenDeviceGroups:
                return write_value(TOKEN_GROUPS64{});
            default:
                break;
            }

            if (token_information_class == TokenLogonSid)
            {
                // S-1-5-5-X-Y names the logon session whose LUID is X:Y.
                constexpr std::array<uint32_t, 3> sub_authorities{5, 0, token_authentication_id};
                constexpr std::array<uint8_t, 8> sid_header{1, static_cast<uint8_t>(sub_authorities.size()), 0, 0, 0, 0, 0, 5};
                constexpr auto sid_size = sid_header.size() + sizeof(sub_authorities);
                constexpr auto required_size = static_cast<ULONG>(sizeof(TOKEN_GROUPS64) + sid_size);
                return_length.write(required_size);
                if (token_information_length < required_size)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                TOKEN_GROUPS64 groups{};
                groups.GroupCount = 1;
                groups.Groups[0].Sid = token_information + sizeof(TOKEN_GROUPS64);
                groups.Groups[0].Attributes = logon_sid_attributes;

                c.emu.write_memory(token_information, groups);
                c.emu.write_memory(groups.Groups[0].Sid, sid_header);
                c.emu.write_memory(groups.Groups[0].Sid + sid_header.size(), sub_authorities);
                return STATUS_SUCCESS;
            }

            c.win_emu.log.error("Unsupported token info class: %X\n", token_information_class);
            c.emu.stop();
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtAccessCheck(const syscall_context& c, const uint64_t security_descriptor, const handle requested_token,
                                      const ACCESS_MASK desired_access, const emulator_object<EMU_GENERIC_MAPPING> generic_mapping,
                                      const uint64_t /*privilege_set*/, const emulator_object<ULONG> privilege_set_length,
                                      const emulator_object<ACCESS_MASK> granted_access, const emulator_object<NTSTATUS> access_status)
        {
            const auto client_token = resolve_token(c, requested_token);
            if (client_token != CURRENT_PROCESS_TOKEN && client_token != CURRENT_THREAD_TOKEN &&
                client_token != CURRENT_THREAD_EFFECTIVE_TOKEN && client_token != DUMMY_IMPERSONATION_TOKEN &&
                client_token != ANONYMOUS_IMPERSONATION_TOKEN)
            {
                return STATUS_INVALID_HANDLE;
            }

            const auto control = emulator_object<SECURITY_DESCRIPTOR_CONTROL>{c.emu, security_descriptor + 2}.read();
            uint64_t dacl_address = 0;
            if (control & SE_SELF_RELATIVE)
            {
                const auto descriptor = emulator_object<SECURITY_DESCRIPTOR_RELATIVE>{c.emu, security_descriptor}.read();
                dacl_address = descriptor.Dacl == 0 ? 0 : security_descriptor + descriptor.Dacl;
            }
            else
            {
                dacl_address = emulator_object<uint64_t>{c.emu, security_descriptor + 32}.read();
            }

            const auto mapping = generic_mapping.read();
            const auto requested = map_generic_access(desired_access, mapping);
            ACCESS_MASK remaining = requested;
            ACCESS_MASK granted = 0;
            bool denied = false;

            if (!(control & SE_DACL_PRESENT) || dacl_address == 0)
            {
                granted = requested;
                remaining = 0;
            }
            else
            {
                const auto acl = emulator_object<ACL>{c.emu, dacl_address}.read();
                auto ace_address = dacl_address + sizeof(ACL);
                // An ACE applies to the user and to the token's groups (not its integrity label).
                const auto groups = token_groups(c.proc, c.win_emu.runs_elevated());
                const auto applies_to_token = [&](const uint64_t ace_sid) {
                    return sid_matches(c.emu.memory(), ace_sid, c.proc.sid) || std::ranges::any_of(groups, [&](const token_group& group) {
                               return group.attributes != group_integrity && sid_matches(c.emu.memory(), ace_sid, group.sid);
                           });
                };
                for (USHORT i = 0; i < acl.AceCount; ++i)
                {
                    const auto ace = emulator_object<ACCESS_ALLOWED_ACE>{c.emu, ace_address}.read();
                    if (ace.Header.AceSize < sizeof(ACCESS_ALLOWED_ACE))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    const auto ace_mask = map_generic_access(ace.Mask, mapping);
                    const auto ace_sid = ace_address + offsetof(ACCESS_ALLOWED_ACE, SidStart);
                    const auto anonymous = client_token == ANONYMOUS_IMPERSONATION_TOKEN;
                    const auto applies = anonymous ? sid_matches(c.emu.memory(), ace_sid, anonymous_sid) : applies_to_token(ace_sid);
                    if (applies && ace.Header.AceType == 1 && (ace_mask & remaining) != 0)
                    {
                        denied = true;
                        break;
                    }
                    if (applies && ace.Header.AceType == 0)
                    {
                        const auto allowed = ace_mask & remaining;
                        granted |= allowed;
                        remaining &= ~allowed;
                    }
                    ace_address += ace.Header.AceSize;
                }
            }

            privilege_set_length.write(0);
            granted_access.write(granted);
            access_status.write(!denied && remaining == 0 ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtPrivilegeCheck(const syscall_context& c, const handle client_token, const emulator_pointer required_privileges,
                                         const emulator_object<BOOLEAN> result)
        {
            struct privilege_set_header
            {
                ULONG privilege_count;
                ULONG control;
            };

            constexpr ULONG privilege_set_all_necessary = 1;
            constexpr ULONG max_privilege_count = 66;
            constexpr DWORD privilege_used_for_access = 0x80000000;

            if (client_token != CURRENT_PROCESS_TOKEN && client_token != DUMMY_IMPERSONATION_TOKEN &&
                client_token != ANONYMOUS_IMPERSONATION_TOKEN)
            {
                const auto object_handle = c.proc.resolve_object_pseudo_handle(client_token, c.vcpu.active_thread);
                auto* store = c.proc.get_handle_store(object_handle);
                return store && store->get_object(object_handle) ? STATUS_OBJECT_TYPE_MISMATCH : STATUS_INVALID_HANDLE;
            }

            const auto header = emulator_object<privilege_set_header>{c.emu, required_privileges}.try_read();
            if (!header)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            // PRIVILEGE_SET declares one entry, so Windows probes that much even for an empty set.
            const auto probed_entries = std::max<uint64_t>(header->privilege_count, 1);
            const auto set_size = sizeof(privilege_set_header) + (probed_entries * sizeof(token_privilege));
            if (!is_writable_range(c.win_emu.memory, required_privileges, set_size) ||
                !is_writable_range(c.win_emu.memory, result.value(), sizeof(BOOLEAN)))
            {
                return STATUS_ACCESS_VIOLATION;
            }

            if (header->privilege_count > max_privilege_count)
            {
                return STATUS_INVALID_PARAMETER;
            }

            // The impersonation tokens hold no privileges.
            const auto* held = client_token == CURRENT_PROCESS_TOKEN ? &c.proc.token_privileges : nullptr;

            ULONG enabled_count = 0;
            const auto entries = required_privileges + sizeof(privilege_set_header);
            for (ULONG i = 0; i < header->privilege_count; ++i)
            {
                const auto entry_address = entries + (static_cast<uint64_t>(i) * sizeof(token_privilege));
                auto entry = c.emu.read_memory<token_privilege>(entry_address);
                const auto privilege = held && entry.Luid.HighPart == 0 ? held->find(entry.Luid.LowPart) : decltype(held->end()){};
                const auto enabled = held && privilege != held->end() && (privilege->second & privilege_enabled) != 0;
                if (enabled)
                {
                    ++enabled_count;
                    entry.Attributes |= privilege_used_for_access;
                    c.emu.write_memory(entry_address, entry);
                }
            }

            const auto all_necessary = (header->control & privilege_set_all_necessary) != 0;
            const BOOLEAN granted = all_necessary ? enabled_count == header->privilege_count : enabled_count != 0;
            result.write(granted);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtQuerySecurityAttributesToken(const syscall_context& c, const handle token_handle,
                                                       const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> attributes,
                                                       const ULONG number_of_attributes, const uint64_t buffer, const ULONG buffer_length,
                                                       const emulator_object<ULONG> return_length)
        {
            if (token_handle != CURRENT_PROCESS_TOKEN && token_handle != CURRENT_THREAD_TOKEN &&
                token_handle != CURRENT_THREAD_EFFECTIVE_TOKEN && token_handle != DUMMY_IMPERSONATION_TOKEN)
            {
                return STATUS_NOT_SUPPORTED;
            }

            if ((number_of_attributes != 0) != (attributes.value() != 0))
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (number_of_attributes != 0)
            {
                for (ULONG index = 0; index < number_of_attributes; ++index)
                {
                    read_unicode_string(c.emu, attributes, index);
                }
                if (return_length.value())
                {
                    return_length.write(0);
                }
                return STATUS_NOT_FOUND;
            }

            constexpr auto required_size = sizeof(TOKEN_SECURITY_ATTRIBUTES_INFORMATION);
            if (return_length.value())
            {
                return_length.write(required_size);
            }

            if (buffer == 0 || buffer_length < required_size)
            {
                return STATUS_BUFFER_TOO_SMALL;
            }

            c.emu.write_memory(buffer, TOKEN_SECURITY_ATTRIBUTES_INFORMATION{
                                           .Version = 1,
                                           .Reserved = {},
                                           .AttributeCount = 0,
                                           .Attribute = {},
                                       });

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCompareSigningLevels(const syscall_context&, UCHAR, UCHAR)
        {
            return STATUS_NOT_SUPPORTED;
        }

        // Enables, disables, or removes the token's privileges. Changes to privileges the token does not hold are
        // skipped with STATUS_NOT_ALL_ASSIGNED; PreviousState receives the old attributes of what changed.
        NTSTATUS handle_NtAdjustPrivilegesToken(const syscall_context& c, const handle /*token_handle*/, const BOOLEAN disable_all,
                                                const uint64_t new_state, const ULONG previous_state_length, const uint64_t previous_state,
                                                const emulator_object<ULONG> return_length)
        {
            if (!disable_all && !new_state)
            {
                return STATUS_INVALID_PARAMETER;
            }

            auto updated = c.proc.token_privileges;
            std::vector<token_privilege> previous{};
            bool all_assigned = true;

            const auto change = [&](const uint32_t luid, const DWORD attributes) {
                const auto held = updated.find(luid);
                if (held == updated.end())
                {
                    all_assigned = false;
                    return;
                }

                if (attributes & privilege_removed)
                {
                    previous.push_back({.Luid = {.LowPart = luid, .HighPart = 0}, .Attributes = held->second});
                    updated.erase(held);
                    return;
                }

                const auto new_attributes = (held->second & ~privilege_enabled) | (attributes & privilege_enabled);
                if (new_attributes != held->second)
                {
                    previous.push_back({.Luid = {.LowPart = luid, .HighPart = 0}, .Attributes = held->second});
                    held->second = new_attributes;
                }
            };

            if (disable_all)
            {
                for (const auto& [luid, attributes] : c.proc.token_privileges)
                {
                    change(luid, 0);
                }
            }
            else
            {
                const auto count = c.emu.read_memory<DWORD>(new_state);
                for (DWORD i = 0; i < count; ++i)
                {
                    const auto entry = c.emu.read_memory<token_privilege>(new_state + sizeof(DWORD) + i * sizeof(token_privilege));
                    if (entry.Luid.HighPart != 0)
                    {
                        all_assigned = false;
                        continue;
                    }
                    change(entry.Luid.LowPart, entry.Attributes);
                }
            }

            // The previous state must fit before anything changes.
            if (previous_state)
            {
                const auto required_size = static_cast<ULONG>(sizeof(DWORD) + previous.size() * sizeof(token_privilege));
                return_length.write_if_valid(required_size);
                if (required_size > previous_state_length)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                c.emu.write_memory(previous_state, static_cast<DWORD>(previous.size()));
                c.emu.write_memory(previous_state + sizeof(DWORD), previous.data(), previous.size() * sizeof(token_privilege));
            }

            c.proc.token_privileges = std::move(updated);
            return all_assigned ? STATUS_SUCCESS : status_not_all_assigned;
        }

        NTSTATUS handle_NtQuerySecurityPolicy()
        {
            return STATUS_NOT_SUPPORTED;
        }
    }

} // namespace sogen
