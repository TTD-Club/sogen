#include "../std_include.hpp"
#include "lsa_policy_lookup.hpp"

#include "binary_writer.hpp"
#include "../registry/registry_utils.hpp"
#include "../windows_emulator.hpp"

namespace sogen
{

    namespace
    {
        constexpr NTSTATUS k_status_none_mapped = static_cast<NTSTATUS>(0xC0000073);
        constexpr ULONG k_open_policy_reply_size_32 = 0x40;
        constexpr ULONG k_open_policy_reply_size_64 = 0x44;
        constexpr ULONG k_lookup_sids_not_mapped_reply_size = 0x18;
        constexpr ULONG k_lookup_sids_min_success_reply_size_32 = 0xCC;
        constexpr ULONG k_lookup_sids_min_success_reply_size_64 = 0x10C;
        constexpr ULONG k_close_policy_reply_size_32 = 0x40;
        constexpr ULONG k_close_policy_reply_size_64 = 0x44;
        constexpr ULONG k_lookup_account_reply_size_32 = 0xDC;
        constexpr ULONG k_lookup_account_reply_size_64 = 0x11C;
        constexpr ULONG k_get_user_name_reply_size_32 = 0x78;
        constexpr ULONG k_get_user_name_reply_size_64 = 0x8C;

        constexpr uint32_t k_lsa_max_referenced_domains = 0x20;
        constexpr uint32_t k_sid_type_user = 1;
        constexpr uint32_t k_policy_lookup_account_procedure = 3;
        constexpr uint32_t k_sspi_get_user_name_procedure = 15;
        constexpr std::array<uint8_t, 16> k_policy_context_uuid = {
            0xBA, 0xA3, 0xDA, 0x01, 0x6E, 0x16, 0x62, 0x49, 0x81, 0x46, 0x13, 0x9B, 0x8A, 0x70, 0x69, 0xE7,
        };

        // MS-LSAD's lsarpc interface, 12345778-1234-abcd-ef00-0123456789ab, which shares this endpoint with the lookup
        // interface above; its opnums are those of the specification.
        constexpr std::array<uint8_t, 16> k_lsarpc_interface = {
            0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
        };
        constexpr uint32_t k_lsar_close = 0;
        constexpr uint32_t k_lsar_query_information_policy = 7;
        constexpr uint32_t k_lsar_query_information_policy2 = 46;
        // POLICY_INFORMATION_CLASS values the queries answer.
        constexpr uint16_t k_policy_primary_domain_information = 3;
        constexpr uint16_t k_policy_account_domain_information = 5;
        constexpr uint16_t k_policy_dns_domain_information = 12;
        constexpr NTSTATUS k_status_invalid_info_class = static_cast<NTSTATUS>(0xC0000003);
        // The emulated machine is in a workgroup, not a domain.
        constexpr std::u16string_view k_workgroup_name = u"WORKGROUP";
        constexpr uint32_t k_lsar_lookup_privilege_value = 31;
        constexpr uint32_t k_lsar_lookup_privilege_name = 32;
        constexpr uint32_t k_lsar_lookup_privilege_display_name = 33;
        constexpr uint32_t k_lsar_open_policy2 = 44;
        constexpr uint32_t k_lsar_open_policy3 = 130;
        // An LSAPR_HANDLE: attributes and a GUID.
        constexpr size_t k_context_handle_size = 20;
        constexpr NTSTATUS k_status_no_such_privilege = static_cast<NTSTATUS>(0xC0000060);
        constexpr uint16_t k_language_english_united_states = 0x409;

        struct privilege_entry
        {
            uint32_t luid{};
            std::u16string_view name{};
            std::u16string_view display_name{};
        };

        // The privileges every Windows system defines, with their fixed LUIDs (SE_*_PRIVILEGE) and English display names.
        // NOLINTBEGIN(modernize-use-designated-initializers): a table of (LUID, name, display name) rows
        constexpr std::array<privilege_entry, 35> k_privileges = {{
            {2, u"SeCreateTokenPrivilege", u"Create a token object"},
            {3, u"SeAssignPrimaryTokenPrivilege", u"Replace a process level token"},
            {4, u"SeLockMemoryPrivilege", u"Lock pages in memory"},
            {5, u"SeIncreaseQuotaPrivilege", u"Adjust memory quotas for a process"},
            {6, u"SeMachineAccountPrivilege", u"Add workstations to domain"},
            {7, u"SeTcbPrivilege", u"Act as part of the operating system"},
            {8, u"SeSecurityPrivilege", u"Manage auditing and security log"},
            {9, u"SeTakeOwnershipPrivilege", u"Take ownership of files or other objects"},
            {10, u"SeLoadDriverPrivilege", u"Load and unload device drivers"},
            {11, u"SeSystemProfilePrivilege", u"Profile system performance"},
            {12, u"SeSystemtimePrivilege", u"Change the system time"},
            {13, u"SeProfileSingleProcessPrivilege", u"Profile single process"},
            {14, u"SeIncreaseBasePriorityPrivilege", u"Increase scheduling priority"},
            {15, u"SeCreatePagefilePrivilege", u"Create a pagefile"},
            {16, u"SeCreatePermanentPrivilege", u"Create permanent shared objects"},
            {17, u"SeBackupPrivilege", u"Back up files and directories"},
            {18, u"SeRestorePrivilege", u"Restore files and directories"},
            {19, u"SeShutdownPrivilege", u"Shut down the system"},
            {20, u"SeDebugPrivilege", u"Debug programs"},
            {21, u"SeAuditPrivilege", u"Generate security audits"},
            {22, u"SeSystemEnvironmentPrivilege", u"Modify firmware environment values"},
            {23, u"SeChangeNotifyPrivilege", u"Bypass traverse checking"},
            {24, u"SeRemoteShutdownPrivilege", u"Force shutdown from a remote system"},
            {25, u"SeUndockPrivilege", u"Remove computer from docking station"},
            {26, u"SeSyncAgentPrivilege", u"Synchronize directory service data"},
            {27, u"SeEnableDelegationPrivilege", u"Enable computer and user accounts to be trusted for delegation"},
            {28, u"SeManageVolumePrivilege", u"Perform volume maintenance tasks"},
            {29, u"SeImpersonatePrivilege", u"Impersonate a client after authentication"},
            {30, u"SeCreateGlobalPrivilege", u"Create global objects"},
            {31, u"SeTrustedCredManAccessPrivilege", u"Access Credential Manager as a trusted caller"},
            {32, u"SeRelabelPrivilege", u"Modify an object label"},
            {33, u"SeIncreaseWorkingSetPrivilege", u"Increase a process working set"},
            {34, u"SeTimeZonePrivilege", u"Change the time zone"},
            {35, u"SeCreateSymbolicLinkPrivilege", u"Create symbolic links"},
            {36, u"SeDelegateSessionUserImpersonatePrivilege", u"Obtain an impersonation token for another user in the same session"},
        }};

        // NOLINTEND(modernize-use-designated-initializers)

        // Privilege names compare without regard to case, as LSA compares them.
        const privilege_entry* find_privilege(const std::u16string_view name)
        {
            const auto lower = [](const char16_t c) { return utils::string::char_to_lower(c); };
            const auto entry = std::ranges::find_if(
                k_privileges, [&](const privilege_entry& privilege) { return std::ranges::equal(privilege.name, name, {}, lower, lower); });
            return entry == k_privileges.end() ? nullptr : &*entry;
        }

        ULONG select_by_pointer_size(const utils::aligned_binary_writer& writer, const ULONG size_32, const ULONG size_64)
        {
            return writer.pointer_size() == utils::aligned_binary_writer::pointer_size_32 ? size_32 : size_64;
        }

        void pad_to_reply_size(utils::aligned_binary_writer& writer, const ULONG size_32, const ULONG size_64)
        {
            const auto reply_size = static_cast<size_t>(select_by_pointer_size(writer, size_32, size_64));
            const auto offset = static_cast<size_t>(writer.offset());
            if (offset < reply_size)
            {
                writer.pad(reply_size - offset);
            }
        }

        bool request_contains_sid(windows_emulator& win_emu, const lpc_request_context& c, const std::span<const uint8_t> sid)
        {
            if (sid.empty() || c.send_buffer_length < sid.size())
            {
                return false;
            }

            std::vector<uint8_t> request(c.send_buffer_length, 0);
            win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());

            const auto it = std::ranges::search(request, sid);
            return it.begin() != request.end();
        }

        bool is_domain_user_sid(const std::span<const uint8_t> sid)
        {
            if (sid.size() < 12)
            {
                return false;
            }

            const auto sub_authority_count = sid[1];
            if (sub_authority_count < 2 || sid.size() < static_cast<size_t>(8 + (sub_authority_count * sizeof(uint32_t))))
            {
                return false;
            }

            constexpr std::array<uint8_t, 6> nt_authority = {0, 0, 0, 0, 0, 5};
            if (!std::ranges::equal(nt_authority, sid.subspan(2, nt_authority.size())))
            {
                return false;
            }

            uint32_t first_sub_authority{};
            std::memcpy(&first_sub_authority, sid.data() + 8, sizeof(first_sub_authority));
            return first_sub_authority == 21;
        }

        std::vector<uint8_t> derive_account_domain_sid(const std::span<const uint8_t> sid)
        {
            if (!is_domain_user_sid(sid))
            {
                return {sid.begin(), sid.end()};
            }

            std::vector<uint8_t> domain_sid(sid.begin(), sid.end() - sizeof(uint32_t));
            --domain_sid[1];
            return domain_sid;
        }

        constexpr uint32_t k_sid_type_alias = 4;
        constexpr uint32_t k_sid_type_well_known_group = 5;

        // A well-known SID of the NT authority (S-1-5-...) with the name LSA gives it.
        struct well_known_sid
        {
            std::vector<uint32_t> sub_authorities{};
            std::vector<uint32_t> domain_sub_authorities{};
            std::u16string_view domain{};
            std::u16string_view name{};
            uint32_t type{};
        };

        well_known_sid nt_authority_group(const uint32_t rid, const std::u16string_view name)
        {
            return {.sub_authorities = {rid}, .domain = u"NT AUTHORITY", .name = name, .type = k_sid_type_well_known_group};
        }

        well_known_sid builtin_alias(const uint32_t rid, const std::u16string_view name)
        {
            constexpr uint32_t builtin_domain_rid = 32;
            return {.sub_authorities = {builtin_domain_rid, rid},
                    .domain_sub_authorities = {builtin_domain_rid},
                    .domain = u"BUILTIN",
                    .name = name,
                    .type = k_sid_type_alias};
        }

        const std::array<well_known_sid, 9> k_well_known_sids = {
            nt_authority_group(2, u"NETWORK"),
            nt_authority_group(4, u"INTERACTIVE"),
            nt_authority_group(11, u"Authenticated Users"),
            nt_authority_group(15, u"This Organization"),
            nt_authority_group(18, u"SYSTEM"),
            nt_authority_group(19, u"LOCAL SERVICE"),
            nt_authority_group(20, u"NETWORK SERVICE"),
            builtin_alias(544, u"Administrators"),
            builtin_alias(545, u"Users"),
        };

        // The binary SID S-1-5-<sub authorities>.
        std::vector<uint8_t> make_sid(const std::span<const uint32_t> sub_authorities)
        {
            std::vector<uint8_t> sid{1, static_cast<uint8_t>(sub_authorities.size()), 0, 0, 0, 0, 0, 5};
            for (const auto sub_authority : sub_authorities)
            {
                const auto* bytes = reinterpret_cast<const uint8_t*>(&sub_authority);
                sid.insert(sid.end(), bytes, bytes + sizeof(sub_authority));
            }
            return sid;
        }

        void write_lsa_unicode_string_header(utils::aligned_binary_writer& writer, const std::u16string_view value)
        {
            writer.write(static_cast<uint16_t>(value.size() * sizeof(char16_t)));
            writer.write(static_cast<uint16_t>((value.size() + 1) * sizeof(char16_t)));
            writer.write_ndr_pointer(true);
        }

        void write_lsa_translated_name(utils::aligned_binary_writer& writer, const std::u16string_view value, const uint32_t sid_type)
        {
            writer.write(sid_type);
            writer.align_to(writer.pointer_size());
            write_lsa_unicode_string_header(writer, value);
            writer.write<int32_t>(0);
            writer.write<int32_t>(0);
            writer.align_to(writer.pointer_size());
            writer.write_ndr_u16string(value, false);
        }

        void write_lookup_sids_success_reply(utils::aligned_binary_writer& writer, const std::u16string_view domain,
                                             const std::span<const uint8_t> domain_sid, const std::u16string_view user,
                                             const uint32_t sid_type = k_sid_type_user)
        {
            writer.write_ndr_pointer(true);

            writer.write<uint32_t>(1);
            writer.write_ndr_pointer(true);
            writer.write(k_lsa_max_referenced_domains);

            writer.write_pointer_sized(1);
            write_lsa_unicode_string_header(writer, domain);
            writer.write_ndr_pointer(true);
            writer.write_ndr_u16string(domain, false);
            writer.align_to(writer.pointer_size());

            writer.write(static_cast<uint32_t>(domain_sid.empty() ? 0 : domain_sid[1]));
            writer.align_to(writer.pointer_size());
            writer.write(domain_sid.data(), domain_sid.size(), alignof(uint32_t));
            writer.align_to(writer.pointer_size());

            writer.write<uint32_t>(1);
            writer.write_ndr_pointer(true);
            writer.write_pointer_sized(1);
            write_lsa_translated_name(writer, user, sid_type);

            writer.write<uint32_t>(1);
            writer.write(STATUS_SUCCESS);

            const auto min_reply_size =
                select_by_pointer_size(writer, k_lookup_sids_min_success_reply_size_32, k_lookup_sids_min_success_reply_size_64);

            if (writer.offset() < min_reply_size)
            {
                writer.pad(static_cast<size_t>(min_reply_size - writer.offset()));
            }
        }

        struct lsa_policy_lookup_port : rpc_port
        {
            /*
             * The layout for this RPC port seems to be all documented here:
             * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc
             */
            NTSTATUS handle_rpc(windows_emulator& win_emu, const uint32_t procedure_id, const lpc_request_context& c,
                                utils::aligned_binary_writer& writer, std::vector<alpc_reply_handle>& /*reply_handles*/) override
            {
                if (this->bound_interface() == k_lsarpc_interface)
                {
                    return handle_lsarpc(win_emu, procedure_id, c, writer);
                }

                switch (procedure_id)
                {
                case 0:
                    return handle_open_policy(win_emu, writer);
                case 1:
                    return handle_close_policy(win_emu, writer);
                case 2:
                    return handle_lookup_sids(win_emu, c, writer);
                case k_policy_lookup_account_procedure:
                    return handle_lookup_account(win_emu, writer);
                case 5:
                    // The shell's account-lookup path (e.g. SHGetKnownFolderPath, used while the engine sets
                    // up its crash-report queue) issues this additional lookup. We don't resolve it, but we
                    // must answer with a well-formed "none mapped" result: returning an RPC error makes the
                    // runtime raise RPC_S_CALL_FAILED in the caller, whose vectored exception handler then
                    // re-enters a half-initialized singleton and deadlocks.
                    return write_lookup_not_mapped_reply(writer);
                case k_sspi_get_user_name_procedure:
                    return handle_get_user_name(win_emu, writer);
                default:
                    return unsupported(win_emu, procedure_id);
                }
            }

          private:
            NTSTATUS unsupported(windows_emulator& win_emu, const uint32_t procedure_id) const
            {
                const auto& id = this->bound_interface();
                win_emu.log.warn("Unsupported LSA RPC procedure %u on interface %02X%02X%02X%02X\n", procedure_id, id[3], id[2], id[1],
                                 id[0]);
                return STATUS_NOT_SUPPORTED;
            }

            // MS-LSAD (lsarpc) as advapi32 uses it on this endpoint: opening and closing a policy handle and the privilege
            // lookups. LsarOpenPolicy3 (130) stays unsupported: the client then falls back to LsarOpenPolicy2.
            NTSTATUS handle_lsarpc(windows_emulator& win_emu, const uint32_t procedure_id, const lpc_request_context& c,
                                   utils::aligned_binary_writer& writer) const
            {
                switch (procedure_id)
                {
                case k_lsar_close:
                    // The [in, out] handle comes back zeroed.
                    writer.pad(k_context_handle_size);
                    writer.write(STATUS_SUCCESS);
                    return STATUS_SUCCESS;
                case k_lsar_open_policy2:
                    writer.write<uint32_t>(0);
                    writer.write(k_policy_context_uuid.data(), k_policy_context_uuid.size());
                    writer.write(STATUS_SUCCESS);
                    return STATUS_SUCCESS;
                case k_lsar_lookup_privilege_value:
                    return handle_lookup_privilege_value(win_emu, c, writer);
                case k_lsar_lookup_privilege_name:
                    return handle_lookup_privilege_name(win_emu, c, writer);
                case k_lsar_lookup_privilege_display_name:
                    return handle_lookup_privilege_display_name(win_emu, c, writer);
                case k_lsar_open_policy3:
                    return STATUS_NOT_SUPPORTED;
                case k_lsar_query_information_policy:
                case k_lsar_query_information_policy2:
                    return handle_query_information_policy(win_emu, c, writer);
                default:
                    return this->unsupported(win_emu, procedure_id);
                }
            }

            // The RPC_UNICODE_STRING the request carries after the policy handle (NDR64: length, maximum length, buffer
            // pointer, then the conformant varying array). Nothing if the request does not hold one.
            static std::optional<std::u16string> read_request_string(windows_emulator& win_emu, const lpc_request_context& c)
            {
                constexpr size_t length_offset = 0x18;
                constexpr size_t actual_count_offset = 0x38;
                constexpr size_t characters_offset = 0x40;
                if (c.send_buffer_length < characters_offset)
                {
                    return std::nullopt;
                }

                const auto length = win_emu.emu().read_memory<uint16_t>(c.send_buffer + length_offset);
                const auto count = win_emu.emu().read_memory<uint64_t>(c.send_buffer + actual_count_offset);
                if (count * sizeof(char16_t) != length || characters_offset + length > c.send_buffer_length)
                {
                    return std::nullopt;
                }

                std::u16string value(count, u'\0');
                win_emu.emu().read_memory(c.send_buffer + characters_offset, value.data(), length);
                return value;
            }

            // A unique pointer to an RPC_UNICODE_STRING: referent, header, and characters (NDR64).
            static void write_unicode_string_pointer(utils::aligned_binary_writer& writer, const std::u16string_view value)
            {
                writer.write_ndr_pointer(true);
                write_lsa_unicode_string_header(writer, value);
                writer.write_ndr_u16string(value, false);
            }

            static NTSTATUS handle_lookup_privilege_value(windows_emulator& win_emu, const lpc_request_context& c,
                                                          utils::aligned_binary_writer& writer)
            {
                const auto name = read_request_string(win_emu, c);
                const auto* privilege = name ? find_privilege(*name) : nullptr;
                writer.write<uint32_t>(privilege ? privilege->luid : 0);
                writer.write<int32_t>(0);
                writer.write(privilege ? STATUS_SUCCESS : k_status_no_such_privilege);
                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_lookup_privilege_name(windows_emulator& win_emu, const lpc_request_context& c,
                                                         utils::aligned_binary_writer& writer)
            {
                // The LUID follows the 20-byte policy handle.
                const privilege_entry* privilege = nullptr;
                if (c.send_buffer_length >= k_context_handle_size + sizeof(uint64_t))
                {
                    const auto low = win_emu.emu().read_memory<uint32_t>(c.send_buffer + k_context_handle_size);
                    const auto high = win_emu.emu().read_memory<int32_t>(c.send_buffer + k_context_handle_size + sizeof(uint32_t));
                    const auto entry = std::ranges::find(k_privileges, low, &privilege_entry::luid);
                    privilege = high == 0 && entry != k_privileges.end() ? &*entry : nullptr;
                }

                if (!privilege)
                {
                    writer.write_ndr_pointer(false);
                    writer.write(k_status_no_such_privilege);
                    return STATUS_SUCCESS;
                }

                write_unicode_string_pointer(writer, privilege->name);
                writer.write(STATUS_SUCCESS);
                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_lookup_privilege_display_name(windows_emulator& win_emu, const lpc_request_context& c,
                                                                 utils::aligned_binary_writer& writer)
            {
                const auto name = read_request_string(win_emu, c);
                const auto* privilege = name ? find_privilege(*name) : nullptr;
                if (!privilege)
                {
                    writer.write_ndr_pointer(false);
                    writer.write<uint16_t>(0);
                    writer.write(k_status_no_such_privilege);
                    return STATUS_SUCCESS;
                }

                write_unicode_string_pointer(writer, privilege->display_name);
                writer.write(k_language_english_united_states);
                writer.write(STATUS_SUCCESS);
                return STATUS_SUCCESS;
            }

            // LsarQueryInformationPolicy(2) (NDR64): a unique pointer to the LSAPR_POLICY_INFORMATION union (its
            // discriminant, then the arm, aligned to 8), the arm's deferred strings and SID, and the status. As on a
            // workgroup machine, the primary and DNS domain are the workgroup without a SID, and the account domain is
            // the machine's.
            static NTSTATUS handle_query_information_policy(windows_emulator& win_emu, const lpc_request_context& c,
                                                            utils::aligned_binary_writer& writer)
            {
                // The class follows the 20-byte policy handle.
                const auto information_class = c.send_buffer_length >= k_context_handle_size + sizeof(uint16_t)
                                                   ? win_emu.emu().read_memory<uint16_t>(c.send_buffer + k_context_handle_size)
                                                   : uint16_t{};

                const auto write_string_header = [&](const std::u16string_view value) {
                    if (value.empty())
                    {
                        writer.write<uint16_t>(0);
                        writer.write<uint16_t>(0);
                        writer.write_ndr_pointer(false);
                        return;
                    }

                    write_lsa_unicode_string_header(writer, value);
                };
                const auto write_string_characters = [&](const std::u16string_view value) {
                    if (!value.empty())
                    {
                        writer.write_ndr_u16string(value, false);
                    }
                };
                const auto write_sid = [&](const std::span<const uint8_t> sid) {
                    if (!sid.empty())
                    {
                        writer.write_pointer_sized(sid[1]);
                        writer.write(sid.data(), sid.size(), alignof(uint32_t));
                    }
                };
                const auto begin_arm = [&] {
                    writer.write_ndr_pointer(true);
                    writer.write<uint32_t>(information_class);
                    writer.align_to(sizeof(uint64_t));
                };

                switch (information_class)
                {
                case k_policy_primary_domain_information:
                    begin_arm();
                    write_string_header(k_workgroup_name);
                    writer.write_ndr_pointer(false);
                    write_string_characters(k_workgroup_name);
                    break;
                case k_policy_account_domain_information: {
                    const auto domain = registry_utils::get_account_domain(win_emu.registry);
                    const auto domain_sid = derive_account_domain_sid(win_emu.process.sid);
                    begin_arm();
                    write_string_header(domain);
                    writer.write_ndr_pointer(!domain_sid.empty());
                    write_string_characters(domain);
                    write_sid(domain_sid);
                    break;
                }
                case k_policy_dns_domain_information:
                    begin_arm();
                    write_string_header(k_workgroup_name);
                    write_string_header({});
                    write_string_header({});
                    writer.pad(16); // DomainGuid: none
                    writer.write_ndr_pointer(false);
                    write_string_characters(k_workgroup_name);
                    break;
                default:
                    win_emu.log.warn("Unsupported LSA policy information class %u\n", static_cast<uint32_t>(information_class));
                    writer.write_ndr_pointer(false);
                    writer.write(k_status_invalid_info_class);
                    return STATUS_SUCCESS;
                }

                writer.write(STATUS_SUCCESS);
                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_lookup_account(windows_emulator& win_emu, utils::aligned_binary_writer& writer)
            {
                const auto domain = utils::string::to_lower(registry_utils::get_account_domain(win_emu.registry));
                const auto domain_sid = derive_account_domain_sid(win_emu.process.sid);

                writer.write_ndr_pointer(true);
                writer.write<uint32_t>(1);
                writer.write_ndr_pointer(true);
                writer.write(k_lsa_max_referenced_domains);

                writer.write_pointer_sized(1);
                write_lsa_unicode_string_header(writer, domain);
                writer.write_ndr_pointer(true);
                writer.write_ndr_u16string(domain, false);

                writer.write(static_cast<uint32_t>(domain_sid[1]));
                writer.write(domain_sid.data(), domain_sid.size(), alignof(uint32_t));

                writer.write<uint32_t>(1);
                writer.write_ndr_pointer(true);
                writer.write_pointer_sized(1);
                writer.write(k_sid_type_user);
                writer.write_ndr_pointer(true);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(0);
                writer.write(static_cast<uint32_t>(win_emu.process.sid[1]));
                writer.write(win_emu.process.sid.data(), win_emu.process.sid.size(), alignof(uint32_t));
                writer.write<uint32_t>(1);

                pad_to_reply_size(writer, k_lookup_account_reply_size_32, k_lookup_account_reply_size_64);

                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_get_user_name(windows_emulator& win_emu, utils::aligned_binary_writer& writer)
            {
                const auto domain = registry_utils::get_account_domain(win_emu.registry);
                const auto user = registry_utils::get_user_name(win_emu.registry);
                const auto name = domain + u"\\" + user;
                const auto length = static_cast<uint16_t>(name.size() * sizeof(char16_t));

                writer.write(length);
                writer.write(static_cast<uint16_t>(length + sizeof(char16_t)));
                writer.write_ndr_pointer(true);
                writer.write_ndr_u16string(name, false);
                pad_to_reply_size(writer, k_get_user_name_reply_size_32, k_get_user_name_reply_size_64);
                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_open_policy(windows_emulator& win_emu, utils::aligned_binary_writer& writer)
            {
                (void)win_emu;
                const auto reply_offset = writer.offset();
                writer.pad(select_by_pointer_size(writer, k_open_policy_reply_size_32, k_open_policy_reply_size_64));
                writer.write_at(reply_offset + 0x04, k_policy_context_uuid.data(), k_policy_context_uuid.size());

                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_lookup_sids(windows_emulator& win_emu, const lpc_request_context& c,
                                               utils::aligned_binary_writer& writer)
            {
                if (request_contains_sid(win_emu, c, win_emu.process.sid))
                {
                    const auto domain = registry_utils::get_account_domain(win_emu.registry);
                    const auto domain_sid = derive_account_domain_sid(win_emu.process.sid);
                    const auto user = registry_utils::get_user_name(win_emu.registry);

                    write_lookup_sids_success_reply(writer, domain, domain_sid, user);

                    return STATUS_SUCCESS;
                }

                for (const auto& known : k_well_known_sids)
                {
                    const auto sid = make_sid(known.sub_authorities);
                    if (request_contains_sid(win_emu, c, sid))
                    {
                        const auto domain_sid = make_sid(known.domain_sub_authorities);
                        write_lookup_sids_success_reply(writer, known.domain, domain_sid, known.name, known.type);
                        return STATUS_SUCCESS;
                    }
                }

                return write_lookup_not_mapped_reply(writer);
            }

            static NTSTATUS write_lookup_not_mapped_reply(utils::aligned_binary_writer& writer)
            {
                const auto reply_offset = writer.offset();
                writer.pad(k_lookup_sids_not_mapped_reply_size);
                writer.write_at(reply_offset + 0x14, k_status_none_mapped);
                return STATUS_SUCCESS;
            }

            static NTSTATUS handle_close_policy(windows_emulator& win_emu, utils::aligned_binary_writer& writer)
            {
                (void)win_emu;
                writer.pad(select_by_pointer_size(writer, k_close_policy_reply_size_32, k_close_policy_reply_size_64));
                return STATUS_SUCCESS;
            }
        };
    }

    std::unique_ptr<port> create_lsa_policy_lookup_port()
    {
        return std::make_unique<lsa_policy_lookup_port>();
    }

} // namespace sogen
