#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>

#include "handles.hpp"

namespace sogen
{
    struct system_process
    {
        uint32_t id{};
        uint32_t parent_id{};
        uint32_t session_id{};
        int32_t base_priority{};
        uint32_t thread_count{};
        std::u16string_view image_name{};
        std::u16string_view image_path{};
        bool owned_by_user{};
    };

    // The processes every Windows 11 installation runs, with an interactive session that started the guest from
    // explorer.exe. Parent ids that are not in the list belong to processes that exited during boot, as they do on
    // Windows (the session instances of smss.exe and userinit.exe).
    // The idle process has one thread per processor; its thread_count is filled in from the processor count.
    constexpr std::array system_processes{
        system_process{.id = 0, .parent_id = 0, .session_id = 0, .base_priority = 0},
        system_process{.id = 4, .parent_id = 0, .session_id = 0, .base_priority = 8, .thread_count = 12, .image_name = u"System"},
        system_process{.id = 0x7C, .parent_id = 4, .session_id = 0, .base_priority = 8, .thread_count = 4, .image_name = u"Registry"},
        system_process{.id = 0x1E8,
                       .parent_id = 4,
                       .session_id = 0,
                       .base_priority = 11,
                       .thread_count = 2,
                       .image_name = u"smss.exe",
                       .image_path = u"C:\\Windows\\System32\\smss.exe"},
        system_process{.id = 0x2A8,
                       .parent_id = 0x2A0,
                       .session_id = 0,
                       .base_priority = 13,
                       .thread_count = 11,
                       .image_name = u"csrss.exe",
                       .image_path = u"C:\\Windows\\System32\\csrss.exe"},
        system_process{.id = 0x2F4,
                       .parent_id = 0x2A0,
                       .session_id = 0,
                       .base_priority = 13,
                       .thread_count = 1,
                       .image_name = u"wininit.exe",
                       .image_path = u"C:\\Windows\\System32\\wininit.exe"},
        system_process{.id = 0x300,
                       .parent_id = 0x2EC,
                       .session_id = 1,
                       .base_priority = 13,
                       .thread_count = 12,
                       .image_name = u"csrss.exe",
                       .image_path = u"C:\\Windows\\System32\\csrss.exe"},
        system_process{.id = 0x354,
                       .parent_id = 0x2F4,
                       .session_id = 0,
                       .base_priority = 9,
                       .thread_count = 7,
                       .image_name = u"services.exe",
                       .image_path = u"C:\\Windows\\System32\\services.exe"},
        system_process{.id = 0x368,
                       .parent_id = 0x2F4,
                       .session_id = 0,
                       .base_priority = 9,
                       .thread_count = 9,
                       .image_name = u"lsass.exe",
                       .image_path = u"C:\\Windows\\System32\\lsass.exe"},
        system_process{.id = 0x3A0,
                       .parent_id = 0x2EC,
                       .session_id = 1,
                       .base_priority = 13,
                       .thread_count = 3,
                       .image_name = u"winlogon.exe",
                       .image_path = u"C:\\Windows\\System32\\winlogon.exe"},
        system_process{.id = 0x40C,
                       .parent_id = 0x354,
                       .session_id = 0,
                       .base_priority = 8,
                       .thread_count = 14,
                       .image_name = u"svchost.exe",
                       .image_path = u"C:\\Windows\\System32\\svchost.exe"},
        system_process{.id = 0x438,
                       .parent_id = 0x3A0,
                       .session_id = 1,
                       .base_priority = 8,
                       .thread_count = 5,
                       .image_name = u"fontdrvhost.exe",
                       .image_path = u"C:\\Windows\\System32\\fontdrvhost.exe"},
        system_process{.id = 0x47C,
                       .parent_id = 0x354,
                       .session_id = 0,
                       .base_priority = 8,
                       .thread_count = 10,
                       .image_name = u"svchost.exe",
                       .image_path = u"C:\\Windows\\System32\\svchost.exe"},
        system_process{.id = 0x4C8,
                       .parent_id = 0x3A0,
                       .session_id = 1,
                       .base_priority = 13,
                       .thread_count = 18,
                       .image_name = u"dwm.exe",
                       .image_path = u"C:\\Windows\\System32\\dwm.exe"},
        system_process{.id = 0x5E4,
                       .parent_id = 0x354,
                       .session_id = 0,
                       .base_priority = 8,
                       .thread_count = 6,
                       .image_name = u"svchost.exe",
                       .image_path = u"C:\\Windows\\System32\\svchost.exe"},
        system_process{.id = 0x1170,
                       .parent_id = 0x5E4,
                       .session_id = 1,
                       .base_priority = 8,
                       .thread_count = 10,
                       .image_name = u"sihost.exe",
                       .image_path = u"C:\\Windows\\System32\\sihost.exe",
                       .owned_by_user = true},
        system_process{.id = 0x1234,
                       .parent_id = 0x5E4,
                       .session_id = 1,
                       .base_priority = 8,
                       .thread_count = 8,
                       .image_name = u"taskhostw.exe",
                       .image_path = u"C:\\Windows\\System32\\taskhostw.exe",
                       .owned_by_user = true},
        system_process{.id = 0x1254,
                       .parent_id = 0x1238,
                       .session_id = 1,
                       .base_priority = 8,
                       .thread_count = 30,
                       .image_name = u"explorer.exe",
                       .image_path = u"C:\\Windows\\explorer.exe",
                       .owned_by_user = true},
    };

    constexpr uint32_t interactive_session_id = 1;
    constexpr uint32_t guest_parent_process_id = 0x1254;

    // Synthetic threads take ids far above the ones the guest hands out, so the two never meet.
    constexpr uint32_t system_thread_id_base = 0x70000;

    constexpr const system_process* find_system_process(const uint64_t id)
    {
        const auto entry = std::ranges::find(system_processes, id, [](const system_process& process) { return uint64_t{process.id}; });
        return entry == system_processes.end() ? nullptr : &*entry;
    }

    constexpr handle make_system_process_handle(const system_process& process)
    {
        return make_pseudo_handle(process.id, handle_types::process);
    }

    constexpr const system_process* find_system_process(const handle h)
    {
        if (!h.value.is_pseudo || h.value.type != handle_types::process || h.value.id == 0)
        {
            return nullptr;
        }

        return find_system_process(uint64_t{h.value.id});
    }

} // namespace sogen
