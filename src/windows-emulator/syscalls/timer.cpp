#include "../std_include.hpp"
#include "../syscall_dispatcher.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

namespace sogen
{

    namespace syscalls
    {
        NTSTATUS handle_NtQueryTimerResolution(const syscall_context&, const emulator_object<ULONG> maximum_time,
                                               const emulator_object<ULONG> minimum_time, const emulator_object<ULONG> current_time)
        {
            maximum_time.write_if_valid(0x0002625a);
            minimum_time.write_if_valid(0x00001388);
            current_time.write_if_valid(0x00002710);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtSetTimerResolution(const syscall_context&, const ULONG /*desired_resolution*/, const BOOLEAN set_resolution,
                                             const emulator_object<ULONG> current_resolution)
        {
            if (current_resolution)
            {
                current_resolution.write(0x0002625a);
            }

            if (set_resolution)
            {
                return STATUS_TIMER_RESOLUTION_NOT_SET;
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCreateTimer2(const syscall_context& c, const emulator_object<handle> timer_handle, uint64_t /*reserved*/,
                                       const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                       ULONG /*attributes*/, ACCESS_MASK /*desired_access*/)
        {
            std::u16string name{};
            if (object_attributes)
            {
                const auto attributes = object_attributes.read();
                if (attributes.ObjectName)
                {
                    name = read_unicode_string(c.emu, attributes.ObjectName);
                    c.win_emu.callbacks.on_generic_access("Opening timer", name);
                }
            }

            if (!name.empty())
            {
                for (auto& entry : c.proc.timers)
                {
                    if (entry.second.name == name)
                    {
                        ++entry.second.ref_count;
                        timer_handle.write(c.proc.timers.make_handle(entry.first));
                        return STATUS_OBJECT_NAME_EXISTS;
                    }
                }
            }

            timer t{};
            t.name = std::move(name);

            const auto h = c.proc.timers.store(std::move(t));
            timer_handle.write(h);

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCreateTimer(const syscall_context& c, const emulator_object<handle> timer_handle, ACCESS_MASK desired_access,
                                      const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes, ULONG timer_type)
        {
            return handle_NtCreateTimer2(c, timer_handle, 0, object_attributes, timer_type, desired_access);
        }

        NTSTATUS handle_NtOpenTimer(const syscall_context& c, const emulator_object<handle> timer_handle, ACCESS_MASK /*desired_access*/,
                                    const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes)
        {
            if (!timer_handle)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            if (!object_attributes)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto attributes = object_attributes.read();

            if (!attributes.ObjectName)
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            auto name = read_unicode_string(c.emu, attributes.ObjectName);
            c.win_emu.callbacks.on_generic_access("Opening timer", name);

            if (name.empty())
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            for (auto& entry : c.proc.timers)
            {
                if (entry.second.name == name)
                {
                    ++entry.second.ref_count;
                    timer_handle.write(c.proc.timers.make_handle(entry.first));
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_OBJECT_NAME_NOT_FOUND;
        }

        NTSTATUS handle_NtSetTimer()
        {
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtSetTimer2()
        {
            return STATUS_SUCCESS;
        }

        // SetWaitableTimerEx (CREATE_WAITABLE_TIMER_HIGH_RESOLUTION timers, e.g. Python's time.sleep) sets timers through
        // TimerSetCoalescableTimer. Like NtSetTimer, the timer is not scheduled: waits treat timers as signaled.
        NTSTATUS handle_NtSetTimerEx(const syscall_context& c, const handle timer_handle, const uint32_t timer_set_info_class,
                                     const uint64_t timer_set_information, const ULONG timer_set_information_length)
        {
            struct timer_set_coalescable_timer_info
            {
                LARGE_INTEGER DueTime;
                uint64_t TimerApcRoutine;
                uint64_t TimerContext;
                uint64_t WakeContext;
                ULONG Period;
                ULONG TolerableDelay;
                uint64_t PreviousState;
            };

            static_assert(sizeof(timer_set_coalescable_timer_info) == 0x30);

            constexpr uint32_t timer_set_coalescable_timer = 0;
            if (timer_set_info_class != timer_set_coalescable_timer)
            {
                return STATUS_INVALID_INFO_CLASS;
            }

            if (timer_set_information_length != sizeof(timer_set_coalescable_timer_info))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            if (!c.proc.timers.get(timer_handle))
            {
                return STATUS_INVALID_HANDLE;
            }

            const auto info = c.emu.read_memory<timer_set_coalescable_timer_info>(timer_set_information);
            if (info.PreviousState)
            {
                c.emu.write_memory<BOOLEAN>(info.PreviousState, FALSE);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCancelTimer()
        {
            return STATUS_SUCCESS;
        }
    }

} // namespace sogen
