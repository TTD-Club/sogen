#include "../std_include.hpp"
#include "../syscall_dispatcher.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

#include <algorithm>

namespace sogen
{

    namespace syscalls
    {
        // In 100 ns units: the coarsest and finest timer resolutions, and the resolution without this process' request.
        constexpr ULONG coarsest_timer_resolution = 0x0002625a;
        constexpr ULONG finest_timer_resolution = 0x00001388;
        constexpr ULONG default_timer_resolution = 0x00002710;

        // A request can only make the timer finer, never coarser than it already is.
        ULONG current_timer_resolution(const process_context& process)
        {
            return std::min(process.timer_resolution_request.value_or(default_timer_resolution), default_timer_resolution);
        }

        NTSTATUS handle_NtQueryTimerResolution(const syscall_context& c, const emulator_object<ULONG> maximum_time,
                                               const emulator_object<ULONG> minimum_time, const emulator_object<ULONG> current_time)
        {
            maximum_time.write_if_valid(coarsest_timer_resolution);
            minimum_time.write_if_valid(finest_timer_resolution);
            current_time.write_if_valid(current_timer_resolution(c.proc));
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtSetTimerResolution(const syscall_context& c, const ULONG desired_resolution, const BOOLEAN set_resolution,
                                             const emulator_object<ULONG> current_resolution)
        {
            auto status = STATUS_SUCCESS;
            if (set_resolution)
            {
                c.proc.timer_resolution_request = std::clamp(desired_resolution, finest_timer_resolution, coarsest_timer_resolution);
            }
            else if (c.proc.timer_resolution_request)
            {
                c.proc.timer_resolution_request.reset();
            }
            else
            {
                status = STATUS_TIMER_RESOLUTION_NOT_SET;
            }

            current_resolution.write_if_valid(current_timer_resolution(c.proc));
            return status;
        }

        namespace
        {
            // The timer behind a handle. The Timer2 calls (NtSetTimer2, NtCancelTimer2) take only NtCreateTimer2's
            // timers; the classic calls take both kinds.
            std::pair<timer*, NTSTATUS> find_timer(const syscall_context& c, const handle timer_handle, const bool timer2_call)
            {
                const auto effective = c.proc.resolve_object_pseudo_handle(timer_handle, c.vcpu.active_thread);
                auto* store = c.proc.get_handle_store(effective);
                if (!store || !store->get_object(effective))
                {
                    return {nullptr, STATUS_INVALID_HANDLE};
                }

                auto* entry = c.proc.timers.get(effective);
                if (!entry || (timer2_call && !entry->extended))
                {
                    return {nullptr, STATUS_OBJECT_TYPE_MISMATCH};
                }

                return {entry, STATUS_SUCCESS};
            }

            // A due time in 100 ns units, relative when not positive, as a steady-clock deadline; one too far out to
            // represent saturates.
            std::chrono::steady_clock::time_point timer_deadline(utils::clock& clock, const LARGE_INTEGER due)
            {
                const auto now = clock.steady_now();
                uint64_t ticks{};
                if (due.QuadPart <= 0)
                {
                    ticks = static_cast<uint64_t>(-(due.QuadPart + 1)) + 1;
                }
                else
                {
                    const auto system_ticks =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(clock.system_now().time_since_epoch()).count() / 100 +
                        WINDOWS_EPOCH_DIFFERENCE;
                    ticks = due.QuadPart > system_ticks ? static_cast<uint64_t>(due.QuadPart - system_ticks) : 0;
                }

                const auto remaining =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::time_point::max() - now).count();
                if (ticks > static_cast<uint64_t>(remaining / 100))
                {
                    return std::chrono::steady_clock::time_point::max();
                }

                return now + std::chrono::nanoseconds(ticks * 100);
            }

            NTSTATUS create_timer(const syscall_context& c, const emulator_object<handle> timer_handle,
                                  const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                  const bool notification, const bool extended)
            {
                std::u16string name{};
                bool inherit{};
                if (object_attributes)
                {
                    const auto attributes = object_attributes.read();
                    inherit = (attributes.Attributes & OBJ_INHERIT) != 0;
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
                t.notification = notification;
                t.extended = extended;
                t.inherit = inherit;

                const auto h = c.proc.timers.store(std::move(t));
                timer_handle.write(h);

                return STATUS_SUCCESS;
            }

            // Arms a timer like KeSetTimerEx: clears its signal, sets the due time and period, and
            // records the APC for the calling thread.
            void set_timer(const syscall_context& c, timer& t, const LARGE_INTEGER due_time,
                           const std::chrono::steady_clock::duration period, const uint64_t apc_routine, const uint64_t apc_context,
                           const emulator_object<BOOLEAN> previous_state)
            {
                previous_state.write_if_valid(t.signaled ? TRUE : FALSE);

                t.signaled = false;
                t.due_time = timer_deadline(c.win_emu.clock(), due_time);
                t.period = period;
                t.apc_routine = apc_routine;
                t.apc_context = apc_context;
                t.apc_thread_id = apc_routine ? c.win_emu.current_thread().id : 0;
            }

            std::chrono::steady_clock::duration period_from_milliseconds(const LONG period)
            {
                return std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::milliseconds{period});
            }
        }

        // NtCreateTimer2's attributes come from CreateWaitableTimerExW: bit 31 is a manual-reset
        // (notification) timer, 4 marks a high-resolution one. Such timers have no name: the object
        // attributes must be null.
        NTSTATUS handle_NtCreateTimer2(const syscall_context& c, const emulator_object<handle> timer_handle, const uint64_t reserved,
                                       const uint64_t object_attributes, const ULONG attributes, ACCESS_MASK /*desired_access*/)
        {
            if (reserved != 0)
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (object_attributes != 0)
            {
                return STATUS_INVALID_PARAMETER_3;
            }

            constexpr ULONG manual_reset = 0x80000000;
            constexpr ULONG high_resolution = 0x4;
            constexpr ULONG no_wake = 0x8;
            if (attributes == 2 || attributes == 6)
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (attributes & ~(manual_reset | high_resolution | no_wake))
            {
                return STATUS_INVALID_PARAMETER_4;
            }

            return create_timer(c, timer_handle, {c.win_emu.memory}, (attributes & manual_reset) != 0, true);
        }

        NTSTATUS handle_NtCreateTimer(const syscall_context& c, const emulator_object<handle> timer_handle, ACCESS_MASK /*desired_access*/,
                                      const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                      const ULONG timer_type)
        {
            constexpr ULONG notification_timer = 0;
            constexpr ULONG synchronization_timer = 1;
            if (timer_type != notification_timer && timer_type != synchronization_timer)
            {
                return STATUS_INVALID_PARAMETER_4;
            }

            return create_timer(c, timer_handle, object_attributes, timer_type == notification_timer, false);
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

        NTSTATUS handle_NtSetTimer(const syscall_context& c, const handle timer_handle, const emulator_object<LARGE_INTEGER> due_time,
                                   const uint64_t apc_routine, const uint64_t apc_context, const BOOLEAN /*resume_timer*/,
                                   const LONG period, const emulator_object<BOOLEAN> previous_state)
        {
            const auto [entry, status] = find_timer(c, timer_handle, false);
            if (!entry)
            {
                return status;
            }

            if (period < 0)
            {
                return STATUS_INVALID_PARAMETER_6;
            }

            if (!due_time)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            set_timer(c, *entry, due_time.read(), period_from_milliseconds(period), apc_routine, apc_context, previous_state);
            return STATUS_SUCCESS;
        }

        // NtSetTimer2's period is in 100 ns units; its parameters only carry a wake tolerance.
        NTSTATUS handle_NtSetTimer2(const syscall_context& c, const handle timer_handle, const emulator_object<LARGE_INTEGER> due_time,
                                    const emulator_object<LARGE_INTEGER> period, const uint64_t /*parameters*/)
        {
            const auto [entry, status] = find_timer(c, timer_handle, true);
            if (!entry)
            {
                return status;
            }

            if (!due_time)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            std::chrono::steady_clock::duration timer_period{};
            if (period)
            {
                const auto hundred_ns = period.read().QuadPart;
                if (hundred_ns < 0 || hundred_ns > std::numeric_limits<int64_t>::max() / 100)
                {
                    return STATUS_INVALID_PARAMETER_3;
                }

                timer_period = std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::nanoseconds{hundred_ns * 100});
            }

            set_timer(c, *entry, due_time.read(), timer_period, 0, 0, {c.win_emu.memory});
            return STATUS_SUCCESS;
        }

        // SetWaitableTimerEx (CREATE_WAITABLE_TIMER_HIGH_RESOLUTION timers, e.g. Python's time.sleep) sets timers through
        // TimerSetCoalescableTimer.
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

            const auto [entry, status] = find_timer(c, timer_handle, false);
            if (!entry)
            {
                return status;
            }

            const auto info = c.emu.read_memory<timer_set_coalescable_timer_info>(timer_set_information);
            set_timer(c, *entry, info.DueTime, period_from_milliseconds(static_cast<LONG>(info.Period)), info.TimerApcRoutine,
                      info.TimerContext, {c.win_emu.memory, info.PreviousState});
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCancelTimer(const syscall_context& c, const handle timer_handle, const emulator_object<BOOLEAN> current_state)
        {
            const auto [entry, status] = find_timer(c, timer_handle, false);
            if (!entry)
            {
                return status;
            }

            entry->cancel();
            current_state.write_if_valid(entry->signaled ? TRUE : FALSE);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCancelTimer2(const syscall_context& c, const handle timer_handle, const uint64_t /*parameters*/)
        {
            const auto [entry, status] = find_timer(c, timer_handle, true);
            if (!entry)
            {
                return status;
            }

            entry->cancel();
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtQueryTimer(const syscall_context& c, const handle timer_handle, const ULONG timer_information_class,
                                     const uint64_t timer_information, const ULONG timer_information_length,
                                     const emulator_object<ULONG> return_length)
        {
            struct timer_basic_information
            {
                LARGE_INTEGER RemainingTime;
                BOOLEAN TimerState;
            };

            constexpr ULONG timer_basic_information_class = 0;
            if (timer_information_class != timer_basic_information_class)
            {
                return STATUS_INVALID_INFO_CLASS;
            }

            if (timer_information_length != sizeof(timer_basic_information))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            const auto [t, status] = find_timer(c, timer_handle, false);
            if (!t)
            {
                return status;
            }

            timer_basic_information info{};
            info.TimerState = t->signaled ? TRUE : FALSE;

            if (t->due_time.has_value())
            {
                const auto remaining = *t->due_time - c.win_emu.clock().steady_now();
                info.RemainingTime.QuadPart =
                    std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, HUNDRED_NANOSECONDS_IN_ONE_SECOND>>>(remaining)
                        .count();
            }

            c.emu.write_memory(timer_information, info);
            return_length.write_if_valid(sizeof(info));
            return STATUS_SUCCESS;
        }
    }

} // namespace sogen
