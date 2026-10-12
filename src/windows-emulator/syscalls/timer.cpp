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

        namespace
        {
            NTSTATUS create_timer(const syscall_context& c, const emulator_object<handle> timer_handle,
                                  const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                  const bool notification)
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
                t.notification = notification;

                const auto h = c.proc.timers.store(std::move(t));
                timer_handle.write(h);

                return STATUS_SUCCESS;
            }

            // Arms a timer like KeSetTimerEx: clears its signal, sets the due time and period, and
            // records the APC for the calling thread.
            NTSTATUS set_timer(const syscall_context& c, const handle timer_handle, const LARGE_INTEGER due_time,
                               const std::chrono::steady_clock::duration period, const uint64_t apc_routine, const uint64_t apc_context,
                               const uint64_t previous_state)
            {
                auto* t = c.proc.timers.get(timer_handle);
                if (!t)
                {
                    return STATUS_INVALID_HANDLE;
                }

                if (period.count() < 0)
                {
                    return STATUS_INVALID_PARAMETER_6;
                }

                if (previous_state)
                {
                    c.emu.write_memory<BOOLEAN>(previous_state, t->signaled ? TRUE : FALSE);
                }

                const auto due = utils::convert_delay_interval_to_time_point(c.win_emu.clock(), due_time);

                t->signaled = false;
                t->due_time = due;
                t->period = period;
                t->apc_routine = apc_routine;
                t->apc_context = apc_context;
                t->apc_thread_id = apc_routine ? c.win_emu.current_thread().id : 0;

                return STATUS_SUCCESS;
            }

            NTSTATUS cancel_timer(const syscall_context& c, const handle timer_handle, const uint64_t current_state)
            {
                auto* t = c.proc.timers.get(timer_handle);
                if (!t)
                {
                    return STATUS_INVALID_HANDLE;
                }

                t->due_time.reset();
                t->period = {};
                t->apc_routine = 0;

                if (current_state)
                {
                    c.emu.write_memory<BOOLEAN>(current_state, t->signaled ? TRUE : FALSE);
                }

                return STATUS_SUCCESS;
            }

            std::chrono::steady_clock::duration period_from_milliseconds(const LONG period)
            {
                return std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::milliseconds{period});
            }
        }

        // NtCreateTimer2's attributes come from CreateWaitableTimerExW: bit 31 is a manual-reset
        // (notification) timer, 4 marks a high-resolution one.
        NTSTATUS handle_NtCreateTimer2(const syscall_context& c, const emulator_object<handle> timer_handle, uint64_t /*reserved*/,
                                       const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                       const ULONG attributes, ACCESS_MASK /*desired_access*/)
        {
            return create_timer(c, timer_handle, object_attributes, (attributes & 0x80000000) != 0);
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

            return create_timer(c, timer_handle, object_attributes, timer_type == notification_timer);
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
                                   const LONG period, const uint64_t previous_state)
        {
            if (!due_time)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            return set_timer(c, timer_handle, due_time.read(), period_from_milliseconds(period), apc_routine, apc_context, previous_state);
        }

        // NtSetTimer2's period is in 100 ns units; its parameters only carry a wake tolerance.
        NTSTATUS handle_NtSetTimer2(const syscall_context& c, const handle timer_handle, const emulator_object<LARGE_INTEGER> due_time,
                                    const emulator_object<LARGE_INTEGER> period, const uint64_t /*parameters*/)
        {
            if (!due_time)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            std::chrono::steady_clock::duration timer_period{};
            if (period)
            {
                const auto hundred_ns = period.read().QuadPart;
                if (hundred_ns < 0)
                {
                    return STATUS_INVALID_PARAMETER_3;
                }

                timer_period = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<int64_t, std::ratio<1, HUNDRED_NANOSECONDS_IN_ONE_SECOND>>{hundred_ns});
            }

            return set_timer(c, timer_handle, due_time.read(), timer_period, 0, 0, 0);
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

            const auto info = c.emu.read_memory<timer_set_coalescable_timer_info>(timer_set_information);
            return set_timer(c, timer_handle, info.DueTime, period_from_milliseconds(static_cast<LONG>(info.Period)), info.TimerApcRoutine,
                             info.TimerContext, info.PreviousState);
        }

        NTSTATUS handle_NtCancelTimer(const syscall_context& c, const handle timer_handle, const uint64_t current_state)
        {
            return cancel_timer(c, timer_handle, current_state);
        }

        NTSTATUS handle_NtCancelTimer2(const syscall_context& c, const handle timer_handle, const uint64_t /*parameters*/)
        {
            return cancel_timer(c, timer_handle, 0);
        }

        NTSTATUS handle_NtQueryTimer(const syscall_context& c, const handle timer_handle, const uint32_t timer_information_class,
                                     const uint64_t timer_information, const ULONG timer_information_length,
                                     const emulator_object<ULONG> return_length)
        {
            struct timer_basic_information
            {
                LARGE_INTEGER RemainingTime;
                BOOLEAN TimerState;
            };

            constexpr uint32_t timer_basic_information_class = 0;
            if (timer_information_class != timer_basic_information_class)
            {
                return STATUS_INVALID_INFO_CLASS;
            }

            if (timer_information_length != sizeof(timer_basic_information))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            const auto* t = c.proc.timers.get(timer_handle);
            if (!t)
            {
                return STATUS_INVALID_HANDLE;
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
