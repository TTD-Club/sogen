#include "../std_include.hpp"
#include "named_pipe.hpp"
#include "../windows_emulator.hpp"

namespace sogen
{
    named_pipe* find_pipe_end(process_context& process, const uint64_t instance, const bool server)
    {
        if (!instance)
        {
            return nullptr;
        }

        for (auto& container : process.devices | std::views::values)
        {
            auto* pipe = container.get_internal_device<named_pipe>();
            if (pipe && pipe->instance == instance && pipe->server == server)
            {
                return pipe;
            }
        }

        return nullptr;
    }

    std::optional<NTSTATUS> read_pipe(windows_emulator& win_emu, named_pipe& pipe, const uint64_t buffer, const ULONG length,
                                      const emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block)
    {
        NTSTATUS status{};
        std::string data{};
        if (!pipe.read_queue.empty())
        {
            bool more{};
            data = pipe.take(length, more);
            status = more ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        }
        else if (!pipe.instance)
        {
            // Not connected to anything that could write (the \Device\NamedPipe\ root).
            status = STATUS_PIPE_EMPTY;
        }
        else if (!find_pipe_peer(win_emu.process, pipe))
        {
            status = STATUS_PIPE_BROKEN;
        }
        else
        {
            return std::nullopt;
        }

        if (!data.empty())
        {
            win_emu.emu().write_memory(buffer, data.data(), data.size());
        }

        if (io_status_block)
        {
            io_status_block.write({.Status = status, .Information = data.size()});
        }

        return status;
    }

    void complete_pipe_io(windows_emulator& win_emu, const io_device_context& request, const uint32_t thread_id, const NTSTATUS status,
                          const uint64_t information, const bool pended)
    {
        auto& process = win_emu.process;
        if (auto* event = process.events.get(request.event))
        {
            event->signaled = true;
        }

        constexpr ULONG file_skip_completion_port_on_success = 0x1;
        if (pended || (NT_SUCCESS(status) && !(request.completion_notification_flags & file_skip_completion_port_on_success)))
        {
            io_device::queue_io_completion(win_emu, request);
        }

        if (!request.apc_routine)
        {
            return;
        }

        for (auto& thread : process.threads | std::views::values)
        {
            if (thread.id != thread_id)
            {
                continue;
            }

            const auto restamp = process.is_wow64_process && request.io_status_block;
            if (restamp)
            {
                // The WoW64 completion routine reads the 32-bit layout (Status @0, Information @4); see
                // deliver_file_io_completion.
                const auto status32 = static_cast<uint32_t>(static_cast<ULONG>(status));
                const auto information32 = static_cast<uint32_t>(information);
                win_emu.emu().write_memory(request.io_status_block.value(), &status32, sizeof(status32));
                win_emu.emu().write_memory(request.io_status_block.value() + sizeof(status32), &information32, sizeof(information32));
            }

            thread.pending_apcs.push_back({
                .flags = 0,
                .apc_routine = request.apc_routine,
                .apc_argument1 = request.apc_context,
                .apc_argument2 = request.io_status_block.value(),
                .apc_argument3 = 0,
                .restamp_io_status_block = restamp,
                .io_status = static_cast<int32_t>(static_cast<ULONG>(status)),
                .io_information = static_cast<uint32_t>(information),
            });
            return;
        }
    }

    void named_pipe::work(windows_emulator& win_emu)
    {
        while (!this->pending_reads.empty())
        {
            const auto& read = this->pending_reads.front();
            const auto& request = read.context;
            const auto status = read_pipe(win_emu, *this, request.output_buffer, request.output_buffer_length, request.io_status_block);
            if (!status)
            {
                return;
            }

            const auto information = request.io_status_block ? request.io_status_block.read().Information : 0;
            complete_pipe_io(win_emu, request, read.thread_id, *status, information, true);
            this->pending_reads.erase(this->pending_reads.begin());
        }
    }

    bool named_pipe::cancel_io(windows_emulator& win_emu, const uint64_t io_status_block)
    {
        for (auto it = this->pending_reads.begin(); it != this->pending_reads.end(); ++it)
        {
            if (it->context.io_status_block.value() != io_status_block)
            {
                continue;
            }

            const auto read = *it;
            this->pending_reads.erase(it);
            if (read.context.io_status_block)
            {
                read.context.io_status_block.write({.Status = STATUS_CANCELLED, .Information = 0});
            }
            complete_pipe_io(win_emu, read.context, read.thread_id, STATUS_CANCELLED, 0, true);
            return true;
        }

        return false;
    }
}
