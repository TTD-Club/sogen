#include "../std_include.hpp"
#include "named_pipe.hpp"
#include "../windows_emulator.hpp"
#include "../io_completion_wait.hpp"
#include <utils/finally.hpp>

namespace sogen
{
    namespace
    {
        NTSTATUS translate_pipe_status(const utils::pipe_io_status status)
        {
            switch (status)
            {
            case utils::pipe_io_status::success:
                return STATUS_SUCCESS;
            case utils::pipe_io_status::pending:
                return STATUS_PENDING;
            case utils::pipe_io_status::broken:
                return STATUS_PIPE_BROKEN;
            case utils::pipe_io_status::cancelled:
                return STATUS_CANCELLED;
            default:
                return STATUS_UNSUCCESSFUL;
            }
        }
    }

    void named_pipe::copy_configuration(const named_pipe& source)
    {
        this->name = source.name;
        this->pipe_type = source.pipe_type;
        this->read_mode = source.read_mode;
        this->completion_mode = source.completion_mode;
        this->max_instances = source.max_instances;
        this->inbound_quota = source.inbound_quota;
        this->outbound_quota = source.outbound_quota;
        this->create_options = source.create_options;
        this->default_timeout = source.default_timeout;
    }

    void named_pipe::complete(windows_emulator& win_emu, const pending_operation& operation, const utils::pipe_io_result result,
                              const bool was_pending)
    {
        const auto& context = operation.context;
        const auto status = translate_pipe_status(result.status);
        this->signaled = true;
        if (operation.kind == operation_kind::read && result.transferred)
        {
            win_emu.memory.write_memory(context.output_buffer, operation.operation->data().data(), result.transferred);
        }
        context.io_status_block.write({.Status = status, .Information = result.transferred});
        write_io_status(context, status);
        if (auto* event = win_emu.process.events.get(context.event))
        {
            event->signaled = true;
        }
        if (context.apc_routine)
        {
            if (auto* thread = win_emu.process.threads.get(operation.issuing_thread))
            {
                thread->pending_apcs.push_back({.apc_routine = context.apc_routine,
                                                .apc_argument1 = context.apc_context,
                                                .apc_argument2 = context.wow64_io_status_block ? context.wow64_io_status_block.value()
                                                                                               : context.io_status_block.value(),
                                                .apc_argument3 = 0});
            }
        }
        else if (was_pending || !NT_SUCCESS(status) || !(context.completion_notification_flags & 1))
        {
            io_device::queue_io_completion(win_emu, context);
        }
    }

    NTSTATUS named_pipe::start_io(windows_emulator& win_emu, io_device_context context, const bool reading)
    {
        if (!this->endpoint || !context.io_status_block)
        {
            return STATUS_INVALID_HANDLE;
        }
        const auto required_access =
            reading ? (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) : (FILE_WRITE_DATA | GENERIC_WRITE | GENERIC_ALL);
        if (!(context.granted_access & required_access))
        {
            return STATUS_ACCESS_DENIED;
        }
        if (reading && this->read_mode != 0)
        {
            return STATUS_NOT_SUPPORTED;
        }
        if ((context.event.bits && !win_emu.process.events.get(context.event)) ||
            (context.completion_port.bits && !win_emu.process.io_completions.get(context.completion_port)))
        {
            return STATUS_INVALID_HANDLE;
        }
        std::unique_ptr<utils::host_pipe_operation> operation;
        if (reading)
        {
            // PIPE_NOWAIT: a read of an empty pipe whose other end is open returns at once (ERROR_NO_DATA).
            if (this->completion_mode == FILE_PIPE_COMPLETE_OPERATION)
            {
                std::string ignored{};
                uint32_t available{};
                if (this->endpoint->peek(ignored, 0, available).status == utils::pipe_io_status::success && available == 0)
                {
                    return STATUS_PIPE_EMPTY;
                }
            }

            operation = this->endpoint->read(context.output_buffer_length);
        }
        else
        {
            std::string data(context.input_buffer_length, '\0');
            win_emu.memory.read_memory(context.input_buffer, data.data(), data.size());

            // PIPE_NOWAIT: a write that does not fit in the reader's buffer writes nothing and succeeds (also in byte
            // mode); CPython reports it as BlockingIOError.
            if (const auto capacity = this->endpoint->write_capacity();
                this->completion_mode == FILE_PIPE_COMPLETE_OPERATION && capacity && data.size() > *capacity)
            {
                data.clear();
            }

            operation = this->endpoint->write(data);
        }
        return this->enqueue_operation(win_emu, context, std::move(operation), reading ? operation_kind::read : operation_kind::write);
    }

    NTSTATUS named_pipe::start_listen(windows_emulator& win_emu, io_device_context context)
    {
        if (!this->endpoint || !context.io_status_block)
        {
            return STATUS_INVALID_HANDLE;
        }
        if (!this->unopened_peer)
        {
            return STATUS_PIPE_CONNECTED;
        }
        if (this->completion_mode != 0)
        {
            return STATUS_PIPE_LISTENING;
        }
        return this->enqueue_operation(win_emu, context, nullptr, operation_kind::listen);
    }

    NTSTATUS named_pipe::disconnect(windows_emulator& win_emu)
    {
        if (!this->server || this->anonymous)
        {
            return STATUS_ILLEGAL_FUNCTION;
        }

        // The client keeps the old pipe, which no server end has any more: its reads and writes find it broken. A new
        // client connects to the new one.
        this->cancel_io(win_emu, 0);
        auto endpoints =
            utils::host_pipe::create_pair(this->pipe_type != 0, std::max<ULONG>({this->inbound_quota, this->outbound_quota, 4096}));
        this->endpoint = std::move(endpoints.first);
        this->unopened_peer = std::move(endpoints.second);
        return STATUS_SUCCESS;
    }

    NTSTATUS named_pipe::wait(windows_emulator& win_emu, const io_device_context& c)
    {
        // FILE_PIPE_WAIT_FOR_BUFFER: Timeout, NameLength, TimeoutSpecified, then the name relative to \Device\NamedPipe\.
        constexpr ULONG name_offset = 14;
        if (c.input_buffer_length < name_offset)
        {
            return STATUS_INVALID_PARAMETER;
        }

        const auto name_length = win_emu.emu().read_memory<ULONG>(c.input_buffer + 8);
        if (name_length % sizeof(char16_t) != 0 || name_offset + name_length > c.input_buffer_length)
        {
            return STATUS_INVALID_PARAMETER;
        }

        std::u16string name(name_length / sizeof(char16_t), u'\0');
        win_emu.emu().read_memory(c.input_buffer + name_offset, name.data(), name_length);
        const windows_path wanted = u"\\Device\\NamedPipe\\" + name;

        // An instance without a client is available now. Waiting for a busy one to be released is not supported: the
        // wait times out at once.
        auto exists = false;
        for (const auto& container : win_emu.process.devices | std::views::values)
        {
            const auto* end = container.get_internal_device<named_pipe>();
            if (!end || !end->server || end->anonymous || windows_path(end->name) != wanted)
            {
                continue;
            }

            exists = true;
            if (end->unopened_peer)
            {
                return STATUS_SUCCESS;
            }
        }

        constexpr auto status_io_timeout = static_cast<NTSTATUS>(0xC00000B5);
        return exists ? status_io_timeout : STATUS_OBJECT_NAME_NOT_FOUND;
    }

    NTSTATUS named_pipe::enqueue_operation(windows_emulator& win_emu, io_device_context context,
                                           std::unique_ptr<utils::host_pipe_operation> operation, const operation_kind kind)
    {
        pending_operation pending{.context = context,
                                  .operation = std::move(operation),
                                  .issuing_thread = win_emu.process.threads.find_handle(&context.thread()),
                                  .kind = kind};
        std::array<handle, 3> retained_references{};
        const std::array<handle*, 3> references{&pending.context.event, &pending.context.completion_port, &pending.issuing_thread};
        for (size_t i = 0; i < references.size(); ++i)
        {
            if (!io_completion_wait::retain_handle_reference(win_emu.process, context.vcpu->active_thread, *references[i],
                                                             retained_references[i]))
            {
                for (auto& retained : retained_references)
                {
                    io_completion_wait::release_handle_reference(win_emu.process, retained);
                }
                return STATUS_INVALID_HANDLE;
            }
        }
        for (size_t i = 0; i < references.size(); ++i)
        {
            *references[i] = retained_references[i];
        }
        bool queued{};
        const auto cleanup = utils::finally([&] {
            if (!queued)
            {
                release_operation(win_emu.process, pending);
            }
        });
        this->signaled = false;
        const auto result =
            pending.operation ? pending.operation->check_completion() : utils::pipe_io_result{.status = utils::pipe_io_status::pending};
        if (result.status != utils::pipe_io_status::pending)
        {
            this->complete(win_emu, pending, result, false);
            return translate_pipe_status(result.status);
        }
        pending.context.vcpu = nullptr;
        context.io_status_block.write({.Status = STATUS_PENDING, .Information = 0});
        write_io_status(context, STATUS_PENDING);
        if (auto* event = win_emu.process.events.get(context.event))
        {
            event->signaled = false;
        }
        this->pending_.push_back(std::move(pending));
        queued = true;
        if (this->create_options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        {
            context.thread().await_file_io = context.io_status_block.value();
            win_emu.yield_thread(*context.vcpu);
        }
        return STATUS_PENDING;
    }

    void named_pipe::release_operation(process_context& process, pending_operation& operation)
    {
        io_completion_wait::release_handle_reference(process, operation.context.event);
        io_completion_wait::release_handle_reference(process, operation.context.completion_port);
        io_completion_wait::release_handle_reference(process, operation.issuing_thread);
    }

    void named_pipe::work(windows_emulator& win_emu)
    {
        for (auto it = this->pending_.begin(); it != this->pending_.end();)
        {
            const auto result =
                it->kind == operation_kind::listen
                    ? utils::pipe_io_result{.status = this->unopened_peer ? utils::pipe_io_status::pending : utils::pipe_io_status::success}
                    : it->operation->check_completion();
            if (result.status == utils::pipe_io_status::pending)
            {
                ++it;
                continue;
            }
            this->complete(win_emu, *it, result, true);
            release_operation(win_emu.process, *it);
            it = this->pending_.erase(it);
        }
    }

    bool named_pipe::cancel_io(windows_emulator& win_emu, const uint64_t io_status_block)
    {
        bool cancelled{};
        for (auto it = this->pending_.begin(); it != this->pending_.end();)
        {
            if (io_status_block && it->context.io_status_block.value() != io_status_block &&
                it->context.wow64_io_status_block.value() != io_status_block)
            {
                ++it;
                continue;
            }
            if (it->operation)
            {
                it->operation->cancel();
            }
            const auto result =
                it->operation ? it->operation->check_completion() : utils::pipe_io_result{.status = utils::pipe_io_status::cancelled};
            if (result.status == utils::pipe_io_status::pending)
            {
                cancelled = true;
                ++it;
                continue;
            }
            this->complete(win_emu, *it, result, true);
            release_operation(win_emu.process, *it);
            it = this->pending_.erase(it);
            cancelled = true;
        }
        return cancelled;
    }

    void named_pipe::release_references(process_context& process)
    {
        for (auto& operation : this->pending_)
        {
            if (operation.operation)
            {
                operation.operation->cancel();
            }
            release_operation(process, operation);
        }
        this->pending_.clear();
    }

    void named_pipe::serialize_object(utils::buffer_serializer& buffer) const
    {
        buffer.write(this->name);
        buffer.write(this->pipe_type);
        buffer.write(this->read_mode);
        buffer.write(this->completion_mode);
        buffer.write(this->max_instances);
        buffer.write(this->inbound_quota);
        buffer.write(this->outbound_quota);
        buffer.write(this->create_options);
        buffer.write(this->signaled);
        buffer.write(this->server);
        buffer.write(this->anonymous);
        buffer.write(this->default_timeout);
        for (const auto& pipe : {this->endpoint, this->unopened_peer})
        {
            buffer.write(static_cast<bool>(pipe));
            if (pipe)
            {
                pipe->serialize(buffer);
            }
        }
        buffer.write(static_cast<uint64_t>(this->pending_.size()));
        for (const auto& pending : this->pending_)
        {
            buffer.write(pending.context);
            buffer.write(static_cast<bool>(pending.operation));
            if (pending.operation)
            {
                pending.operation->serialize(buffer);
            }
            buffer.write(pending.issuing_thread);
            buffer.write(pending.kind);
        }
    }

    void named_pipe::deserialize_object(utils::buffer_deserializer& buffer)
    {
        buffer.read(this->name);
        buffer.read(this->pipe_type);
        buffer.read(this->read_mode);
        buffer.read(this->completion_mode);
        buffer.read(this->max_instances);
        buffer.read(this->inbound_quota);
        buffer.read(this->outbound_quota);
        buffer.read(this->create_options);
        buffer.read(this->signaled);
        buffer.read(this->server);
        buffer.read(this->anonymous);
        buffer.read(this->default_timeout);
        for (auto* pipe : {&this->endpoint, &this->unopened_peer})
        {
            *pipe = buffer.read<bool>() ? utils::host_pipe::deserialize(buffer) : nullptr;
        }
        this->pending_.clear();
        const auto count = buffer.read<uint64_t>();
        for (uint64_t i = 0; i < count; ++i)
        {
            pending_operation pending{.context = buffer.read<io_device_context>()};
            if (buffer.read<bool>())
            {
                pending.operation = std::make_unique<utils::host_pipe_operation>(buffer);
            }
            buffer.read(pending.issuing_thread);
            buffer.read(pending.kind);
            this->pending_.push_back(std::move(pending));
        }
    }
}
