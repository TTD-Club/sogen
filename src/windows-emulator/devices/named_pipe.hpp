#pragma once
#include "../io_device.hpp"
#include "../windows_emulator.hpp"

namespace sogen
{
    // FSCTL_PIPE_PEEK = CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
    constexpr ULONG FSCTL_PIPE_PEEK = 0x11400C;
    // FSCTL_PIPE_WAIT = CTL_CODE(FILE_DEVICE_NAMED_PIPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS), on the \Device\NamedPipe\ root.
    constexpr ULONG FSCTL_PIPE_WAIT = 0x110018;
    constexpr ULONG FILE_PIPE_CONNECTED_STATE = 3;

    // Header of FILE_PIPE_PEEK_BUFFER; the peeked data follows immediately after.
    struct file_pipe_peek_buffer
    {
        ULONG named_pipe_state;
        ULONG read_data_available;
        ULONG number_of_messages;
        ULONG message_length;
    };

    // FILE_PIPE_INFORMATION (FilePipeInformation): FILE_PIPE_BYTE_STREAM_MODE or _MESSAGE_MODE, and
    // FILE_PIPE_QUEUE_OPERATION or _COMPLETE_OPERATION (PIPE_NOWAIT).
    struct file_pipe_information
    {
        ULONG read_mode;
        ULONG completion_mode;
    };

    constexpr ULONG FILE_PIPE_MESSAGE_MODE_VALUE = 1;
    constexpr ULONG FILE_PIPE_COMPLETE_OPERATION_VALUE = 1;

    // An overlapped read waiting for data: the read goes to output_buffer/output_buffer_length, and its completion
    // APC (ReadFileEx) to the thread that issued it.
    struct pending_pipe_read
    {
        io_device_context context;
        uint32_t thread_id{};

        pending_pipe_read(memory_interface& emu)
            : context(emu)
        {
        }

        pending_pipe_read(utils::buffer_deserializer& buffer)
            : context(buffer)
        {
        }

        void serialize(utils::buffer_serializer& buffer) const
        {
            buffer.write(this->context);
            buffer.write(this->thread_id);
        }

        void deserialize(utils::buffer_deserializer& buffer)
        {
            buffer.read(this->context);
            buffer.read(this->thread_id);
        }
    };

    // One end of a pipe. The two ends of a pipe instance share `instance` (0: no instance, e.g. the
    // \Device\NamedPipe\ root a CreatePipe opens first); what one end writes waits in the other end's read_queue.
    class named_pipe : public io_device
    {
      public:
        std::u16string name;
        // Data written by the other end, not read yet, one entry per write.
        std::deque<std::string> read_queue;
        // Overlapped reads waiting for data, oldest first. Reads through a synchronous handle wait in their thread.
        std::vector<pending_pipe_read> pending_reads;
        // Opened for synchronous I/O (FILE_SYNCHRONOUS_IO_*): a read that has to wait blocks its thread.
        bool synchronous{};
        uint64_t instance{};
        // The end NtCreateNamedPipeFile created, as opposed to a client that opened it.
        bool server{};
        // Clients reach an anonymous pipe's server only through its handle, never by name.
        bool anonymous{};
        ACCESS_MASK access = 0;
        ULONG pipe_type{};
        ULONG read_mode{};
        ULONG completion_mode{};
        ULONG max_instances{};
        ULONG inbound_quota{};
        ULONG outbound_quota{};
        LARGE_INTEGER default_timeout{};

        void create(windows_emulator&, const io_device_creation_data&) override
        {
        }

        // Completes the overlapped reads that can complete.
        void work(windows_emulator& win_emu) override;

        bool cancel_io(windows_emulator& win_emu, uint64_t io_status_block) override;

        // Bytes the other end wrote that wait to be read.
        size_t queued_bytes() const
        {
            size_t queued = 0;
            for (const auto& chunk : this->read_queue)
            {
                queued += chunk.size();
            }
            return queued;
        }

        // Takes up to `length` bytes of what the other end wrote: in message mode the rest of the oldest message (sets
        // `more` when it does not fit), in byte mode as much as is queued.
        std::string take(size_t length, bool& more)
        {
            std::string data{};
            more = false;
            if (this->read_queue.empty())
            {
                return data;
            }

            if (this->read_mode == FILE_PIPE_MESSAGE_MODE_VALUE)
            {
                auto& message = this->read_queue.front();
                data = message.substr(0, length);
                more = data.size() < message.size();
                if (more)
                {
                    message.erase(0, data.size());
                }
                else
                {
                    this->read_queue.pop_front();
                }

                return data;
            }

            while (!this->read_queue.empty() && data.size() < length)
            {
                auto& chunk = this->read_queue.front();
                const auto count = std::min(chunk.size(), length - data.size());
                data.append(chunk, 0, count);
                if (count == chunk.size())
                {
                    this->read_queue.pop_front();
                }
                else
                {
                    chunk.erase(0, count);
                }
            }

            return data;
        }

        NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& c) override
        {
            if (c.io_control_code == FSCTL_PIPE_PEEK)
            {
                return this->peek(win_emu, c);
            }

            if (c.io_control_code == FSCTL_PIPE_WAIT)
            {
                return wait(win_emu, c);
            }

            win_emu.log.warn("Unsupported named pipe FSCTL: 0x%X\n", static_cast<uint32_t>(c.io_control_code));
            return STATUS_NOT_SUPPORTED;
        }

        void serialize_object(utils::buffer_serializer& buffer) const override
        {
            buffer.write_string(this->name);
            buffer.write(static_cast<uint64_t>(this->read_queue.size()));
            for (const auto& chunk : this->read_queue)
            {
                buffer.write_string(chunk);
            }
            buffer.write_vector(this->pending_reads);
            buffer.write(this->synchronous);
            buffer.write(this->instance);
            buffer.write(this->server);
            buffer.write(this->anonymous);
            buffer.write(this->access);
            buffer.write(this->pipe_type);
            buffer.write(this->read_mode);
            buffer.write(this->completion_mode);
            buffer.write(this->max_instances);
            buffer.write(this->inbound_quota);
            buffer.write(this->outbound_quota);
            buffer.write(this->default_timeout);
        }

        void deserialize_object(utils::buffer_deserializer& buffer) override
        {
            buffer.read_string(this->name);
            const auto chunks = buffer.read<uint64_t>();
            this->read_queue.clear();
            for (uint64_t i = 0; i < chunks; ++i)
            {
                buffer.read_string(this->read_queue.emplace_back());
            }
            buffer.read_vector(this->pending_reads);
            buffer.read(this->synchronous);
            buffer.read(this->instance);
            buffer.read(this->server);
            buffer.read(this->anonymous);
            buffer.read(this->access);
            buffer.read(this->pipe_type);
            buffer.read(this->read_mode);
            buffer.read(this->completion_mode);
            buffer.read(this->max_instances);
            buffer.read(this->inbound_quota);
            buffer.read(this->outbound_quota);
            buffer.read(this->default_timeout);
        }

      private:
        // FSCTL_PIPE_WAIT (WaitNamedPipe): whether a server instance of the name has no client yet.
        static NTSTATUS wait(windows_emulator& win_emu, const io_device_context& c);

        NTSTATUS peek(windows_emulator& win_emu, const io_device_context& c)
        {
            constexpr auto header_size = static_cast<ULONG>(sizeof(file_pipe_peek_buffer));
            if (!c.output_buffer || c.output_buffer_length < header_size)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto available = this->queued_bytes();

            // Peeking is non-destructive: copy as much queued data as the caller's buffer holds.
            const auto data_capacity = static_cast<size_t>(c.output_buffer_length - header_size);
            std::string data;
            for (const auto& chunk : this->read_queue)
            {
                if (data.size() >= data_capacity)
                {
                    break;
                }

                data.append(chunk, 0, std::min(data_capacity - data.size(), chunk.size()));
            }

            file_pipe_peek_buffer header{};
            header.named_pipe_state = FILE_PIPE_CONNECTED_STATE;
            header.read_data_available = static_cast<ULONG>(available);
            header.number_of_messages = 0;
            header.message_length = this->read_queue.empty() ? 0 : static_cast<ULONG>(this->read_queue.front().size());

            auto& emu = win_emu.emu();
            emu.write_memory(c.output_buffer, &header, sizeof(header));
            if (!data.empty())
            {
                emu.write_memory(c.output_buffer + header_size, data.data(), data.size());
            }

            if (c.io_status_block)
            {
                c.io_status_block.access(
                    [&](IO_STATUS_BLOCK<EmulatorTraits<Emu64>>& sb) { sb.Information = header_size + static_cast<uint32_t>(data.size()); });
            }

            return available > data.size() ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        }
    };

    // A pipe's name without the \Device\NamedPipe\ or \??\pipe\ prefix, lower case; empty for the prefix itself.
    std::u16string pipe_short_name(std::u16string_view path);

    // The end of pipe instance `instance` that is (or is not) the server, if it is open.
    named_pipe* find_pipe_end(process_context& process, uint64_t instance, bool server);

    inline named_pipe* find_pipe_peer(process_context& process, const named_pipe& end)
    {
        return find_pipe_end(process, end.instance, !end.server);
    }

    // How many more bytes `reader` takes before its buffer quota (the server's inbound quota for the server, its outbound
    // quota for the client; 4096 where none was given, as CreatePipe's default) is full.
    size_t pipe_room(process_context& process, const named_pipe& reader);

    // A read of up to `length` bytes into `buffer`, if it can complete now: STATUS_SUCCESS with what the other end
    // wrote (STATUS_BUFFER_OVERFLOW for part of a message), STATUS_PIPE_BROKEN when nothing is left and the other end
    // is closed. Writes the I/O status block when it completes. Nothing while the read has to wait.
    std::optional<NTSTATUS> read_pipe(windows_emulator& win_emu, named_pipe& pipe, uint64_t buffer, ULONG length,
                                      emulator_object<IO_STATUS_BLOCK<EmulatorTraits<Emu64>>> io_status_block);

    // Reports a completed pipe request: signals its event, posts it to the completion port (always when it had
    // pended, otherwise on success unless the handle skips that), and queues its APC on thread `thread_id`.
    void complete_pipe_io(windows_emulator& win_emu, const io_device_context& request, uint32_t thread_id, NTSTATUS status,
                          uint64_t information, bool pended);

} // namespace sogen
