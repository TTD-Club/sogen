#pragma once
#include "../io_device.hpp"

namespace sogen
{
    // FSCTL_PIPE_PEEK = CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
    constexpr ULONG FSCTL_PIPE_PEEK = 0x11400C;
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

    // One end of a pipe. The two ends of a pipe instance share `instance` (0: no instance, e.g. the
    // \Device\NamedPipe\ root a CreatePipe opens first); what one end writes waits in the other end's read_queue.
    class named_pipe : public io_device
    {
      public:
        std::u16string name;
        // Data written by the other end, not read yet.
        std::deque<std::string> read_queue;
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

        void work(windows_emulator&) override
        {
        }

        NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& c) override
        {
            if (c.io_control_code == FSCTL_PIPE_PEEK)
            {
                return this->peek(win_emu, c);
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
        NTSTATUS peek(windows_emulator& win_emu, const io_device_context& c)
        {
            constexpr auto header_size = static_cast<ULONG>(sizeof(file_pipe_peek_buffer));
            if (!c.output_buffer || c.output_buffer_length < header_size)
            {
                return STATUS_INVALID_PARAMETER;
            }

            size_t available = 0;
            for (const auto& chunk : this->read_queue)
            {
                available += chunk.size();
            }

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

} // namespace sogen
