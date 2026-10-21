#pragma once
#include "../io_device.hpp"
#include "../windows_emulator.hpp"
#include <utils/host_pipe.hpp>

namespace sogen
{
    // FSCTL_PIPE_PEEK = CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
    constexpr ULONG FSCTL_PIPE_PEEK = 0x11400C;
    constexpr ULONG FSCTL_PIPE_LISTEN = 0x110008;
    // FSCTL_PIPE_DISCONNECT (DisconnectNamedPipe), on a server end.
    constexpr ULONG FSCTL_PIPE_DISCONNECT = 0x110004;
    // FSCTL_PIPE_WAIT (WaitNamedPipe), on the \Device\NamedPipe\ root.
    constexpr ULONG FSCTL_PIPE_WAIT = 0x110018;
    constexpr ULONG FILE_PIPE_CONNECTED_STATE = 3;
    constexpr ULONG FILE_PIPE_COMPLETE_OPERATION = 1;

    // FILE_PIPE_INFORMATION (FilePipeInformation): FILE_PIPE_BYTE_STREAM_MODE or _MESSAGE_MODE, and
    // FILE_PIPE_QUEUE_OPERATION or _COMPLETE_OPERATION (PIPE_NOWAIT).
    struct file_pipe_information
    {
        ULONG read_mode;
        ULONG completion_mode;
    };

    // Header of FILE_PIPE_PEEK_BUFFER; the peeked data follows immediately after.
    struct file_pipe_peek_buffer
    {
        ULONG named_pipe_state;
        ULONG read_data_available;
        ULONG number_of_messages;
        ULONG message_length;
    };

    class named_pipe : public io_device
    {
      public:
        std::u16string name;
        std::shared_ptr<utils::host_pipe> endpoint;
        std::shared_ptr<utils::host_pipe> unopened_peer;
        ULONG pipe_type{};
        ULONG read_mode{};
        ULONG completion_mode{};
        ULONG max_instances{};
        ULONG inbound_quota{};
        ULONG outbound_quota{};
        ULONG create_options{};
        bool signaled{true};
        // The end NtCreateNamedPipeFile created, as opposed to a client that opened it.
        bool server{};
        // Clients reach an anonymous pipe's server only through its handle, never by name.
        bool anonymous{};
        LARGE_INTEGER default_timeout{};

        void create(windows_emulator&, const io_device_creation_data&) override
        {
        }

        void work(windows_emulator& win_emu) override;
        bool cancel_io(windows_emulator& win_emu, uint64_t io_status_block, std::optional<uint32_t> issuing_thread_id = {}) override;
        bool has_pending_io(uint32_t issuing_thread_id) const override;
        void release_references(process_context& process) override;
        NTSTATUS start_io(windows_emulator& win_emu, io_device_context context, bool reading);
        void copy_configuration(const named_pipe& source);

        NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& c) override
        {
            if (c.io_control_code == FSCTL_PIPE_LISTEN)
            {
                return this->start_listen(win_emu, c);
            }
            if (c.io_control_code == FSCTL_PIPE_PEEK)
            {
                return this->peek(win_emu, c);
            }
            if (c.io_control_code == FSCTL_PIPE_DISCONNECT)
            {
                return this->disconnect(win_emu);
            }
            if (c.io_control_code == FSCTL_PIPE_WAIT)
            {
                return wait(win_emu, c);
            }

            win_emu.log.warn("Unsupported named pipe FSCTL: 0x%X\n", static_cast<uint32_t>(c.io_control_code));
            return STATUS_NOT_SUPPORTED;
        }

        // Bytes the other end wrote that wait to be read.
        uint32_t bytes_available() const
        {
            uint32_t available{};
            std::string data;
            if (!this->endpoint || this->endpoint->peek(data, 0, available).status != utils::pipe_io_status::success)
            {
                return 0;
            }
            return available;
        }

        void serialize_object(utils::buffer_serializer& buffer) const override;
        void deserialize_object(utils::buffer_deserializer& buffer) override;

      private:
        enum class operation_kind
        {
            read,
            write,
            listen,
        };

        struct pending_operation
        {
            io_device_context context;
            std::unique_ptr<utils::host_pipe_operation> operation{};
            handle issuing_thread{};
            operation_kind kind{};
        };

        std::vector<pending_operation> pending_;

        NTSTATUS start_listen(windows_emulator& win_emu, io_device_context context);

        // Drops the client (its end breaks) and what it wrote; the server end can listen for the next client.
        NTSTATUS disconnect(windows_emulator& win_emu);

        // Whether a server instance of the name has no client yet.
        static NTSTATUS wait(windows_emulator& win_emu, const io_device_context& c);
        NTSTATUS enqueue_operation(windows_emulator& win_emu, io_device_context context,
                                   std::unique_ptr<utils::host_pipe_operation> operation, operation_kind kind);

        void complete(windows_emulator& win_emu, const pending_operation& operation, utils::pipe_io_result result, bool was_pending);
        static void release_operation(process_context& process, pending_operation& operation);

        NTSTATUS peek(windows_emulator& win_emu, const io_device_context& c) const
        {
            constexpr auto header_size = static_cast<ULONG>(sizeof(file_pipe_peek_buffer));
            if (!c.output_buffer || c.output_buffer_length < header_size)
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (!this->endpoint)
            {
                return STATUS_INVALID_HANDLE;
            }
            uint32_t available{};
            std::string data;
            const auto result = this->endpoint->peek(data, c.output_buffer_length - header_size, available);
            if (result.status != utils::pipe_io_status::success)
            {
                return result.status == utils::pipe_io_status::broken ? STATUS_PIPE_BROKEN : STATUS_UNSUCCESSFUL;
            }

            file_pipe_peek_buffer header{};
            header.named_pipe_state = FILE_PIPE_CONNECTED_STATE;
            header.read_data_available = static_cast<ULONG>(available);
            header.number_of_messages = 0;
            header.message_length = 0;

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
