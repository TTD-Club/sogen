#include "../std_include.hpp"
#include "afd_endpoint.hpp"
#include "../io_completion_wait.hpp"
#include "afd_types.hpp"

#include "../windows_emulator.hpp"
#include "../network/socket_factory.hpp"

#include <algorithm>
#include <network/address.hpp>
#include <network/socket.hpp>

#include <utils/finally.hpp>
#include <utils/time.hpp>

namespace sogen
{

    namespace
    {
        // NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

        struct afd_creation_data
        {
            uint64_t unk1;
            char afd_open_packet_xx[0x10];
            uint64_t unk2;
            int address_family;
            int type;
            int protocol;

            // ...

            friend void serialize(utils::buffer_serializer& buffer, const afd_creation_data& value)
            {
                buffer.write_zero_padded(value, &afd_creation_data::unk1, &afd_creation_data::afd_open_packet_xx, &afd_creation_data::unk2,
                                         &afd_creation_data::address_family, &afd_creation_data::type, &afd_creation_data::protocol);
            }
        };

        struct win_sockaddr
        {
            int16_t sa_family;
            uint8_t sa_data[14];
        };

        struct win_sockaddr_in
        {
            int16_t sin_family;
            uint16_t sin_port;
            in_addr sin_addr;
            uint8_t sin_zero[8];
        };

        struct win_sockaddr_in6
        {
            int16_t sin6_family;
            uint16_t sin6_port;
            uint32_t sin6_flowinfo;
            in6_addr sin6_addr;
            uint32_t sin6_scope_id;
        };

        // NOLINTEND(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

        static_assert(sizeof(win_sockaddr) == 16);
        static_assert(sizeof(win_sockaddr_in) == 16);
        static_assert(sizeof(win_sockaddr_in6) == 28);

        static_assert(sizeof(win_sockaddr_in::sin_addr) == 4);
        static_assert(sizeof(win_sockaddr_in6::sin6_addr) == 16);
        static_assert(sizeof(win_sockaddr_in6::sin6_flowinfo) == sizeof(sockaddr_in6::sin6_flowinfo));
        static_assert(sizeof(win_sockaddr_in6::sin6_scope_id) == sizeof(sockaddr_in6::sin6_scope_id));

        struct socket_mapping
        {
            int win_value;
            int host_value;
        };

        constexpr std::array address_family_map{
            socket_mapping{.win_value = 0, .host_value = AF_UNSPEC},
            socket_mapping{.win_value = 2, .host_value = AF_INET},
            socket_mapping{.win_value = 23, .host_value = AF_INET6},
        };

        constexpr std::array socket_type_map{
            socket_mapping{.win_value = 0, .host_value = 0},          socket_mapping{.win_value = 1, .host_value = SOCK_STREAM},
            socket_mapping{.win_value = 2, .host_value = SOCK_DGRAM}, socket_mapping{.win_value = 3, .host_value = SOCK_RAW},
            socket_mapping{.win_value = 4, .host_value = SOCK_RDM},
        };

        constexpr std::array socket_protocol_map{
            socket_mapping{.win_value = 0, .host_value = 0},
            socket_mapping{.win_value = 6, .host_value = IPPROTO_TCP},
            socket_mapping{.win_value = 17, .host_value = IPPROTO_UDP},
            socket_mapping{.win_value = 255, .host_value = IPPROTO_RAW},
        };

        int16_t translate_host_to_win_address_family(const int host_af)
        {
            for (const auto& entry : address_family_map)
            {
                if (entry.host_value == host_af)
                {
                    return static_cast<int16_t>(entry.win_value);
                }
            }

            throw std::runtime_error("Unknown host address family: " + std::to_string(host_af));
        }

        int translate_win_to_host_address_family(const int win_af)
        {
            for (const auto& entry : address_family_map)
            {
                if (entry.win_value == win_af)
                {
                    return entry.host_value;
                }
            }

            throw std::runtime_error("Unknown address family: " + std::to_string(win_af));
        }

        int translate_win_to_host_type(const int win_type)
        {
            for (const auto& entry : socket_type_map)
            {
                if (entry.win_value == win_type)
                {
                    return entry.host_value;
                }
            }

            throw std::runtime_error("Unknown socket type: " + std::to_string(win_type));
        }

        int translate_win_to_host_protocol(const int win_protocol)
        {
            for (const auto& entry : socket_protocol_map)
            {
                if (entry.win_value == win_protocol)
                {
                    return entry.host_value;
                }
            }

            throw std::runtime_error("Unknown socket protocol: " + std::to_string(win_protocol));
        }

        std::vector<std::byte> convert_to_win_address(const windows_emulator& win_emu, const network::address& a)
        {
            if (a.is_ipv4())
            {
                win_sockaddr_in win_addr{};
                win_addr.sin_family = translate_host_to_win_address_family(a.get_family());
                win_addr.sin_port = htons(win_emu.get_emulator_port(a.get_port()));
                memcpy(&win_addr.sin_addr, &a.get_in_addr().sin_addr, sizeof(win_addr.sin_addr));

                const auto* ptr = reinterpret_cast<std::byte*>(&win_addr);
                return {ptr, ptr + sizeof(win_addr)};
            }

            if (a.is_ipv6())
            {
                win_sockaddr_in6 win_addr{};
                win_addr.sin6_family = translate_host_to_win_address_family(a.get_family());
                win_addr.sin6_port = htons(win_emu.get_emulator_port(a.get_port()));

                const auto& addr = a.get_in6_addr();
                memcpy(&win_addr.sin6_addr, &addr.sin6_addr, sizeof(win_addr.sin6_addr));
                win_addr.sin6_flowinfo = addr.sin6_flowinfo;
                win_addr.sin6_scope_id = addr.sin6_scope_id;

                const auto* ptr = reinterpret_cast<std::byte*>(&win_addr);
                return {ptr, ptr + sizeof(win_addr)};
            }

            throw std::runtime_error("Unsupported host address family for conversion: " + std::to_string(a.get_family()));
        }

        void report_socket_activity(windows_emulator& win_emu, const network::socket_activity activity,
                                    const network::address& host_address)
        {
            if (!win_emu.callbacks.on_socket_activity)
            {
                return;
            }

            auto guest_address = host_address;
            guest_address.set_port(win_emu.get_emulator_port(host_address.get_port()));
            win_emu.callbacks.on_socket_activity(activity, guest_address);
        }

        network::address convert_to_host_address(const windows_emulator& win_emu, const std::span<const std::byte> data)
        {
            if (data.size() < sizeof(win_sockaddr))
            {
                throw std::runtime_error("Bad address size");
            }

            win_sockaddr win_addr{};
            memcpy(&win_addr, data.data(), sizeof(win_addr));

            const auto family = translate_win_to_host_address_family(win_addr.sa_family);

            network::address a{};

            if (family == AF_INET)
            {
                if (data.size() < sizeof(win_sockaddr_in))
                {
                    throw std::runtime_error("Bad IPv4 address size");
                }

                win_sockaddr_in win_addr4{};
                memcpy(&win_addr4, data.data(), sizeof(win_addr4));

                a.set_ipv4(win_addr4.sin_addr);
                a.set_port(win_emu.get_host_port(ntohs(win_addr4.sin_port)));

                return a;
            }

            if (family == AF_INET6)
            {
                if (data.size() < sizeof(win_sockaddr_in6))
                {
                    throw std::runtime_error("Bad IPv6 address size");
                }

                win_sockaddr_in6 win_addr6{};
                memcpy(&win_addr6, data.data(), sizeof(win_addr6));

                a.set_ipv6(win_addr6.sin6_addr);
                a.set_port(ntohs(win_addr6.sin6_port));

                auto& addr = a.get_in6_addr();
                addr.sin6_flowinfo = win_addr6.sin6_flowinfo;
                addr.sin6_scope_id = win_addr6.sin6_scope_id;

                return a;
            }

            throw std::runtime_error("Unsupported win address family for conversion: " + std::to_string(family));
        }

        afd_creation_data get_creation_data(windows_emulator& win_emu, const io_device_creation_data& data)
        {
            if (!data.buffer || data.length < sizeof(afd_creation_data))
            {
                throw std::runtime_error("Bad AFD creation data");
            }

            return win_emu.emu().read_memory<afd_creation_data>(data.buffer);
        }

        template <typename Traits>
        std::pair<AFD_POLL_INFO<Traits>, std::vector<AFD_POLL_HANDLE_INFO<Traits>>> get_poll_info(windows_emulator& win_emu,
                                                                                                  const io_device_context& c)
        {
            constexpr auto info_size = offsetof(AFD_POLL_INFO<Traits>, Handles);
            if (!c.input_buffer || c.input_buffer_length < info_size || c.input_buffer != c.output_buffer)
            {
                throw std::runtime_error("Bad AFD poll data");
            }

            AFD_POLL_INFO<Traits> poll_info{};
            win_emu.emu().read_memory(c.input_buffer, &poll_info, info_size);

            std::vector<AFD_POLL_HANDLE_INFO<Traits>> handle_info{};

            const emulator_object<AFD_POLL_HANDLE_INFO<Traits>> handle_info_obj{win_emu.emu(), c.input_buffer + info_size};

            if (c.input_buffer_length < (info_size + (sizeof(AFD_POLL_HANDLE_INFO<Traits>) * poll_info.NumberOfHandles)))
            {
                throw std::runtime_error("Bad AFD poll handle data");
            }

            handle_info.reserve(poll_info.NumberOfHandles);
            for (ULONG i = 0; i < poll_info.NumberOfHandles; ++i)
            {
                handle_info.emplace_back(handle_info_obj.read(i));
            }

            return {poll_info, std::move(handle_info)};
        }

        int16_t map_afd_request_events_to_socket(const ULONG poll_events)
        {
            int16_t socket_events{};

            if (poll_events & (AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT | AFD_POLL_RECEIVE))
            {
                socket_events |= POLLRDNORM;
            }

            if (poll_events & AFD_POLL_RECEIVE_EXPEDITED)
            {
                socket_events |= POLLRDBAND;
            }

            if (poll_events & (AFD_POLL_CONNECT | AFD_POLL_CONNECT_FAIL | AFD_POLL_SEND))
            {
                socket_events |= POLLWRNORM;
            }

            return socket_events;
        }

        ULONG map_socket_response_events_to_afd(const int16_t socket_events, const ULONG afd_poll_events, const bool is_listening,
                                                const bool is_connecting)
        {
            ULONG afd_events = 0;

            if (socket_events & POLLRDNORM)
            {
                if (!is_listening && afd_poll_events & AFD_POLL_RECEIVE)
                {
                    afd_events |= AFD_POLL_RECEIVE;
                }
                else if (is_listening && afd_poll_events & AFD_POLL_ACCEPT)
                {
                    afd_events |= AFD_POLL_ACCEPT;
                }
            }

            if (socket_events & POLLRDBAND && afd_poll_events & AFD_POLL_RECEIVE_EXPEDITED)
            {
                afd_events |= AFD_POLL_RECEIVE_EXPEDITED;
            }

            const bool has_host_error = (socket_events & POLLERR) != 0;
            const bool has_host_hangup = (socket_events & POLLHUP) != 0;
            const bool has_connect_failure = has_host_error || has_host_hangup;
            if ((socket_events & POLLWRNORM) && !has_connect_failure)
            {
                if (afd_poll_events & AFD_POLL_SEND)
                {
                    afd_events |= AFD_POLL_SEND;
                }

                if (is_connecting && afd_poll_events & AFD_POLL_CONNECT)
                {
                    afd_events |= AFD_POLL_CONNECT;
                }
            }

            if (is_connecting && has_connect_failure && afd_poll_events & AFD_POLL_CONNECT_FAIL)
            {
                afd_events |= AFD_POLL_CONNECT_FAIL;
            }

            if (has_host_error && has_host_hangup && afd_poll_events & AFD_POLL_ABORT)
            {
                afd_events |= AFD_POLL_ABORT;
            }
            else if (has_host_hangup && !has_host_error && afd_poll_events & AFD_POLL_DISCONNECT)
            {
                afd_events |= AFD_POLL_DISCONNECT;
            }

            if (socket_events & POLLNVAL && afd_poll_events & AFD_POLL_LOCAL_CLOSE)
            {
                afd_events |= AFD_POLL_LOCAL_CLOSE;
            }

            return afd_events;
        }

        template <typename Traits>
        struct afd_endpoint : io_device
        {
            using status_block = IO_STATUS_BLOCK<EmulatorTraits<Emu64>>;

            struct pending_connection
            {
                network::address remote_address;
                std::unique_ptr<network::i_socket> accepted_socket;
            };

            // What a receive or send references, captured when it is issued: mswsock builds the AFD request on its
            // stack, and WSARecv/WSASend let the caller reuse the WSABUF array once an overlapped call returns.
            struct transfer_request
            {
                ULONG afd_flags{};
                std::vector<EMU_WSABUF<Traits>> buffers{};
                uint64_t address{};
                uint64_t address_length{};
                std::vector<std::byte> remote_address{};

                void serialize(utils::buffer_serializer& buffer) const
                {
                    buffer.write(this->afd_flags);
                    buffer.write_vector(this->buffers);
                    buffer.write(this->address);
                    buffer.write(this->address_length);
                    buffer.write_vector(this->remote_address);
                }

                void deserialize(utils::buffer_deserializer& buffer)
                {
                    buffer.read(this->afd_flags);
                    buffer.read_vector(this->buffers);
                    buffer.read(this->address);
                    buffer.read(this->address_length);
                    buffer.read_vector(this->remote_address);
                }
            };

            std::unique_ptr<network::i_socket> s_{};

            bool executing_delayed_ioctl_{};
            std::optional<transfer_request> delayed_request_{};
            bool connect_failed_{};
            std::optional<afd_creation_data> creation_data{};
            std::optional<bool> require_poll_{};
            std::optional<io_device_context> delayed_ioctl_{};
            handle retained_completion_port_{};
            std::optional<std::chrono::steady_clock::time_point> timeout_{};
            std::optional<std::function<void(windows_emulator&, const io_device_context&)>> timeout_callback_{};

            std::unordered_map<LONG, pending_connection> pending_connections_{};
            LONG next_sequence_{0};

            static constexpr ULONG max_stream_buffer_count = 1024;

            // Stream operations may complete partially, so cap staging allocations instead of trusting guest-provided WSABUF lengths.
            static constexpr size_t max_stream_transfer_bytes = 64u << 20;

            std::optional<handle> event_select_event_{};
            ULONG event_select_mask_{0};
            ULONG triggered_events_{0};

            // Reflects the guest socket's blocking mode (FIONBIO). mswsock keeps this in its per-socket
            // SOCK_SHARED_INFO and pushes the whole structure to the kernel via AFD_SET_CONTEXT; the
            // NonBlocking flag is bit 6 of the option bitfield at offset 0x2c. When set, an operation that
            // would block must fail immediately with STATUS_DEVICE_NOT_READY (which mswsock maps to
            // WSAEWOULDBLOCK) instead of pending, because the guest's synchronous recv/send call would
            // otherwise wait forever on a packet that never arrives.
            bool non_blocking_{false};
            std::vector<std::byte> shared_context_{};

            // AFD_POLL requests (select, WSAPoll) waiting for a socket event. They pend beside the delayed request:
            // a select for a non-blocking connect's completion is issued while that connect is still pending.
            struct pending_poll
            {
                io_device_context context;
                std::optional<std::chrono::steady_clock::time_point> timeout{};
                handle retained_completion_port{};

                pending_poll(memory_interface& emu)
                    : context(emu)
                {
                }

                pending_poll(const io_device_context& context, const std::optional<std::chrono::steady_clock::time_point> timeout)
                    : context(context),
                      timeout(timeout)
                {
                }

                pending_poll(utils::buffer_deserializer& buffer)
                    : context(buffer)
                {
                }

                void serialize(utils::buffer_serializer& buffer) const
                {
                    this->context.serialize(buffer);
                    buffer.write_optional(this->timeout);
                    buffer.write(this->retained_completion_port);
                }

                void deserialize(utils::buffer_deserializer& buffer)
                {
                    this->context.deserialize(buffer);
                    buffer.read_optional(this->timeout);
                    buffer.read(this->retained_completion_port);
                }
            };

            std::vector<pending_poll> pending_polls_{};

            afd_endpoint()
            {
                network::initialize_wsa();
            }

            afd_endpoint(afd_endpoint&&) = delete;
            afd_endpoint& operator=(afd_endpoint&&) = delete;

            ~afd_endpoint() override = default;

            void create(windows_emulator& win_emu, const io_device_creation_data& data) override
            {
                this->creation_data = get_creation_data(win_emu, data);
                this->setup(win_emu.socket_factory());
            }

            void set_socket(std::unique_ptr<network::i_socket> socket)
            {
                this->s_ = std::move(socket);
                if (this->s_)
                {
                    this->s_->set_blocking(false);
                }
            }

            bool has_pending_io(const uint32_t issuing_thread_id) const override
            {
                return (this->delayed_ioctl_ && this->delayed_ioctl_->issuing_thread_id == issuing_thread_id) ||
                       std::ranges::any_of(this->pending_polls_, [issuing_thread_id](const pending_poll& poll) {
                           return poll.context.issuing_thread_id == issuing_thread_id;
                       });
            }

            bool cancel_io(windows_emulator& win_emu, const uint64_t io_status_block,
                           const std::optional<uint32_t> issuing_thread_id = {}) override
            {
                const auto matches = [&](const io_device_context& context) {
                    return (!io_status_block || context.io_status_block.value() == io_status_block) &&
                           (!issuing_thread_id || context.issuing_thread_id == *issuing_thread_id);
                };

                bool cancelled = false;
                for (auto it = this->pending_polls_.begin(); it != this->pending_polls_.end();)
                {
                    if (!matches(it->context))
                    {
                        ++it;
                        continue;
                    }

                    this->complete_io(win_emu, it->context, STATUS_CANCELLED);
                    io_completion_wait::release_handle_reference(win_emu.process, it->retained_completion_port);
                    it = this->pending_polls_.erase(it);
                    cancelled = true;
                }

                if (!this->delayed_ioctl_ || !matches(*this->delayed_ioctl_))
                {
                    return cancelled;
                }

                this->complete_io(win_emu, *this->delayed_ioctl_, STATUS_CANCELLED);
                this->clear_pending_state(win_emu);
                return true;
            }

            void release_references(process_context& process) override
            {
                io_completion_wait::release_handle_reference(process, this->retained_completion_port_);
                for (auto& poll : this->pending_polls_)
                {
                    io_completion_wait::release_handle_reference(process, poll.retained_completion_port);
                }
            }

            // A poll that timed out reports no handles.
            static void complete_poll_timeout(windows_emulator& win_emu, const io_device_context& c)
            {
                const emulator_object<AFD_POLL_INFO<Traits>> info_obj{win_emu.emu(), c.input_buffer};
                info_obj.access([&](AFD_POLL_INFO<Traits>& poll_info) {
                    poll_info.NumberOfHandles = 0; //
                });
            }

            NTSTATUS queue_poll(windows_emulator& win_emu, const io_device_context& c,
                                const std::optional<std::chrono::steady_clock::time_point> timeout)
            {
                handle retained_port{};
                const auto* active_thread = c.vcpu ? &c.thread() : nullptr;
                if (!io_completion_wait::retain_handle_reference(win_emu.process, active_thread, c.completion_port, retained_port))
                {
                    return STATUS_INVALID_HANDLE;
                }

                auto request = c;
                request.completion_port = retained_port;
                this->pending_polls_.emplace_back(request, timeout);
                this->pending_polls_.back().retained_completion_port = retained_port;
                return STATUS_PENDING;
            }

            // Completes the pending polls whose sockets are ready or whose time is up.
            void work_polls(windows_emulator& win_emu)
            {
                for (auto it = this->pending_polls_.begin(); it != this->pending_polls_.end();)
                {
                    const auto [info, handles] = get_poll_info<Traits>(win_emu, it->context);
                    const auto endpoints = resolve_endpoints(win_emu, handles);
                    auto status = perform_poll(win_emu, it->context, endpoints, handles);

                    if (status == STATUS_PENDING)
                    {
                        if (!it->timeout || *it->timeout > win_emu.clock().steady_now())
                        {
                            ++it;
                            continue;
                        }

                        complete_poll_timeout(win_emu, it->context);
                        status = STATUS_TIMEOUT;
                    }

                    this->complete_io(win_emu, it->context, status);
                    io_completion_wait::release_handle_reference(win_emu.process, it->retained_completion_port);
                    it = this->pending_polls_.erase(it);
                }
            }

            void complete_io(windows_emulator& win_emu, const io_device_context& context, const NTSTATUS status)
            {
                write_io_status(context, status);
                if (auto* event = win_emu.process.events.get(context.event))
                {
                    event->signaled = true;
                    win_emu.wake_idle_vcpu();
                }
                io_device::queue_io_completion(win_emu, context);
            }

            void setup(network::socket_factory& factory)
            {
                if (!this->creation_data)
                {
                    return;
                }

                const auto& data = *this->creation_data;

                const auto af = translate_win_to_host_address_family(data.address_family);
                const auto type = translate_win_to_host_type(data.type);
                const auto protocol = translate_win_to_host_protocol(data.protocol);

                this->set_socket(factory.create_socket(af, type, protocol));
                if (!this->s_)
                {
                    throw std::runtime_error("Failed to create socket!");
                }
            }

            NTSTATUS delay_ioctrl(
                windows_emulator& win_emu, const io_device_context& c, const std::optional<bool> require_poll = {},
                const std::optional<std::chrono::steady_clock::time_point> timeout = {},
                const std::optional<std::function<void(windows_emulator&, const io_device_context&)>>& timeout_callback = {})
            {
                if (this->executing_delayed_ioctl_)
                {
                    return STATUS_PENDING;
                }

                if (this->delayed_ioctl_)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                handle retained_port{};
                const auto* active_thread = c.vcpu ? &c.thread() : nullptr;
                if (!io_completion_wait::retain_handle_reference(win_emu.process, active_thread, c.completion_port, retained_port))
                {
                    return STATUS_INVALID_HANDLE;
                }

                this->timeout_callback_ = timeout_callback;
                this->timeout_ = timeout;
                this->require_poll_ = require_poll;
                this->delayed_ioctl_ = c;
                this->delayed_ioctl_->completion_port = retained_port;
                this->retained_completion_port_ = retained_port;
                return STATUS_PENDING;
            }

            void clear_pending_state(windows_emulator& win_emu)
            {
                io_completion_wait::release_handle_reference(win_emu.process, this->retained_completion_port_);
                this->timeout_callback_ = {};
                this->timeout_ = {};
                this->require_poll_ = {};
                this->delayed_ioctl_ = {};
                this->delayed_request_ = {};
            }

            void update_shared_info(windows_emulator& win_emu, const io_device_context& c)
            {
                this->shared_context_ = win_emu.emu().read_memory(c.input_buffer, c.input_buffer_length);

                constexpr size_t option_flags_offset = 0x2c;
                constexpr ULONG non_blocking_flag = 1u << 6;
                if (c.input_buffer_length < option_flags_offset + sizeof(ULONG))
                {
                    return;
                }

                const auto option_flags = win_emu.emu().read_memory<ULONG>(c.input_buffer + option_flags_offset);
                this->non_blocking_ = (option_flags & non_blocking_flag) != 0;
            }

            NTSTATUS ioctl_set_information(windows_emulator& win_emu, const io_device_context& c)
            {
                if (c.input_buffer_length < sizeof(AFD_INFORMATION))
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto info = win_emu.emu().read_memory<AFD_INFORMATION>(c.input_buffer);
                if (info.InformationClass == AFD_INFO_BLOCKING_MODE)
                {
                    this->non_blocking_ = info.Information.Boolean != FALSE;
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_get_context(windows_emulator& win_emu, const io_device_context& c) const
            {
                if (c.output_buffer_length < this->shared_context_.size())
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                if (!this->shared_context_.empty())
                {
                    win_emu.emu().write_memory(c.output_buffer, this->shared_context_.data(), this->shared_context_.size());
                }

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = static_cast<ULONG>(this->shared_context_.size());
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            // For a non-blocking socket an operation that would block must complete immediately with
            // STATUS_DEVICE_NOT_READY (mapped to WSAEWOULDBLOCK by mswsock); a blocking socket instead pends
            // the request and the delayed-ioctl machinery resumes it once the host socket is ready. Overlapped
            // requests (AFD_OVERLAPPED, set for WSARecv/WSASend with an OVERLAPPED) pend on non-blocking sockets too.
            NTSTATUS pend_or_would_block(windows_emulator& win_emu, const io_device_context& c, const bool require_poll,
                                         const transfer_request& request)
            {
                constexpr ULONG afd_overlapped = 0x2;
                if (this->non_blocking_ && !(request.afd_flags & afd_overlapped))
                {
                    return STATUS_DEVICE_NOT_READY;
                }

                const auto status = this->delay_ioctrl(win_emu, c, require_poll);
                if (status == STATUS_PENDING && !this->executing_delayed_ioctl_)
                {
                    this->delayed_request_ = request;
                }
                return status;
            }

            template <typename Info>
            NTSTATUS read_stream_request(windows_emulator& win_emu, const io_device_context& c, transfer_request& request) const
            {
                if (this->executing_delayed_ioctl_ && this->delayed_request_)
                {
                    request = *this->delayed_request_;
                    return STATUS_SUCCESS;
                }

                if (c.input_buffer_length < sizeof(Info))
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto info = win_emu.emu().read_memory<Info>(c.input_buffer);
                if (!info.BufferArray || info.BufferCount == 0 || info.BufferCount > max_stream_buffer_count)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                request.afd_flags = info.AfdFlags;
                request.buffers.resize(info.BufferCount);
                win_emu.emu().read_memory(info.BufferArray, request.buffers.data(), request.buffers.size() * sizeof(EMU_WSABUF<Traits>));
                return STATUS_SUCCESS;
            }

            void work(windows_emulator& win_emu) override
            {
                this->work_polls(win_emu);

                const bool has_pending_work = this->delayed_ioctl_ || this->event_select_mask_;
                if (!this->s_ || !has_pending_work)
                {
                    return;
                }

                network::poll_entry pfd{};
                pfd.s = this->s_.get();

                if (this->delayed_ioctl_ && this->require_poll_.has_value())
                {
                    pfd.events |= *this->require_poll_ ? POLLIN : POLLOUT;
                }
                if (this->event_select_mask_)
                {
                    pfd.events = static_cast<int16_t>(pfd.events | map_afd_request_events_to_socket(this->event_select_mask_));
                }
                pfd.revents = pfd.events;

                if (pfd.events != 0)
                {
                    win_emu.socket_factory().poll_sockets(std::span{&pfd, 1});
                }

                const auto socket_events = static_cast<int16_t>(pfd.revents | (this->connect_failed_ ? POLLERR : 0));

                if (socket_events && this->event_select_mask_)
                {
                    const bool is_connecting = this->connect_failed_ ||
                                               (this->delayed_ioctl_ && _AFD_REQUEST(this->delayed_ioctl_->io_control_code) == AFD_CONNECT);
                    ULONG current_events =
                        map_socket_response_events_to_afd(socket_events, this->event_select_mask_, pfd.s->is_listening(), is_connecting);

                    if ((current_events & ~this->triggered_events_) != 0)
                    {
                        this->triggered_events_ |= current_events;

                        if (auto* event = win_emu.process.events.get(*this->event_select_event_))
                        {
                            event->signaled = true;
                            win_emu.wake_idle_vcpu();
                        }
                    }
                }

                if (this->delayed_ioctl_)
                {
                    this->executing_delayed_ioctl_ = true;
                    const auto _ = utils::finally([&] { this->executing_delayed_ioctl_ = false; });

                    if (this->require_poll_.has_value())
                    {
                        const auto is_ready = socket_events & ((*this->require_poll_ ? POLLIN : POLLOUT) | POLLHUP | POLLERR);
                        if (!is_ready)
                        {
                            return;
                        }
                    }

                    auto status = this->io_control(win_emu, *this->delayed_ioctl_);
                    if (status == STATUS_PENDING)
                    {
                        if (!this->timeout_ || this->timeout_ > win_emu.clock().steady_now())
                        {
                            return;
                        }

                        if (this->timeout_callback_)
                        {
                            (*this->timeout_callback_)(win_emu, *this->delayed_ioctl_);
                        }
                        status = STATUS_TIMEOUT;
                    }

                    this->complete_io(win_emu, *this->delayed_ioctl_, status);
                    this->clear_pending_state(win_emu);
                }
            }

            void deserialize_object(utils::buffer_deserializer& buffer) override
            {
                buffer.read_optional(this->creation_data);
                this->setup(buffer.read<socket_factory_wrapper>());

                buffer.read_optional(this->require_poll_);
                buffer.read_optional(this->delayed_ioctl_);
                buffer.read_optional(this->delayed_request_);
                buffer.read(this->retained_completion_port_);
                buffer.read_optional(this->timeout_);
                buffer.read(this->non_blocking_);
                buffer.read(this->connect_failed_);
                buffer.read(this->shared_context_);
                buffer.read_vector(this->pending_polls_);
            }

            void serialize_object(utils::buffer_serializer& buffer) const override
            {
                buffer.write_optional(this->creation_data);
                buffer.write_optional(this->require_poll_);
                buffer.write_optional(this->delayed_ioctl_);
                buffer.write_optional(this->delayed_request_);
                buffer.write(this->retained_completion_port_);
                buffer.write_optional(this->timeout_);
                buffer.write(this->non_blocking_);
                buffer.write(this->connect_failed_);
                buffer.write(this->shared_context_);
                buffer.write_vector(this->pending_polls_);
            }

            NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& c) override
            {
                if (_AFD_BASE(c.io_control_code) != FSCTL_AFD_BASE)
                {
                    win_emu.log.error("Bad AFD IOCTL: 0x%X\n", static_cast<uint32_t>(c.io_control_code));
                    return STATUS_NOT_SUPPORTED;
                }

                const auto request = _AFD_REQUEST(c.io_control_code);

                switch (request)
                {
                case AFD_BIND:
                    return this->ioctl_bind(win_emu, c);
                case AFD_CONNECT:
                    return this->ioctl_connect(win_emu, c);
                case AFD_START_LISTEN:
                    return this->ioctl_listen(win_emu, c);
                case AFD_WAIT_FOR_LISTEN:
                    return this->ioctl_wait_for_listen(win_emu, c);
                case AFD_ACCEPT:
                    return this->ioctl_accept(win_emu, c);
                case AFD_SEND:
                    return this->ioctl_send(win_emu, c);
                case AFD_RECEIVE:
                    return this->ioctl_receive(win_emu, c);
                case AFD_SEND_DATAGRAM:
                    return this->ioctl_send_datagram(win_emu, c);
                case AFD_RECEIVE_DATAGRAM:
                    return this->ioctl_receive_datagram(win_emu, c);
                case AFD_POLL:
                    return this->ioctl_poll(win_emu, c);
                case AFD_GET_ADDRESS:
                    return this->ioctl_get_address(win_emu, c);
                case AFD_GET_CONTEXT:
                    return this->ioctl_get_context(win_emu, c);
                case AFD_EVENT_SELECT:
                    return this->ioctl_event_select(win_emu, c);
                case AFD_ENUM_NETWORK_EVENTS:
                    return this->ioctl_enum_network_events(win_emu, c);
                case AFD_SET_CONTEXT:
                    this->update_shared_info(win_emu, c);
                    return STATUS_SUCCESS;
                case AFD_SET_INFORMATION:
                    return this->ioctl_set_information(win_emu, c);
                case AFD_GET_INFORMATION:
                case AFD_QUERY_HANDLES:
                case AFD_TRANSPORT_IOCTL:
                case AFD_PARTIAL_DISCONNECT:
                    return STATUS_SUCCESS;
                default:
                    win_emu.log.error("Unsupported AFD IOCTL: 0x%X (%u)\n", static_cast<uint32_t>(c.io_control_code),
                                      static_cast<uint32_t>(request));
                    return STATUS_NOT_SUPPORTED;
                }
            }

            NTSTATUS ioctl_connect(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                if (this->executing_delayed_ioctl_)
                {
                    const auto socket_error = this->s_->get_socket_error();
                    if (!socket_error)
                    {
                        this->connect_failed_ = true;
                        return STATUS_UNSUCCESSFUL;
                    }

                    if (*socket_error == 0)
                    {
                        this->connect_failed_ = false;
                        return STATUS_SUCCESS;
                    }

                    this->connect_failed_ = true;
                    if (*socket_error == SERR(ECONNREFUSED))
                    {
                        return STATUS_CONNECTION_REFUSED;
                    }

                    return STATUS_UNSUCCESSFUL;
                }

                this->connect_failed_ = false;
                auto data = win_emu.emu().read_memory(c.input_buffer, c.input_buffer_length);

                // AFD_CONNECT_INFO::RemoteAddress follows BOOLEAN + two ULONG_PTR (pointer-aligned): 24 on x64, 12 on WoW64.
                constexpr auto address_offset = 3 * sizeof(typename Traits::ULONG_PTR);

                if (data.size() < address_offset)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto addr = convert_to_host_address(win_emu, std::span(data).subspan(address_offset));
                report_socket_activity(win_emu, network::socket_activity::connect, addr);
                const auto connected = this->s_->connect(addr);
                if (!connected)
                {
                    const auto error = this->s_->get_last_error();

                    if (error == SERR(EINPROGRESS) || error == SERR(EWOULDBLOCK)
#ifndef _WIN32
                        || error == EAGAIN
#endif
                        || error == SERR(EALREADY))
                    {
                        return this->delay_ioctrl(win_emu, c, false);
                    }

                    if (error == SERR(ECONNREFUSED))
                    {
                        this->connect_failed_ = true;
                        return STATUS_CONNECTION_REFUSED;
                    }

                    this->connect_failed_ = true;
                    return STATUS_UNSUCCESSFUL;
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_bind(windows_emulator& win_emu, const io_device_context& c) const
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                auto data = win_emu.emu().read_memory(c.input_buffer, c.input_buffer_length);

                constexpr auto address_offset = 4;

                if (data.size() < address_offset)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto addr = convert_to_host_address(win_emu, std::span(data).subspan(address_offset));
                report_socket_activity(win_emu, network::socket_activity::bind, addr);

                if (!this->s_->bind(addr))
                {
                    return STATUS_ADDRESS_ALREADY_ASSOCIATED;
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_listen(windows_emulator& win_emu, const io_device_context& c) const
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                if (c.input_buffer_length < sizeof(AFD_LISTEN_INFO))
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto listen_info = win_emu.emu().read_memory<AFD_LISTEN_INFO>(c.input_buffer);

                if (!this->s_->listen(static_cast<int>(listen_info.MaximumConnectionQueue)))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_wait_for_listen(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                if (c.output_buffer_length < sizeof(AFD_LISTEN_RESPONSE_INFO))
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                network::address remote_address{};
                auto accepted_socket_ptr = this->s_->accept(remote_address);

                if (!accepted_socket_ptr)
                {
                    const auto error = this->s_->get_last_error();
                    if (error == SERR(EWOULDBLOCK))
                    {
                        return this->delay_ioctrl(win_emu, c, true);
                    }

                    return STATUS_UNSUCCESSFUL;
                }

                // The remote address follows the sequence number in full: a sockaddr_in, or a sockaddr_in6 (28 bytes),
                // which mswsock sizes the buffer for on an IPv6 socket.
                const auto transport_buffer = convert_to_win_address(win_emu, remote_address);
                constexpr auto address_offset = offsetof(AFD_LISTEN_RESPONSE_INFO, RemoteAddress);
                const auto response_size = std::max(sizeof(AFD_LISTEN_RESPONSE_INFO), address_offset + transport_buffer.size());
                if (c.output_buffer_length < response_size)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                pending_connection pending{};
                pending.remote_address = remote_address;
                pending.accepted_socket = std::move(accepted_socket_ptr);

                LONG sequence = next_sequence_++;
                pending_connections_.try_emplace(sequence, std::move(pending));

                std::vector<std::byte> response(response_size);
                memcpy(response.data(), &sequence, sizeof(sequence));
                memcpy(response.data() + address_offset, transport_buffer.data(), transport_buffer.size());
                win_emu.emu().write_memory(c.output_buffer, response.data(), response.size());

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = response_size;
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_accept(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                if (c.input_buffer_length < sizeof(AFD_ACCEPT_INFO<Traits>))
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto accept_info = win_emu.emu().read_memory<AFD_ACCEPT_INFO<Traits>>(c.input_buffer);

                const auto it = pending_connections_.find(accept_info.Sequence);
                if (it == pending_connections_.end())
                {
                    return STATUS_INVALID_PARAMETER;
                }

                auto& accepted_socket = it->second.accepted_socket;

                auto* target_device = win_emu.process.devices.get(accept_info.AcceptHandle);
                if (!target_device)
                {
                    return STATUS_INVALID_HANDLE;
                }

                auto* target_endpoint = target_device->template get_internal_device<afd_endpoint>();
                if (!target_endpoint)
                {
                    return STATUS_INVALID_HANDLE;
                }

                target_endpoint->set_socket(std::move(accepted_socket));

                pending_connections_.erase(it);

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_receive(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                auto& emu = win_emu.emu();

                transfer_request request{};
                if (const auto status = this->read_stream_request<AFD_RECV_INFO<Traits>>(win_emu, c, request); status != STATUS_SUCCESS)
                {
                    return status;
                }

                size_t transfer_size = 0;
                for (const auto& wsabuf : request.buffers)
                {
                    if (!wsabuf.buf && wsabuf.len != 0)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    transfer_size += std::min<size_t>(wsabuf.len, max_stream_transfer_bytes - transfer_size);
                    if (transfer_size == max_stream_transfer_bytes)
                    {
                        break;
                    }
                }

                if (transfer_size == 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                std::vector<std::byte> host_buffer;
                host_buffer.resize(transfer_size);

                const auto bytes_received = this->s_->recv(host_buffer);

                if (bytes_received < 0)
                {
                    const auto error = this->s_->get_last_error();
                    if (error == SERR(EWOULDBLOCK))
                    {
                        return this->pend_or_would_block(win_emu, c, true, request);
                    }

                    if (error == SERR(ECONNRESET))
                    {
                        return STATUS_CONNECTION_RESET;
                    }

                    return STATUS_UNSUCCESSFUL;
                }

                size_t source_offset = 0;
                for (const auto& wsabuf : request.buffers)
                {
                    const auto copy_size = std::min<size_t>(wsabuf.len, static_cast<size_t>(bytes_received) - source_offset);
                    if (copy_size == 0)
                    {
                        break;
                    }

                    emu.write_memory(wsabuf.buf, host_buffer.data() + source_offset, copy_size);
                    source_offset += copy_size;
                }

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = static_cast<uint32_t>(bytes_received);
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_send(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                auto& emu = win_emu.emu();

                transfer_request request{};
                if (const auto status = this->read_stream_request<AFD_SEND_INFO<Traits>>(win_emu, c, request); status != STATUS_SUCCESS)
                {
                    return status;
                }

                std::vector<std::byte> host_buffer{};
                host_buffer.reserve(0x1000);

                for (size_t i = 0; i < request.buffers.size() && host_buffer.size() < max_stream_transfer_bytes; ++i)
                {
                    const auto& wsabuf = request.buffers[i];
                    if (!wsabuf.buf && wsabuf.len != 0)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    const auto copy_size = std::min<size_t>(wsabuf.len, max_stream_transfer_bytes - host_buffer.size());
                    const auto offset = host_buffer.size();
                    host_buffer.resize(offset + copy_size);
                    if (copy_size != 0)
                    {
                        emu.read_memory(wsabuf.buf, host_buffer.data() + offset, copy_size);
                    }
                }

                if (host_buffer.empty())
                {
                    if (c.io_status_block)
                    {
                        c.io_status_block.write({});
                    }
                    return STATUS_SUCCESS;
                }

                const auto bytes_sent = this->s_->send(host_buffer);

                if (bytes_sent < 0)
                {
                    const auto error = this->s_->get_last_error();
                    if (error == SERR(EWOULDBLOCK))
                    {
                        return this->pend_or_would_block(win_emu, c, false, request);
                    }

                    if (error == SERR(ECONNRESET))
                    {
                        return STATUS_CONNECTION_RESET;
                    }

                    return STATUS_UNSUCCESSFUL;
                }

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = static_cast<uint32_t>(bytes_sent);
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            static std::vector<const afd_endpoint*> resolve_endpoints(windows_emulator& win_emu,
                                                                      const std::span<const AFD_POLL_HANDLE_INFO<Traits>> handles)
            {
                auto& proc = win_emu.process;

                std::vector<const afd_endpoint*> endpoints{};
                endpoints.reserve(handles.size());

                // A socket closed while a poll on it is pending stays as null and reports AFD_POLL_LOCAL_CLOSE.
                for (const auto& handle : handles)
                {
                    const auto* device = proc.devices.get(handle.Handle);
                    const auto* endpoint = device ? device->template get_internal_device<afd_endpoint<Traits>>() : nullptr;
                    endpoints.push_back(endpoint && endpoint->s_ ? endpoint : nullptr);
                }

                return endpoints;
            }

            static NTSTATUS perform_poll(windows_emulator& win_emu, const io_device_context& c,
                                         const std::span<const afd_endpoint* const> endpoints,
                                         const std::span<const AFD_POLL_HANDLE_INFO<Traits>> handles)
            {
                const auto entry_count = std::min(endpoints.size(), handles.size());

                std::vector<network::poll_entry> poll_data{};
                std::vector<size_t> poll_indices{};
                for (size_t index = 0; index < entry_count; ++index)
                {
                    if (!endpoints[index])
                    {
                        continue;
                    }

                    network::poll_entry pfd{};
                    pfd.s = endpoints[index]->s_.get();
                    pfd.events = map_afd_request_events_to_socket(handles[index].PollEvents);
                    pfd.revents = pfd.events;
                    poll_data.push_back(pfd);
                    poll_indices.push_back(index);
                }

                if (!poll_data.empty())
                {
                    win_emu.socket_factory().poll_sockets(poll_data);
                }

                std::vector<ULONG> afd_events(entry_count);
                for (size_t index = 0; index < entry_count; ++index)
                {
                    if (!endpoints[index])
                    {
                        afd_events[index] = handles[index].PollEvents & AFD_POLL_LOCAL_CLOSE;
                    }
                }

                for (size_t poll_index = 0; poll_index < poll_data.size(); ++poll_index)
                {
                    const auto index = poll_indices[poll_index];
                    const auto* endpoint = endpoints[index];
                    auto& pfd = poll_data[poll_index];
                    if (endpoint->connect_failed_)
                    {
                        pfd.revents = static_cast<int16_t>(pfd.revents | POLLERR);
                    }

                    if (pfd.revents == 0)
                    {
                        continue;
                    }

                    const bool is_connecting =
                        endpoint->connect_failed_ ||
                        (endpoint->delayed_ioctl_ && _AFD_REQUEST(endpoint->delayed_ioctl_->io_control_code) == AFD_CONNECT);

                    afd_events[index] =
                        map_socket_response_events_to_afd(pfd.revents, handles[index].PollEvents, pfd.s->is_listening(), is_connecting);
                }

                // Host readiness that maps to none of the requested AFD events (e.g. a connected socket being writable while
                // only CONNECT_FAIL is requested) must keep the poll pending; completing it would make IOCP-driven
                // pollers like mio re-arm in a busy loop.
                if (std::ranges::none_of(afd_events, [](const ULONG events) { return events != 0; }))
                {
                    return STATUS_PENDING;
                }

                constexpr auto info_size = offsetof(AFD_POLL_INFO<Traits>, Handles);
                const emulator_object<AFD_POLL_HANDLE_INFO<Traits>> handle_info_obj{win_emu.emu(), c.input_buffer + info_size};

                size_t current_index = 0;

                for (size_t source_index = 0; source_index < afd_events.size(); ++source_index)
                {
                    if (afd_events[source_index] == 0)
                    {
                        continue;
                    }

                    auto entry = handle_info_obj.read(source_index);
                    entry.PollEvents = afd_events[source_index];
                    entry.Status = STATUS_SUCCESS;

                    handle_info_obj.write(entry, current_index++);
                }

                const emulator_object<AFD_POLL_INFO<Traits>> info_obj{win_emu.emu(), c.input_buffer};
                info_obj.access([&](AFD_POLL_INFO<Traits>& info) {
                    info.NumberOfHandles = static_cast<ULONG>(current_index); //
                });

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = info_size + (sizeof(AFD_POLL_HANDLE_INFO<Traits>) * current_index);
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_poll(windows_emulator& win_emu, const io_device_context& c)
            {
                const auto [info, handles] = get_poll_info<Traits>(win_emu, c);
                const auto endpoints = resolve_endpoints(win_emu, handles);
                if (std::ranges::find(endpoints, nullptr) != endpoints.end())
                {
                    return STATUS_INVALID_HANDLE;
                }

                const auto status = perform_poll(win_emu, c, endpoints, handles);
                if (status != STATUS_PENDING)
                {
                    return status;
                }

                if (!info.Timeout.QuadPart)
                {
                    complete_poll_timeout(win_emu, c);
                    return STATUS_TIMEOUT;
                }

                std::optional<std::chrono::steady_clock::time_point> timeout{};
                if (info.Timeout.QuadPart != std::numeric_limits<int64_t>::max())
                {
                    timeout = utils::convert_delay_interval_to_time_point(win_emu.clock(), info.Timeout,
                                                                          {.QuadPart = std::numeric_limits<int64_t>::max()});
                }

                return this->queue_poll(win_emu, c, timeout);
            }

            NTSTATUS ioctl_receive_datagram(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                auto& emu = win_emu.emu();

                transfer_request request{};
                if (this->executing_delayed_ioctl_ && this->delayed_request_)
                {
                    request = *this->delayed_request_;
                }
                else
                {
                    if (c.input_buffer_length < sizeof(AFD_RECV_DATAGRAM_INFO<Traits>))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    const auto receive_info = emu.read_memory<AFD_RECV_DATAGRAM_INFO<Traits>>(c.input_buffer);
                    request.afd_flags = receive_info.AfdFlags;
                    request.buffers.push_back(emu.read_memory<EMU_WSABUF<Traits>>(receive_info.BufferArray));
                    request.address = receive_info.Address;
                    request.address_length = receive_info.AddressLength;
                }

                const auto& buffer = request.buffers.front();
                if (!buffer.len || !buffer.buf)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                network::address from{};
                std::vector<std::byte> data{};
                // The guest may hand us a buffer larger than any datagram (iw4x uses a 128 KiB packet
                // buffer); a UDP datagram is at most ~64 KiB, so only allocate/receive up to that. Rejecting
                // the oversized buffer instead made recvfrom fail with WSAEINVAL and spam the game's netcode.
                data.resize(std::min<size_t>(buffer.len, 0x10000));

                const auto recevied_data = this->s_->recvfrom(from, data);

                if (recevied_data < 0)
                {
                    const auto error = this->s_->get_last_error();
                    if (error == SERR(EWOULDBLOCK))
                    {
                        return this->pend_or_would_block(win_emu, c, true, request);
                    }

                    return STATUS_UNSUCCESSFUL;
                }

                const auto data_size = std::min(data.size(), static_cast<size_t>(recevied_data));
                emu.write_memory(buffer.buf, data.data(), data_size);

                const auto win_from = convert_to_win_address(win_emu, from);

                if (request.address && request.address_length)
                {
                    const emulator_object<ULONG> address_length{emu, request.address_length};
                    const auto address_size = std::min(win_from.size(), static_cast<size_t>(address_length.read()));

                    emu.write_memory(request.address, win_from.data(), address_size);
                    address_length.write(static_cast<ULONG>(address_size));
                }

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = static_cast<uint32_t>(recevied_data);
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_send_datagram(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                const auto& emu = win_emu.emu();

                transfer_request request{};
                if (this->executing_delayed_ioctl_ && this->delayed_request_)
                {
                    request = *this->delayed_request_;
                }
                else
                {
                    if (c.input_buffer_length < sizeof(AFD_SEND_DATAGRAM_INFO<Traits>))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    const auto send_info = emu.read_memory<AFD_SEND_DATAGRAM_INFO<Traits>>(c.input_buffer);

                    // RemoteAddressLength is a signed LONG; a negative or oversized value would turn into a
                    // huge read below. A sockaddr is at most sizeof(win_sockaddr_in6).
                    if (send_info.TdiConnInfo.RemoteAddressLength < 0 ||
                        static_cast<size_t>(send_info.TdiConnInfo.RemoteAddressLength) > sizeof(win_sockaddr_in6))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    request.afd_flags = send_info.AfdFlags;
                    request.buffers.push_back(emu.read_memory<EMU_WSABUF<Traits>>(send_info.BufferArray));
                    request.remote_address = emu.read_memory(send_info.TdiConnInfo.RemoteAddress,
                                                             static_cast<size_t>(send_info.TdiConnInfo.RemoteAddressLength));
                }

                const auto& buffer = request.buffers.front();
                const auto target = convert_to_host_address(win_emu, request.remote_address);
                report_socket_activity(win_emu, network::socket_activity::sendto, target);
                const auto data = emu.read_memory(buffer.buf, buffer.len);

                const auto sent_data = this->s_->sendto(target, data);
                if (sent_data < 0)
                {
                    const auto error = this->s_->get_last_error();
                    if (error == SERR(EWOULDBLOCK))
                    {
                        return this->pend_or_would_block(win_emu, c, false, request);
                    }

                    return STATUS_UNSUCCESSFUL;
                }

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = static_cast<uint32_t>(sent_data);
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_get_address(windows_emulator& win_emu, const io_device_context& c) const
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                const auto local_address = this->s_->get_local_address();
                if (!local_address)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                std::vector<std::byte> win_addr_bytes = convert_to_win_address(win_emu, *local_address);

                if (c.output_buffer_length < win_addr_bytes.size())
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                win_emu.emu().write_memory(c.output_buffer, win_addr_bytes.data(), win_addr_bytes.size());

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = static_cast<ULONG>(win_addr_bytes.size());
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_event_select(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                if (c.input_buffer_length < sizeof(AFD_EVENT_SELECT_INFO))
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto select_info = win_emu.emu().read_memory<AFD_EVENT_SELECT_INFO>(c.input_buffer);

                this->event_select_event_ = select_info.Event;
                this->event_select_mask_ = select_info.PollEvents;
                this->triggered_events_ = 0;

                if (auto* event = win_emu.process.events.get(select_info.Event))
                {
                    event->signaled = false;
                }

                return STATUS_SUCCESS;
            }

            NTSTATUS ioctl_enum_network_events(windows_emulator& win_emu, const io_device_context& c)
            {
                if (!this->s_)
                {
                    throw std::runtime_error("Invalid AFD endpoint socket!");
                }

                if (c.output_buffer_length < 56)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                if (c.input_buffer)
                {
                    if (c.input_buffer_length == 0)
                    {
                        handle h{};
                        h.bits = c.input_buffer;

                        if (auto* event = win_emu.process.events.get(h))
                        {
                            event->signaled = false;
                        }
                    }
                    else
                    {
                        return STATUS_NOT_SUPPORTED;
                    }
                }

                win_emu.emu().write_memory(c.output_buffer, this->triggered_events_);
                this->triggered_events_ = 0;

                if (c.io_status_block)
                {
                    status_block block{};
                    block.Information = 56;
                    c.io_status_block.write(block);
                }

                return STATUS_SUCCESS;
            }
        };

        template <typename Traits>
        // An endpoint without a socket that mswsock polls other sockets through (its polls pend like any endpoint's).
        struct afd_mio_endpoint final : afd_endpoint<Traits>
        {
            void create(windows_emulator&, const io_device_creation_data&) override
            {
            }
        };

        template <typename Traits>
        struct afd_async_connect_hlp : stateless_device
        {
            NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& c) override
            {
                if (c.io_control_code != 0x12007)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (c.input_buffer_length < 40)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const auto target_handle = win_emu.emu().read_memory<handle>(c.input_buffer + 16);

                auto* target_device = win_emu.process.devices.get(target_handle);
                if (!target_device)
                {
                    return STATUS_INVALID_HANDLE;
                }

                auto* target_endpoint = target_device->get_internal_device<afd_endpoint<Traits>>();
                if (!target_endpoint)
                {
                    return STATUS_INVALID_HANDLE;
                }

                return target_endpoint->io_control(win_emu, c);
            }
        };
    }

    std::unique_ptr<io_device> create_afd_endpoint(const device_creation_context& context)
    {
        if (context.is_32_bit)
        {
            return std::make_unique<afd_endpoint<EmulatorTraits<Emu32>>>();
        }

        return std::make_unique<afd_endpoint<EmulatorTraits<Emu64>>>();
    }

    std::unique_ptr<io_device> create_afd_mio_endpoint(const device_creation_context& context)
    {
        if (context.is_32_bit)
        {
            return std::make_unique<afd_mio_endpoint<EmulatorTraits<Emu32>>>();
        }

        return std::make_unique<afd_mio_endpoint<EmulatorTraits<Emu64>>>();
    }

    std::unique_ptr<io_device> create_afd_async_connect_hlp(const device_creation_context& context)
    {
        if (context.is_32_bit)
        {
            return std::make_unique<afd_async_connect_hlp<EmulatorTraits<Emu32>>>();
        }

        return std::make_unique<afd_async_connect_hlp<EmulatorTraits<Emu64>>>();
    }

} // namespace sogen
