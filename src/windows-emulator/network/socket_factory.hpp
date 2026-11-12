#pragma once

#include "i_socket.hpp"
#include "network_mode.hpp"

#include <chrono>
#include <cstdint>
#include <memory>

namespace sogen
{

    namespace network
    {
        struct poll_entry
        {
            i_socket* s{};
            int16_t events{};
            int16_t revents{};
        };

        struct socket_factory
        {
            socket_factory();
            virtual ~socket_factory() = default;

            virtual std::unique_ptr<i_socket> create_socket(int af, int type, int protocol);
            virtual int poll_sockets(std::span<poll_entry> entries);
            virtual std::vector<address> get_local_addresses(int family);

            // As poll_sockets, but a socket the host completes may first take up to `wait` of real time to become
            // ready. Sockets that only the guest makes ready are polled.
            virtual int wait_for_sockets(const std::span<poll_entry> entries, const std::chrono::milliseconds wait)
            {
                (void)wait;
                return this->poll_sockets(entries);
            }

            // A socket of a saved state, with the stream i_socket::recorded_stream named when it was saved. A factory that
            // records or replays the host network continues that stream without asking the host; others start a new
            // socket.
            virtual std::unique_ptr<i_socket> restore_socket(const std::optional<uint64_t> stream, const int af, const int type,
                                                             const int protocol)
            {
                (void)stream;
                return this->create_socket(af, type, protocol);
            }

            // How much of the host network's recorded input has been taken, which a saved state keeps.
            virtual uint64_t input_position() const
            {
                return 0;
            }

            virtual void restore_input_position(const uint64_t position)
            {
                (void)position;
            }
        };

        std::unique_ptr<socket_factory> create_socket_factory(network_mode mode);
    }

} // namespace sogen
