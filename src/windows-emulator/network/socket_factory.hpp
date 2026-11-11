#pragma once

#include "i_socket.hpp"
#include "network_mode.hpp"

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

            // Whether a socket becomes ready on the host's time, not only through what the guest does.
            virtual bool is_host_timed() const
            {
                return true;
            }
        };

        std::unique_ptr<socket_factory> create_socket_factory(network_mode mode);
    }

} // namespace sogen
