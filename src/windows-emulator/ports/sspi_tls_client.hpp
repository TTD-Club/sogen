#pragma once

#include "sspi_context.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace sogen::sspi
{
    enum class handshake_status
    {
        continue_needed,
        incomplete_message,
        complete,
        failed,
    };

    struct handshake_result
    {
        handshake_status status{handshake_status::failed};
        std::vector<uint8_t> output_token{};
        size_t missing_size{};
        size_t extra_size{};
    };

    class tls_client
    {
      public:
        // What a reproducible run makes a handshake from instead of the host: the randomness (client random, key share)
        // and the time (which a TLS 1.2 client random starts with), so that it makes the same handshake again.
        struct reproducible
        {
            std::array<uint8_t, 48> seed{};
            int64_t time{};
        };

        static std::unique_ptr<tls_client> create(std::string_view target, const std::optional<reproducible>& fixed = std::nullopt);

        ~tls_client();
        tls_client(const tls_client&) = delete;
        tls_client& operator=(const tls_client&) = delete;

        handshake_result process(std::span<const uint8_t> input);
        std::optional<provider_context_input> take_handoff_state();

      private:
        struct impl;

        explicit tls_client(std::unique_ptr<impl> state);

        std::unique_ptr<impl> state_;
    };
}
