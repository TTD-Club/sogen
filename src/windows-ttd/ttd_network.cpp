#include "ttd_network.hpp"

#include <cstring>
#include <functional>
#include <sstream>
#include <utility>
#include <vector>

#include <network/address.hpp>

namespace sogen::ttd
{
    enum class tap_mode : uint8_t
    {
        live,
        recording,
        replaying,
    };

    struct network_tap_state
    {
        windows_emulator* emu{};
        std::unique_ptr<network::socket_factory> inner_factory{};
        std::unique_ptr<network::dns_lookup> inner_lookup{};
        tap_mode mode{tap_mode::live};
        // Inputs recorded or replayed, and sockets made, so far: the emulator's input position.
        uint64_t position{};
        network_inputs* recording{};
        std::shared_ptr<const network_inputs> replay{};
        std::optional<std::string> error{};

        struct answer
        {
            int64_t value{};
            std::vector<std::byte> data{};
        };

        // One call to the host network: answered by `live` (or by `dead` when the call cannot reach the host), logged
        // while recording, and answered from the log while replaying.
        answer ask(const network_call call, const uint64_t stream, const uint64_t argument, const std::function<answer()>& live,
                   const answer& dead)
        {
            if (this->mode == tap_mode::replaying)
            {
                const auto* input = this->take(call, stream, argument);
                return input ? answer{.value = input->value, .data = input->data} : dead;
            }

            auto result = live ? live() : dead;
            this->note(call, stream, argument, result);
            return result;
        }

        void note(const network_call call, const uint64_t stream, const uint64_t argument, const answer& result)
        {
            if (this->mode == tap_mode::recording)
            {
                this->recording->inputs.push_back(
                    {.call = call, .stream = stream, .argument = argument, .value = result.value, .data = result.data});
                ++this->position;
            }
        }

        // A replay's next input when it is the answer to this call; otherwise the replay stops.
        const network_input* take(const network_call call, const uint64_t stream, const uint64_t argument)
        {
            if (this->error)
            {
                return nullptr;
            }

            const auto& inputs = this->replay->inputs;
            const auto first = this->replay->first_position;
            if (this->position < first || this->position - first >= inputs.size())
            {
                this->fail(call, stream, "after the recorded ones");
                return nullptr;
            }

            const auto& input = inputs[static_cast<size_t>(this->position - first)];
            if (input.call != call || input.stream != stream || input.argument != argument)
            {
                std::ostringstream recorded;
                recorded << "where the recording asked call " << static_cast<unsigned>(input.call) << " of stream " << input.stream
                         << " (argument " << std::hex << input.argument << ")";
                this->fail(call, stream, recorded.str(), argument);
                return nullptr;
            }

            ++this->position;
            return &input;
        }

        void fail(const network_call call, const uint64_t stream, const std::string& detail, const uint64_t argument = 0)
        {
            std::ostringstream message;
            message << "TTD replay asked the host network call " << static_cast<unsigned>(call) << " of stream " << stream << " (argument "
                    << std::hex << argument << std::dec << ") at input " << this->position << ", " << detail;
            this->error = message.str();
            this->emu->stop();
        }

        // A socket that is made: its stream is the position it is made at, and making it takes the position on.
        uint64_t next_stream() const
        {
            return this->position;
        }

        void made_live_socket()
        {
            if (this->mode == tap_mode::live)
            {
                ++this->position;
            }
        }
    };

    namespace
    {
        using answer = network_tap_state::answer;

        uint64_t hash_bytes(const std::span<const std::byte> bytes, uint64_t hash = 0xcbf29ce484222325)
        {
            for (const auto byte : bytes)
            {
                hash = (hash ^ static_cast<uint8_t>(byte)) * 0x100000001b3;
            }
            return hash;
        }

        std::span<const std::byte> address_bytes(const network::address& address)
        {
            return {reinterpret_cast<const std::byte*>(&address.get_addr()), static_cast<size_t>(address.get_size())};
        }

        void put_address(std::vector<std::byte>& output, const network::address& address)
        {
            const auto bytes = address_bytes(address);
            const auto size = static_cast<uint16_t>(bytes.size());
            const auto* size_bytes = reinterpret_cast<const std::byte*>(&size);
            output.insert(output.end(), size_bytes, size_bytes + sizeof(size));
            output.insert(output.end(), bytes.begin(), bytes.end());
        }

        std::optional<network::address> get_address(std::span<const std::byte>& input)
        {
            uint16_t size{};
            if (input.size() < sizeof(size))
            {
                return std::nullopt;
            }
            memcpy(&size, input.data(), sizeof(size));
            if (input.size() - sizeof(size) < size)
            {
                return std::nullopt;
            }
            network::address address(reinterpret_cast<const sockaddr*>(input.data() + sizeof(size)), static_cast<socklen_t>(size));
            input = input.subspan(sizeof(size) + size);
            return address;
        }

        answer addresses_answer(const std::vector<network::address>& addresses)
        {
            answer result{.value = static_cast<int64_t>(addresses.size())};
            for (const auto& address : addresses)
            {
                put_address(result.data, address);
            }
            return result;
        }

        std::vector<network::address> addresses_of(const answer& result)
        {
            std::vector<network::address> addresses{};
            std::span<const std::byte> data{result.data};
            for (int64_t i = 0; i < result.value; ++i)
            {
                auto address = get_address(data);
                if (!address)
                {
                    break;
                }
                addresses.push_back(*address);
            }
            return addresses;
        }

        answer optional_address_answer(const std::optional<network::address>& address)
        {
            answer result{.value = address ? 1 : 0};
            if (address)
            {
                put_address(result.data, *address);
            }
            return result;
        }

        std::optional<network::address> optional_address_of(const answer& result)
        {
            std::span<const std::byte> data{result.data};
            return result.value ? get_address(data) : std::nullopt;
        }

        answer received_answer(const sent_size size, const std::span<const std::byte> data)
        {
            answer result{.value = size};
            if (size > 0)
            {
                result.data.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(std::min(static_cast<size_t>(size), data.size())));
            }
            return result;
        }

        sent_size received_into(const answer& result, const std::span<std::byte> data)
        {
            const auto size = std::min(result.data.size(), data.size());
            memcpy(data.data(), result.data.data(), size);
            return static_cast<sent_size>(result.value);
        }

        const answer dead_failure{.value = 0};
        const answer dead_transfer{.value = -1};

        class tap_socket final : public network::i_socket
        {
          public:
            tap_socket(std::shared_ptr<network_tap_state> state, const uint64_t stream, std::unique_ptr<network::i_socket> inner)
                : state_(std::move(state)),
                  stream_(stream),
                  inner_(std::move(inner))
            {
            }

            network::i_socket* inner() const
            {
                return this->state_->mode == tap_mode::replaying ? nullptr : this->inner_.get();
            }

            uint64_t stream() const
            {
                return this->stream_;
            }

            void set_blocking(const bool blocking) override
            {
                if (auto* inner = this->inner())
                {
                    inner->set_blocking(blocking);
                }
            }

            int get_last_error() override
            {
                return static_cast<int>(this->ask(network_call::last_error, 0,
                                                  [this] { return answer{.value = this->inner_->get_last_error()}; },
                                                  {.value = SERR(ECONNRESET)})
                                            .value);
            }

            std::optional<int> get_socket_error() override
            {
                constexpr auto none = std::numeric_limits<int64_t>::min();
                const auto result = this->ask(network_call::socket_error, 0,
                                              [this] {
                                                  const auto error = this->inner_->get_socket_error();
                                                  return answer{.value = error ? *error : none};
                                              },
                                              {.value = SERR(ECONNRESET)});
                return result.value == none ? std::nullopt : std::optional<int>(static_cast<int>(result.value));
            }

            bool is_ready(const bool in_poll) override
            {
                return this->ask(network_call::is_ready, in_poll ? 1 : 0, [&] { return answer{.value = this->inner_->is_ready(in_poll)}; },
                                 {.value = 1})
                           .value != 0;
            }

            bool is_listening() override
            {
                return this->ask(
                               network_call::is_listening, 0, [this] { return answer{.value = this->inner_->is_listening()}; },
                               dead_failure)
                           .value != 0;
            }

            std::optional<network::address> get_local_address() override
            {
                if (this->state_->mode == tap_mode::live && this->inner_)
                {
                    return this->inner_->get_local_address();
                }
                return optional_address_of(this->ask(
                    network_call::local_address, 0, [this] { return optional_address_answer(this->inner_->get_local_address()); },
                    dead_failure));
            }

            std::optional<network::address> get_remote_address() override
            {
                if (this->state_->mode == tap_mode::live && this->inner_)
                {
                    return this->inner_->get_remote_address();
                }
                return optional_address_of(this->ask(
                    network_call::remote_address, 0, [this] { return optional_address_answer(this->inner_->get_remote_address()); },
                    dead_failure));
            }

            bool bind(const network::address& addr) override
            {
                return this->ask(
                               network_call::bind, hash_bytes(address_bytes(addr)),
                               [&] { return answer{.value = this->inner_->bind(addr)}; }, dead_failure)
                           .value != 0;
            }

            bool connect(const network::address& addr) override
            {
                return this->ask(
                               network_call::connect, hash_bytes(address_bytes(addr)),
                               [&] { return answer{.value = this->inner_->connect(addr)}; }, dead_failure)
                           .value != 0;
            }

            bool listen(const int backlog) override
            {
                return this->ask(
                               network_call::listen, static_cast<uint64_t>(backlog),
                               [&] { return answer{.value = this->inner_->listen(backlog)}; }, dead_failure)
                           .value != 0;
            }

            std::unique_ptr<network::i_socket> accept(network::address& address) override
            {
                const auto stream = this->state_->next_stream();
                std::unique_ptr<network::i_socket> accepted{};
                const auto result = this->ask(
                    network_call::accept, 0,
                    [&] {
                        network::address peer{};
                        accepted = this->inner_->accept(peer);
                        return accepted ? optional_address_answer(peer) : dead_failure;
                    },
                    dead_failure);
                if (!result.value)
                {
                    return nullptr;
                }
                this->state_->made_live_socket();
                if (auto peer = optional_address_of(result))
                {
                    address = *peer;
                }
                return std::make_unique<tap_socket>(this->state_, stream, std::move(accepted));
            }

            sent_size send(const std::span<const std::byte> data) override
            {
                return static_cast<sent_size>(
                    this->ask(
                            network_call::send, data.size(), [&] { return answer{.value = this->inner_->send(data)}; }, dead_transfer)
                        .value);
            }

            sent_size sendto(const network::address& destination, const std::span<const std::byte> data) override
            {
                return static_cast<sent_size>(this->ask(
                                                      network_call::sendto, hash_bytes(address_bytes(destination), data.size()),
                                                      [&] { return answer{.value = this->inner_->sendto(destination, data)}; },
                                                      dead_transfer)
                                                  .value);
            }

            sent_size recv(const std::span<std::byte> data) override
            {
                return received_into(
                    this->ask(
                        network_call::recv, data.size(), [&] { return received_answer(this->inner_->recv(data), data); }, dead_transfer),
                    data);
            }

            sent_size recvfrom(network::address& source, const std::span<std::byte> data) override
            {
                const auto result = this->ask(
                    network_call::recvfrom, data.size(),
                    [&] {
                        network::address from{};
                        const auto size = this->inner_->recvfrom(from, data);
                        answer received{.value = size};
                        put_address(received.data, from);
                        if (size > 0)
                        {
                            received.data.insert(received.data.end(), data.begin(), data.begin() + size);
                        }
                        return received;
                    },
                    dead_transfer);
                std::span<const std::byte> rest{result.data};
                if (auto from = get_address(rest))
                {
                    source = *from;
                }
                memcpy(data.data(), rest.data(), std::min(rest.size(), data.size()));
                return static_cast<sent_size>(result.value);
            }

            sent_size peek(const std::span<std::byte> data) override
            {
                return received_into(
                    this->ask(
                        network_call::peek, data.size(), [&] { return received_answer(this->inner_->peek(data), data); }, dead_transfer),
                    data);
            }

            std::optional<uint64_t> recorded_stream() const override
            {
                if (this->state_->mode == tap_mode::live && this->inner_)
                {
                    return std::nullopt;
                }
                return this->stream_;
            }

          private:
            std::shared_ptr<network_tap_state> state_{};
            uint64_t stream_{};
            std::unique_ptr<network::i_socket> inner_{};

            answer ask(const network_call call, const uint64_t argument, const std::function<answer()>& live, const answer& dead)
            {
                return this->state_->ask(call, this->stream_, argument, this->inner() ? live : std::function<answer()>{}, dead);
            }
        };

        class tap_factory final : public network::socket_factory
        {
          public:
            explicit tap_factory(std::shared_ptr<network_tap_state> state)
                : state_(std::move(state))
            {
            }

            const std::shared_ptr<network_tap_state>& state() const
            {
                return this->state_;
            }

            std::unique_ptr<network::i_socket> create_socket(const int af, const int type, const int protocol) override
            {
                const auto stream = this->state_->next_stream();
                std::unique_ptr<network::i_socket> inner{};
                const auto argument = static_cast<uint64_t>(static_cast<uint16_t>(af)) |
                                      (static_cast<uint64_t>(static_cast<uint16_t>(type)) << 16) |
                                      (static_cast<uint64_t>(static_cast<uint32_t>(protocol)) << 32);
                const auto result = this->state_->ask(
                    network_call::create_socket, 0, argument,
                    [&] {
                        inner = this->state_->inner_factory->create_socket(af, type, protocol);
                        return answer{.value = inner ? 1 : 0};
                    },
                    dead_failure);
                if (!result.value)
                {
                    return nullptr;
                }
                this->state_->made_live_socket();
                return std::make_unique<tap_socket>(this->state_, stream, std::move(inner));
            }

            // A recorded socket has no host socket after a load (its connection ended with the run that saved it), and a
            // replay takes its answers from the log. Only a live socket saved while live gets a host socket again.
            std::unique_ptr<network::i_socket> restore_socket(const std::optional<uint64_t> stream, const int af, const int type,
                                                              const int protocol) override
            {
                if (this->state_->mode == tap_mode::live && !stream)
                {
                    return std::make_unique<tap_socket>(this->state_, this->state_->position,
                                                        this->state_->inner_factory->restore_socket(stream, af, type, protocol));
                }
                return std::make_unique<tap_socket>(this->state_, stream.value_or(0), nullptr);
            }

            int poll_sockets(const std::span<network::poll_entry> entries) override
            {
                return this->poll(entries, std::chrono::milliseconds{});
            }

            int wait_for_sockets(const std::span<network::poll_entry> entries, const std::chrono::milliseconds wait) override
            {
                return this->poll(entries, wait);
            }

            std::vector<network::address> get_local_addresses(const int family) override
            {
                return addresses_of(this->state_->ask(
                    network_call::local_addresses, 0, static_cast<uint64_t>(static_cast<uint32_t>(family)),
                    [&] { return addresses_answer(this->state_->inner_factory->get_local_addresses(family)); }, dead_failure));
            }

            uint64_t input_position() const override
            {
                return this->state_->position;
            }

            // A loaded state continues from its own position; a divergence of the run before it no longer matters.
            void restore_input_position(const uint64_t position) override
            {
                this->state_->position = position;
                this->state_->error.reset();
            }

          private:
            std::shared_ptr<network_tap_state> state_{};

            // Each entry's stream, requested events and resulting events: what a replay checks and takes.
            struct poll_record
            {
                uint64_t stream{};
                int16_t events{};
                int16_t revents{};
            };

            int poll(const std::span<network::poll_entry> entries, const std::chrono::milliseconds wait)
            {
                // A socket made before the tap is the host's own (its calls are not recorded).
                constexpr auto untapped = std::numeric_limits<uint64_t>::max();
                std::vector<poll_record> asked(entries.size());
                std::vector<tap_socket*> sockets(entries.size());
                for (size_t i = 0; i < entries.size(); ++i)
                {
                    sockets[i] = dynamic_cast<tap_socket*>(entries[i].s);
                    asked[i] = {.stream = sockets[i] ? sockets[i]->stream() : untapped, .events = entries[i].events};
                }

                const auto requested = std::as_bytes(std::span(asked));
                const auto argument = hash_bytes(requested);
                const auto result = this->state_->ask(
                    network_call::poll, 0, argument,
                    [&] {
                        std::vector<network::poll_entry> inner_entries{};
                        std::vector<size_t> inner_indices{};
                        auto results = asked;
                        for (size_t i = 0; i < entries.size(); ++i)
                        {
                            if (auto* inner = sockets[i] ? sockets[i]->inner() : entries[i].s)
                            {
                                inner_entries.push_back({.s = inner, .events = entries[i].events, .revents = entries[i].events});
                                inner_indices.push_back(i);
                            }
                            else
                            {
                                results[i].revents = static_cast<int16_t>(POLLERR | POLLHUP);
                            }
                        }
                        if (!inner_entries.empty())
                        {
                            this->state_->inner_factory->wait_for_sockets(inner_entries, wait);
                        }
                        for (size_t j = 0; j < inner_indices.size(); ++j)
                        {
                            results[inner_indices[j]].revents = inner_entries[j].revents;
                        }
                        answer polled{};
                        for (const auto& entry : results)
                        {
                            polled.value += entry.revents != 0 ? 1 : 0;
                        }
                        const auto bytes = std::as_bytes(std::span(results));
                        polled.data.assign(bytes.begin(), bytes.end());
                        return polled;
                    },
                    {});

                std::vector<poll_record> results(entries.size());
                if (result.data.size() == results.size() * sizeof(poll_record))
                {
                    memcpy(results.data(), result.data.data(), result.data.size());
                }
                else
                {
                    for (auto& entry : results)
                    {
                        entry.revents = static_cast<int16_t>(POLLERR | POLLHUP);
                    }
                }
                for (size_t i = 0; i < entries.size(); ++i)
                {
                    entries[i].revents = results[i].revents;
                }
                return static_cast<int>(result.value);
            }
        };

        class tap_lookup final : public network::dns_lookup
        {
          public:
            explicit tap_lookup(std::shared_ptr<network_tap_state> state)
                : state_(std::move(state))
            {
            }

            std::vector<network::address> resolve_host(const std::string_view hostname, const std::optional<int> family) override
            {
                const auto argument = hash_bytes(std::as_bytes(std::span(hostname)), static_cast<uint64_t>(family.value_or(-1)) + 1);
                return addresses_of(this->state_->ask(
                    network_call::resolve_host, 0, argument,
                    [&] { return addresses_answer(this->state_->inner_lookup->resolve_host(hostname, family)); }, dead_failure));
            }

          private:
            std::shared_ptr<network_tap_state> state_{};
        };
    }

    network_tap::network_tap(std::shared_ptr<network_tap_state> state)
        : state_(std::move(state))
    {
    }

    void network_tap::start_recording(network_inputs& inputs)
    {
        inputs.first_position = this->state_->position;
        inputs.inputs.clear();
        this->state_->recording = &inputs;
        this->state_->replay.reset();
        this->state_->error.reset();
        this->state_->mode = tap_mode::recording;
    }

    void network_tap::stop_recording()
    {
        if (this->state_->mode == tap_mode::recording)
        {
            this->go_live();
        }
    }

    void network_tap::start_replay(std::shared_ptr<const network_inputs> recorded)
    {
        if (!recorded)
        {
            throw std::invalid_argument("A network replay needs recorded inputs");
        }
        this->state_->recording = nullptr;
        this->state_->replay = std::move(recorded);
        this->state_->error.reset();
        this->state_->mode = tap_mode::replaying;
    }

    void network_tap::go_live()
    {
        this->state_->recording = nullptr;
        this->state_->replay.reset();
        this->state_->error.reset();
        this->state_->mode = tap_mode::live;
    }

    std::optional<std::string> network_tap::error() const
    {
        return this->state_->error;
    }

    std::optional<network_tap> find_network_tap(windows_emulator& win_emu)
    {
        if (const auto* factory = dynamic_cast<tap_factory*>(&win_emu.socket_factory()))
        {
            return network_tap(factory->state());
        }
        return std::nullopt;
    }

    network_tap install_network_tap(windows_emulator& win_emu)
    {
        if (auto tap = find_network_tap(win_emu))
        {
            return *tap;
        }

        auto state = std::make_shared<network_tap_state>();
        state->emu = &win_emu;
        state->position = win_emu.socket_factory().input_position();
        auto [factory, lookup] = win_emu.exchange_network(std::make_unique<tap_factory>(state), std::make_unique<tap_lookup>(state));
        state->inner_factory = std::move(factory);
        state->inner_lookup = std::move(lookup);
        return network_tap(std::move(state));
    }
}
