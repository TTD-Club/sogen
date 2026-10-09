#pragma once

#include "hook_interface.hpp"
#include "memory_interface.hpp"

#include "serialization.hpp"

#include <cstdint>
#include <optional>

namespace sogen
{

    class emulator : public memory_interface, public hook_interface
    {
      public:
        emulator() = default;
        ~emulator() override = default;

        emulator(const emulator&) = delete;
        emulator& operator=(const emulator&) = delete;

        emulator(emulator&&) = delete;
        emulator& operator=(emulator&&) = delete;

        virtual std::string get_name() const = 0;

        // Whether this backend can drive more than one virtual CPU within a single
        // emulator instance. Requesting more than one vCPU on a backend that returns
        // false is an error at construction time.
        virtual bool supports_multiple_vcpus() const = 0;

        virtual void serialize_state(utils::buffer_serializer& buffer, bool is_snapshot) const = 0;
        virtual void deserialize_state(utils::buffer_deserializer& buffer, bool is_snapshot) = 0;

        // A value that changes, to one no emulator in the process had before, whenever guest memory may have changed
        // through this backend: a write, a mapping or protection change, a state restore, or running guest code.
        // Nothing when the backend does not track it.
        virtual std::optional<uint64_t> get_memory_generation() const
        {
            return std::nullopt;
        }

        // A value that changes whenever the host sets CPU registers (a register write, a register or state restore);
        // guest instructions leave it alone. Nothing when the backend does not track it.
        virtual std::optional<uint64_t> get_register_generation() const
        {
            return std::nullopt;
        }
    };

} // namespace sogen
