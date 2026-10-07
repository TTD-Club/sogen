#pragma once

#include "memory_permission.hpp"

#include <cstddef>
#include <cassert>
#include <functional>
#include <span>
#include <stdexcept>

namespace sogen
{

    struct emulator_hook;
    struct cpu_interface;

    using memory_operation = memory_permission;

    enum class instruction_hook_continuation : uint8_t
    {
        run_instruction = 0,
        skip_instruction = 1,
        finalized_instruction_pointer = 2,
    };

    enum class memory_violation_continuation : uint8_t
    {
        stop,
        resume,
        restart,
    };

    enum class memory_violation_type : uint8_t
    {
        unmapped,
        protection,
    };

    struct basic_block
    {
        uint64_t address;
        size_t instruction_count;
        size_t size;
    };

    // Hook callbacks receive the virtual CPU that triggered them as their first
    // argument. Callbacks always run on the host thread driving that CPU.
    using edge_generation_hook_callback =
        std::function<void(cpu_interface& cpu, const basic_block& current_block, const basic_block& previous_block)>;
    using basic_block_hook_callback = std::function<void(cpu_interface& cpu, const basic_block& block)>;

    using simple_instruction_hook_callback = std::function<instruction_hook_continuation()>;
    using instruction_hook_callback = std::function<instruction_hook_continuation(cpu_interface& cpu, uint64_t data)>;
    using interrupt_hook_callback = std::function<void(cpu_interface& cpu, int interrupt)>;

    using memory_access_hook_callback = std::function<void(cpu_interface& cpu, uint64_t address, const void* data, size_t size)>;
    using memory_access_data_callback = std::function<void(cpu_interface& cpu, uint64_t address, std::span<const std::byte> data)>;
    // `size` is the instruction's length, or 0 when the backend cannot decode it (the instruction then raises an exception).
    using memory_execution_metadata_callback = std::function<void(cpu_interface& cpu, uint64_t address, size_t size)>;
    using memory_execution_hook_callback = std::function<void(cpu_interface& cpu, uint64_t address)>;

    using memory_violation_hook_callback = std::function<memory_violation_continuation(
        cpu_interface& cpu, uint64_t address, size_t size, memory_operation operation, memory_violation_type type)>;

    class hook_interface
    {
      public:
        virtual ~hook_interface() = default;

        enum class memory_execution_hook_mode
        {
            automatic,
            int3,
        };

        virtual void set_memory_execution_hook_mode(const memory_execution_hook_mode mode)
        {
            if (mode == memory_execution_hook_mode::int3)
            {
                throw std::runtime_error("The selected emulator backend does not support int3 memory execution hooks");
            }
        }

        virtual bool supports_global_memory_execution_hooks() const
        {
            return true;
        }

        virtual emulator_hook* hook_memory_execution(memory_execution_hook_callback callback) = 0;
        virtual emulator_hook* hook_memory_execution(uint64_t address, memory_execution_hook_callback callback) = 0;
        virtual emulator_hook* hook_memory_range_execution(uint64_t address, uint64_t size, memory_execution_hook_callback callback) = 0;
        virtual emulator_hook* hook_memory_read(uint64_t address, uint64_t size, memory_access_hook_callback callback) = 0;
        virtual emulator_hook* hook_memory_write(uint64_t address, uint64_t size, memory_access_hook_callback callback) = 0;

        // These hooks report the exact bytes of every access and the size of every instruction, which the hooks above
        // cannot (they cap widths at eight bytes and do not report instruction sizes). Backends that cannot provide
        // them refuse instead of approximating, so trace recording cannot silently record wrong data.
        // NOLINTBEGIN(performance-unnecessary-value-param)
        virtual emulator_hook* hook_memory_write_data(uint64_t /*address*/, uint64_t /*size*/, memory_access_data_callback /*callback*/)
        {
            throw std::runtime_error("This backend cannot report written memory");
        }

        virtual emulator_hook* hook_memory_read_data(uint64_t /*address*/, uint64_t /*size*/, memory_access_data_callback /*callback*/)
        {
            throw std::runtime_error("This backend cannot report read memory");
        }

        virtual emulator_hook* hook_memory_execution_metadata(memory_execution_metadata_callback /*callback*/)
        {
            throw std::runtime_error("This backend cannot report instruction execution metadata");
        }

        // Reports writes made through the memory interface (syscall handlers, loaders, exception dispatch), which
        // bypass the guest memory hooks above. Called after the write succeeded.
        virtual emulator_hook* hook_host_memory_write(memory_access_data_callback /*callback*/)
        {
            throw std::runtime_error("This backend cannot report host memory writes");
        }

        // NOLINTEND(performance-unnecessary-value-param)

        virtual emulator_hook* hook_instruction(int instruction_type, instruction_hook_callback callback) = 0;

        virtual emulator_hook* hook_interrupt(interrupt_hook_callback callback) = 0;
        virtual emulator_hook* hook_memory_violation(memory_violation_hook_callback callback) = 0;

        virtual emulator_hook* hook_basic_block(basic_block_hook_callback callback) = 0;

        virtual void delete_hook(emulator_hook* hook) = 0;
    };

} // namespace sogen
