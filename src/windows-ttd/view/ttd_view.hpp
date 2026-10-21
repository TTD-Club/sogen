#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <arch_emulator.hpp>

#include "ttd_trace.hpp"

namespace sogen::ttd
{
    // The CPU at a position of a trace, without an emulated process: the registers of the latest register snapshot at or
    // before the position, then the instructions up to it run on a standalone backend CPU whose memory holds only what
    // those instructions touch, with every read given the bytes the recording read. Every event is checked against
    // the recording; a difference throws divergence_error. Needs a trace with register snapshots.
    class cpu_view
    {
      public:
        cpu_view(trace& recorded, uint64_t position);
        // The CPU with `registers` (a backend register state), at `position`, `replayed_instructions` after a snapshot.
        cpu_view(uint64_t position, uint64_t replayed_instructions, std::vector<std::byte> registers);

        uint64_t position() const
        {
            return position_;
        }

        // The instructions replayed from the snapshot to the position.
        uint64_t replayed_instructions() const
        {
            return replayed_instructions_;
        }

        // The low 64 bits of a register.
        uint64_t read_register(x86_register reg) const;
        // A register's value, little-endian, into `value`; returns its size (as x86_64_emulator::read_register).
        size_t read_register(x86_register reg, void* value, size_t size) const;

        // A CPU holding only the registers at the position, created on first use. read_register needs none: it decodes
        // the registers on a CPU each thread shares, so many views cost no backend CPU each.
        x86_64_emulator& cpu();

        // The backend register state at the position.
        const std::vector<std::byte>& registers() const
        {
            return registers_;
        }

      private:
        std::vector<std::byte> registers_{};
        std::unique_ptr<x86_64_emulator> cpu_{};
        uint64_t position_{};
        uint64_t replayed_instructions_{};
        // Tells the shared decoding CPU which view's registers it holds.
        uint64_t id_{};
    };

    // The CPUs at `positions`, in their order: each as cpu_view(recorded, position) would be, but every snapshot interval
    // replays once for all the positions in it (registers for both ends of every call to a function cost one replay per
    // interval, not one per position).
    std::vector<cpu_view> cpu_views_at(trace& recorded, std::span<const uint64_t> positions);
}
