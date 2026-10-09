#pragma once

#include <cstdint>
#include <memory>

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

        uint64_t position() const
        {
            return position_;
        }

        // The instructions replayed from the snapshot to the position.
        uint64_t replayed_instructions() const
        {
            return replayed_instructions_;
        }

        x86_64_emulator& cpu()
        {
            return *cpu_;
        }

      private:
        // Holds only the registers at the position.
        std::unique_ptr<x86_64_emulator> cpu_{};
        uint64_t position_{};
        uint64_t replayed_instructions_{};
    };
}
