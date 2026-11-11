#pragma once

#include <memory>
#include <optional>
#include <string>

#include <windows_emulator.hpp>

#include "ttd_format.hpp"

namespace sogen::ttd
{
    struct network_tap_state;

    // Stands between a TTD emulator and the host network: its socket factory, its sockets and its DNS lookup. The host
    // network answers when it pleases, so a replay cannot ask it again: while recording, the tap passes every answer on
    // and logs it (network_inputs); while replaying, it gives the logged answers in the same order without asking the
    // host, so a replay does not depend on the network or its timing. Live, it only passes calls on.
    //
    // Sockets the tap makes count in the emulator's input position (socket_factory::input_position), which saved
    // states keep. A socket restored from a saved state has no host socket: in a replay its answers come from the log,
    // otherwise it answers as a connection the host reset.
    class network_tap
    {
      public:
        explicit network_tap(std::shared_ptr<network_tap_state> state);

        // Logs the host network's answers into `inputs` until stop_recording.
        void start_recording(network_inputs& inputs);
        void stop_recording();

        // Gives the recorded answers from the emulator's input position on.
        void start_replay(std::shared_ptr<const network_inputs> recorded);

        // Passes calls on to the host network again.
        void go_live();

        // Why a replay stopped: it asked the host network something the recording did not. The tap stops the emulator
        // when that happens.
        std::optional<std::string> error() const;

      private:
        std::shared_ptr<network_tap_state> state_{};
    };

    // The emulator's tap, put in place of its network the first time.
    network_tap install_network_tap(windows_emulator& win_emu);

    // The emulator's tap, if it has one.
    std::optional<network_tap> find_network_tap(windows_emulator& win_emu);
}
