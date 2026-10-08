#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <unordered_set>
#include <vector>

#include <windows_emulator.hpp>

#include "ttd_format.hpp"

namespace sogen::ttd
{
    // The UI backend of a TTD emulator. Host window events are input a replay cannot repeat, so this wraps the real
    // backend (or a null one for a headless emulator) and passes the events it delivers through one of three paths:
    // live (no recording or replay attached), recorded (passed on and logged), or replaced (dropped while a replay
    // delivers the recorded ones). Everything else (windows, surfaces, cursor) goes to the inner backend unchanged.
    class recordable_ui_backend final : public ui_backend
    {
      public:
        using recorder = std::function<void(const ui_event&)>;
        // The number of events the replay has verified so far.
        using replay_clock = std::function<uint64_t()>;

        explicit recordable_ui_backend(std::unique_ptr<ui_backend> inner);

        void start_recording(recorder record);
        void start_replay(std::span<const ui_input_entry> inputs, replay_clock clock);
        // Back to live input.
        void stop();

        // Delivers an event as if the host window produced it, at the first pump once its window exists (or the next
        // pump for window 0); for tests and scripted input.
        void inject(const ui_event& event);

        void set_event_sink(event_sink sink) override;
        void pump_events() override;
        void reset() override;
        void create_window(const ui_window_desc& desc) override;
        void destroy_window(hwnd window) override;
        void set_window_rect(hwnd window, const RECT& rect) override;
        void set_window_visible(hwnd window, bool visible) override;
        void set_window_enabled(hwnd window, bool enabled) override;
        void set_window_title(hwnd window, std::u16string_view title) override;
        void invalidate(hwnd window, const std::optional<RECT>& rect) override;
        void present_surface(hwnd window, const ui_surface_desc& surface) override;
        void set_cursor_position(hwnd window, int32_t screen_x, int32_t screen_y) override;
        void set_cursor_visibility(bool visible) override;

      private:
        std::unique_ptr<ui_backend> inner_{};
        event_sink sink_{};
        recorder recorder_{};
        std::span<const ui_input_entry> replay_inputs_{};
        size_t next_replay_input_{};
        replay_clock replay_clock_{};
        bool replaying_{};
        std::vector<ui_event> injected_{};
        std::unordered_set<uint64_t> windows_{};

        void on_host_event(const ui_event& event);
        void deliver(const ui_event& event);
    };

    // Delivers a trace's recorded window events while it replays from checkpoint `checkpoint`, and returns the
    // emulator to live input when destroyed. Does nothing for a trace without UI input; throws when the trace has
    // some and the emulator's UI backend is not a recordable_ui_backend.
    class ui_replay
    {
      public:
        ui_replay(windows_emulator& win_emu, std::span<const ui_input_entry> inputs, uint64_t checkpoint,
                  recordable_ui_backend::replay_clock clock);

        // The first `count` recorded events, for a replay that continues from a position that is not a checkpoint.
        struct after_events
        {
            uint64_t count{};
        };

        // Delivers the inputs that reached the guest after `start`.
        ui_replay(windows_emulator& win_emu, std::span<const ui_input_entry> inputs, after_events start,
                  recordable_ui_backend::replay_clock clock);
        ~ui_replay();
        ui_replay(const ui_replay&) = delete;
        ui_replay& operator=(const ui_replay&) = delete;

      private:
        recordable_ui_backend* backend_{};

        // Delivers inputs[first..]; a trace with any input needs a recordable UI.
        void start(windows_emulator& win_emu, std::span<const ui_input_entry> inputs, size_t first,
                   recordable_ui_backend::replay_clock clock);
    };
}
