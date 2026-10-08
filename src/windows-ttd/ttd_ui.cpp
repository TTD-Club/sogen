#include "ttd_ui.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace sogen::ttd
{
    recordable_ui_backend::recordable_ui_backend(std::unique_ptr<ui_backend> inner)
        : inner_(inner ? std::move(inner) : std::make_unique<null_ui_backend>())
    {
    }

    void recordable_ui_backend::start_recording(recorder record)
    {
        this->stop();
        this->recorder_ = std::move(record);
    }

    void recordable_ui_backend::start_replay(const std::span<const ui_input_entry> inputs, replay_clock clock)
    {
        this->stop();
        this->replay_inputs_ = inputs;
        this->next_replay_input_ = 0;
        this->replay_clock_ = std::move(clock);
        this->replaying_ = true;
    }

    void recordable_ui_backend::stop()
    {
        this->recorder_ = {};
        this->replay_inputs_ = {};
        this->next_replay_input_ = 0;
        this->replay_clock_ = {};
        this->replaying_ = false;
    }

    void recordable_ui_backend::inject(const ui_event& event)
    {
        this->injected_.push_back(event);
    }

    void recordable_ui_backend::set_event_sink(event_sink sink)
    {
        this->sink_ = std::move(sink);
        this->inner_->set_event_sink([this](const ui_event& event) { this->on_host_event(event); });
    }

    void recordable_ui_backend::on_host_event(const ui_event& event)
    {
        if (!this->replaying_)
        {
            this->deliver(event);
        }
    }

    void recordable_ui_backend::deliver(const ui_event& event)
    {
        if (this->recorder_)
        {
            this->recorder_(event);
        }
        if (this->sink_)
        {
            this->sink_(event);
        }
    }

    void recordable_ui_backend::pump_events()
    {
        this->inner_->pump_events();
        std::vector<ui_event> waiting{};
        for (const auto& event : std::exchange(this->injected_, {}))
        {
            if (event.window && !this->windows_.contains(static_cast<uint64_t>(event.window)))
            {
                waiting.push_back(event);
                continue;
            }
            this->on_host_event(event);
        }
        this->injected_ = std::move(waiting);
        if (!this->replaying_)
        {
            return;
        }
        // The clock is read for every input: events one input causes (its host writes) come before the next input of
        // the same pump in the recording.
        while (this->next_replay_input_ < this->replay_inputs_.size() &&
               this->replay_inputs_[this->next_replay_input_].event_number <= this->replay_clock_())
        {
            const auto& input = this->replay_inputs_[this->next_replay_input_++];
            if (this->sink_)
            {
                this->sink_({.window = input.window, .message = input.message, .wParam = input.wparam, .lParam = input.lparam});
            }
        }
    }

    void recordable_ui_backend::reset()
    {
        (*this->inner_).reset();
        this->injected_.clear();
        this->windows_.clear();
    }

    void recordable_ui_backend::create_window(const ui_window_desc& desc)
    {
        this->windows_.insert(static_cast<uint64_t>(desc.handle));
        this->inner_->create_window(desc);
    }

    void recordable_ui_backend::destroy_window(const hwnd window)
    {
        this->windows_.erase(static_cast<uint64_t>(window));
        this->inner_->destroy_window(window);
    }

    void recordable_ui_backend::set_window_rect(const hwnd window, const RECT& rect)
    {
        this->inner_->set_window_rect(window, rect);
    }

    void recordable_ui_backend::set_window_visible(const hwnd window, const bool visible)
    {
        this->inner_->set_window_visible(window, visible);
    }

    void recordable_ui_backend::set_window_enabled(const hwnd window, const bool enabled)
    {
        this->inner_->set_window_enabled(window, enabled);
    }

    void recordable_ui_backend::set_window_title(const hwnd window, const std::u16string_view title)
    {
        this->inner_->set_window_title(window, title);
    }

    void recordable_ui_backend::invalidate(const hwnd window, const std::optional<RECT>& rect)
    {
        this->inner_->invalidate(window, rect);
    }

    void recordable_ui_backend::present_surface(const hwnd window, const ui_surface_desc& surface)
    {
        this->inner_->present_surface(window, surface);
    }

    void recordable_ui_backend::set_cursor_position(const hwnd window, const int32_t screen_x, const int32_t screen_y)
    {
        this->inner_->set_cursor_position(window, screen_x, screen_y);
    }

    void recordable_ui_backend::set_cursor_visibility(const bool visible)
    {
        this->inner_->set_cursor_visibility(visible);
    }

    ui_replay::ui_replay(windows_emulator& win_emu, const std::span<const ui_input_entry> inputs, const uint64_t checkpoint,
                         recordable_ui_backend::replay_clock clock)
    {
        // Inputs delivered before the checkpoint are part of its state.
        const auto first = std::ranges::partition_point(inputs, [&](const ui_input_entry& input) { return input.checkpoint < checkpoint; });
        this->start(win_emu, inputs, static_cast<size_t>(first - inputs.begin()), std::move(clock));
    }

    ui_replay::ui_replay(windows_emulator& win_emu, const std::span<const ui_input_entry> inputs, const after_events start,
                         recordable_ui_backend::replay_clock clock)
    {
        // A budgeted start() returns at its target without pumping window input, so an input recorded after exactly
        // start.count events was not delivered yet.
        const auto first =
            std::ranges::partition_point(inputs, [&](const ui_input_entry& input) { return input.event_number < start.count; });
        this->start(win_emu, inputs, static_cast<size_t>(first - inputs.begin()), std::move(clock));
    }

    void ui_replay::start(windows_emulator& win_emu, const std::span<const ui_input_entry> inputs, const size_t first,
                          recordable_ui_backend::replay_clock clock)
    {
        this->backend_ = dynamic_cast<recordable_ui_backend*>(&win_emu.ui());
        if (!this->backend_)
        {
            if (!inputs.empty())
            {
                throw std::runtime_error("TTD trace has recorded window input; replay it on an emulator from ttd.create_emulator");
            }
            return;
        }
        this->backend_->start_replay(inputs.subspan(first), std::move(clock));
    }

    ui_replay::~ui_replay()
    {
        if (this->backend_)
        {
            this->backend_->stop();
        }
    }
}
