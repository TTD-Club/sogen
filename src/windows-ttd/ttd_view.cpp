#include "ttd_view.hpp"

#include <backend_selection.hpp>

#include <algorithm>
#include <cstring>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <vector>

namespace sogen::ttd
{
    namespace
    {
        constexpr uint64_t page_size = 0x1000;

        std::string describe(const std::string_view what, const access_kind kind, const uint64_t address, const size_t size)
        {
            std::ostringstream text;
            text << what << ' ' << access_kind_name(kind) << " address=0x" << std::hex << address << std::dec << " size=" << size;
            return text.str();
        }

        std::unique_ptr<x86_64_emulator> cpu_with_registers(const std::vector<std::byte>& registers)
        {
            auto cpu = create_x86_64_emulator(backend_type::unicorn);
            cpu->restore_registers(registers);
            // Snapshots are taken while the recording CPU runs, where the backend keeps the arithmetic and direction flags
            // outside the flags register; starting the CPU would rebuild them from the flags register and lose them.
            cpu->reg<uint64_t>(x86_register::rflags, cpu->reg<uint64_t>(x86_register::rflags));
            return cpu;
        }
    }

    // The standalone CPU that replays a trace's snapshot intervals, kept with the trace. Its pages stay mapped from one
    // replay to the next and only bytes that differ are rewritten, so the code it translated once is reused (the backend
    // drops translations whose bytes change).
    class view_engine
    {
      public:
        view_engine()
            : cpu_(create_x86_64_emulator(backend_type::unicorn)),
              memory_(*cpu_)
        {
            auto& cpu = *cpu_;
            cpu.hook_memory_execution_metadata([this](cpu_interface&, const uint64_t address, const size_t size) {
                // The backend can abandon an instruction before its effects land and run it again (when a store looks
                // like it could change translated code). Its events then repeat; any difference still shows as a
                // divergence.
                const auto restarted =
                    this->running_ && this->events_[*this->running_].address == address &&
                    (this->cursor_ >= this->events_.size() || this->events_[this->cursor_].kind != access_kind::execute ||
                     this->events_[this->cursor_].address != address);
                if (restarted)
                {
                    this->cursor_ = *this->running_;
                }
                if (this->expect(access_kind::execute, address, size))
                {
                    this->running_ = this->cursor_++;
                }
            });
            cpu.hook_memory_read_before(0, UINT64_MAX, [this](cpu_interface&, const uint64_t address, const size_t size) {
                const auto* event = this->expect(access_kind::read, address, size);
                if (!event)
                {
                    return;
                }
                // The read then returns exactly the recorded bytes, so it needs no check afterwards. Memory already holds
                // them unless prepare_memory found otherwise; writing memory needlessly would make the CPU retranslate
                // code that shares the page.
                if (this->inject_[this->cursor_])
                {
                    this->cpu_->write_memory(address, event->payload.data(), size);
                }
                ++this->cursor_;
            });
            cpu.hook_memory_write_data(
                0, UINT64_MAX, [this](cpu_interface&, const uint64_t address, const std::span<const std::byte> data) {
                    const auto* event = this->expect(access_kind::write, address, data.size());
                    if (!event)
                    {
                        return;
                    }
                    if (memcmp(data.data(), event->payload.data(), data.size()) != 0)
                    {
                        this->divergence_ = describe("TTD replay produced other bytes for", event->kind, event->address, data.size());
                        this->cpu_->stop();
                        return;
                    }
                    ++this->cursor_;
                });
        }

        // Whether the engine replayed before.
        bool used() const
        {
            return this->used_;
        }

        // Runs `events` (the instructions after a snapshot, up to a position, all without host writes) from
        // `registers` and returns the registers at the end. `following` is the instruction after them, if any.
        std::vector<std::byte> replay(const std::span<const access_event> events, const std::optional<access_event>& following,
                                      const std::vector<std::byte>& registers, const uint64_t position)
        {
            this->used_ = true;
            this->prepare_memory(events, following);
            auto& cpu = *this->cpu_;
            cpu.restore_registers(registers);
            cpu.reg<uint64_t>(x86_register::rflags, cpu.reg<uint64_t>(x86_register::rflags));

            this->events_ = events;
            this->cursor_ = 0;
            this->running_.reset();
            this->divergence_.reset();

            // The backend's instruction count stops the CPU where its state is complete (a stop from a hook can leave the
            // flags uncomputed). A restarted instruction counts twice, so the rest runs again until every one ran.
            std::vector<size_t> instructions_from(events.size() + 1);
            for (auto i = events.size(); i-- > 0;)
            {
                instructions_from[i] = instructions_from[i + 1] + (events[i].kind == access_kind::execute ? 1 : 0);
            }
            while (!this->divergence_)
            {
                // An instruction abandoned just before the count ran out has to run again.
                if (!instructions_from[this->cursor_] && following && this->running_ &&
                    cpu.read_instruction_pointer() != following->address &&
                    cpu.read_instruction_pointer() == events[*this->running_].address)
                {
                    this->cursor_ = *this->running_;
                }
                if (!instructions_from[this->cursor_])
                {
                    break;
                }
                const auto before = this->cursor_;
                cpu.start(instructions_from[this->cursor_]);
                if (this->cursor_ == before)
                {
                    break;
                }
            }
            this->events_ = {};

            if (this->divergence_)
            {
                std::string context{};
                const auto cursor = this->cursor_;
                for (auto i = cursor > 8 ? cursor - 8 : 0; i < std::min(cursor + 2, events.size()); ++i)
                {
                    context += "\n  " + std::string(i == cursor ? "> " : "  ") +
                               describe("", events[i].kind, events[i].address, events[i].size) + " step=" + std::to_string(events[i].step);
                }
                throw divergence_error(*this->divergence_ + " replaying to position " + std::to_string(position) + context);
            }
            if (this->cursor_ != events.size())
            {
                throw divergence_error("TTD replay to position " + std::to_string(position) + " stopped after " +
                                       std::to_string(this->cursor_) + " of " + std::to_string(events.size()) + " recorded events");
            }
            return cpu.save_registers();
        }

      private:
        std::unique_ptr<x86_64_emulator> cpu_{};
        memory_manager memory_;
        // Sorted page numbers mapped so far.
        std::vector<uint64_t> mapped_{};

        std::span<const access_event> events_{};
        // Per event, whether a read must be given its recorded bytes as it happens (see prepare_memory).
        std::vector<bool> inject_{};
        size_t cursor_{};
        bool used_{};
        // The execute event of the instruction running now.
        std::optional<size_t> running_{};
        std::optional<std::string> divergence_{};

        const access_event* expect(const access_kind kind, const uint64_t address, const size_t size)
        {
            if (this->divergence_)
            {
                return nullptr;
            }
            if (this->cursor_ >= this->events_.size())
            {
                this->divergence_ = describe("TTD replay produced an unrecorded", kind, address, size);
            }
            else if (const auto& event = this->events_[this->cursor_];
                     event.kind != kind || event.address != address || (size && event.size != size))
            {
                this->divergence_ = describe("TTD replay produced", kind, address, size) + " where the recording has " +
                                    describe("", event.kind, event.address, static_cast<size_t>(event.size));
            }
            else
            {
                return &event;
            }
            this->cpu_->stop();
            return nullptr;
        }

        // Maps the pages the events touch and gives each byte the first value an instruction executed or read there.
        // Guest writes in the interval change bytes later, as they did while recording.
        void prepare_memory(const std::span<const access_event> events, const std::optional<access_event>& following)
        {
            const auto touched = [&](const auto& visit) {
                for (const auto& event : events)
                {
                    visit(event);
                }
                if (following)
                {
                    visit(*following);
                }
            };

            std::vector<uint64_t> pages{};
            pages.reserve(events.size() + 1);
            touched([&](const access_event& event) {
                // The CPU decodes ahead of the instructions it runs, possibly into the next page.
                const auto ahead = event.kind == access_kind::execute ? page_size : 0;
                const auto last = event.address + std::max<uint64_t>(event.size, 1) - 1 + ahead;
                for (auto page = event.address / page_size; page <= last / page_size; ++page)
                {
                    pages.push_back(page);
                }
            });
            std::ranges::sort(pages);
            pages.erase(std::ranges::unique(pages).begin(), pages.end());
            this->map_pages(pages);

            // Walking backwards, earlier events overwrite later ones.
            std::vector<std::byte> contents(pages.size() * page_size);
            std::vector<bool> known(contents.size());
            size_t page_index = 0;
            const auto fill = [&](const access_event& event) {
                if (event.kind != access_kind::execute && event.kind != access_kind::read)
                {
                    return;
                }
                const auto* bytes = reinterpret_cast<const std::byte*>(event.payload.data());
                for (uint64_t i = 0; i < event.size; ++i)
                {
                    const auto address = event.address + i;
                    if (pages[page_index] != address / page_size)
                    {
                        page_index = static_cast<size_t>(std::ranges::lower_bound(pages, address / page_size) - pages.begin());
                    }
                    const auto offset = page_index * page_size + address % page_size;
                    contents[offset] = bytes[i];
                    known[offset] = true;
                }
            };
            if (following)
            {
                fill(*following);
            }
            for (const auto& event : std::views::reverse(events))
            {
                fill(event);
            }

            // Only bytes that differ are written, and translations of a page that changed are dropped (code translated in
            // an earlier replay can include bytes that were not known then); the rest stay translated.
            std::array<std::byte, page_size> current{};
            for (size_t index = 0; index < pages.size(); ++index)
            {
                const auto base = pages[index] * page_size;
                this->cpu_->read_memory(base, current.data(), current.size());
                bool changed = false;
                for (size_t offset = 0; offset < page_size;)
                {
                    const auto at = index * page_size + offset;
                    if (!known[at] || contents[at] == current[offset])
                    {
                        ++offset;
                        continue;
                    }
                    auto end = offset + 1;
                    while (end < page_size && known[index * page_size + end] && contents[index * page_size + end] != current[end])
                    {
                        ++end;
                    }
                    this->cpu_->write_memory(base + offset, contents.data() + at, end - offset);
                    changed = true;
                    offset = end;
                }
                if (changed)
                {
                    this->cpu_->flush_translations(base, page_size);
                }
            }

            // Following the recorded writes from there shows which reads find bytes memory would not hold by then
            // (memory that changed without a write, such as the shared user data); only those get their recorded bytes
            // written as they happen.
            this->inject_.assign(events.size(), false);
            for (size_t i = 0; i < events.size(); ++i)
            {
                const auto& event = events[i];
                if (event.kind != access_kind::read && event.kind != access_kind::write)
                {
                    continue;
                }
                const auto* bytes = reinterpret_cast<const std::byte*>(event.payload.data());
                for (uint64_t k = 0; k < event.size; ++k)
                {
                    const auto address = event.address + k;
                    if (pages[page_index] != address / page_size)
                    {
                        page_index = static_cast<size_t>(std::ranges::lower_bound(pages, address / page_size) - pages.begin());
                    }
                    auto& value = contents[page_index * page_size + address % page_size];
                    if (event.kind == access_kind::read && value != bytes[k])
                    {
                        this->inject_[i] = true;
                    }
                    value = bytes[k];
                }
            }
        }

        void map_pages(const std::span<const uint64_t> pages)
        {
            std::vector<uint64_t> missing{};
            std::ranges::set_difference(pages, this->mapped_, std::back_inserter(missing));
            for (size_t first = 0; first < missing.size();)
            {
                auto count = size_t{1};
                while (first + count < missing.size() && missing[first + count] == missing[first] + count)
                {
                    ++count;
                }
                if (!this->memory_.allocate_memory(missing[first] * page_size, count * page_size, memory_permission::all))
                {
                    throw std::runtime_error("Cannot map memory for a TTD CPU view");
                }
                first += count;
            }
            if (!missing.empty())
            {
                std::vector<uint64_t> merged{};
                merged.reserve(this->mapped_.size() + missing.size());
                std::ranges::merge(this->mapped_, missing, std::back_inserter(merged));
                this->mapped_ = std::move(merged);
            }
        }
    };

    cpu_view::cpu_view(trace& recorded, const uint64_t position)
        : position_(position)
    {
        if (position > recorded.metadata().instruction_count)
        {
            throw std::out_of_range("TTD position is beyond end of trace");
        }
        const auto snapshots = recorded.register_snapshots();
        if (snapshots.empty())
        {
            throw std::runtime_error("This TTD trace has no register snapshots");
        }
        const auto next = std::ranges::upper_bound(snapshots, position, {}, &register_snapshot_entry::step);
        if (next == snapshots.begin())
        {
            throw std::out_of_range("No TTD register snapshot at or before this position");
        }
        const auto index = static_cast<size_t>(next - snapshots.begin() - 1);
        const auto& snapshot = snapshots[index];
        replayed_instructions_ = position - snapshot.step;
        auto registers = recorded.snapshot_registers(index);
        if (!replayed_instructions_)
        {
            cpu_ = cpu_with_registers(registers);
            return;
        }

        // The events of the instructions after the snapshot, up to and including instruction `position`, and the
        // instruction after it, which the CPU decodes before it stops.
        std::vector<access_event> events{};
        std::optional<access_event> following{};
        event_reader reader(recorded, snapshot.event_number);
        while (const auto event = reader.next())
        {
            if (event->kind == access_kind::execute && event->step > position)
            {
                following = event;
                break;
            }
            if (event->kind == access_kind::host_write || event->size > inline_data_limit)
            {
                throw std::runtime_error("TTD register snapshot interval contains a host write");
            }
            events.push_back(*event);
        }

        auto& engine = recorded.view_engine_slot();
        if (!engine)
        {
            engine = std::make_shared<view_engine>();
        }
        const auto reused = engine->used();
        try
        {
            cpu_ = cpu_with_registers(engine->replay(events, following, registers, position));
        }
        catch (const divergence_error&)
        {
            // Code an engine translated in earlier replays can make the backend take a store for self-modifying code and
            // rerun the instruction without reporting its stores again. A fresh engine settles whether the replay really
            // diverges.
            if (!reused)
            {
                throw;
            }
            engine = std::make_shared<view_engine>();
            cpu_ = cpu_with_registers(engine->replay(events, following, registers, position));
        }
    }
}
