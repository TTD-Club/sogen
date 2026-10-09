#include "ttd_view.hpp"

#include <backend_selection.hpp>

#include <algorithm>
#include <cstring>
#include <optional>
#include <ranges>
#include <set>
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

        // Maps every page the events touch, merging adjacent pages into one mapping.
        void map_touched_pages(memory_manager& memory, const std::span<const access_event> events)
        {
            std::set<uint64_t> pages{};
            for (const auto& event : events)
            {
                // The CPU decodes ahead of the instructions it runs, possibly into the next page.
                const auto ahead = event.kind == access_kind::execute ? page_size : 0;
                const auto last = event.address + std::max<uint64_t>(event.size, 1) - 1 + ahead;
                for (auto page = event.address / page_size; page <= last / page_size; ++page)
                {
                    pages.insert(page);
                }
            }
            for (auto page = pages.begin(); page != pages.end();)
            {
                const auto first = *page;
                auto count = uint64_t{1};
                ++page;
                while (page != pages.end() && *page == first + count)
                {
                    ++count;
                    ++page;
                }
                if (!memory.allocate_memory(first * page_size, static_cast<size_t>(count * page_size), memory_permission::all))
                {
                    throw std::runtime_error("Cannot map memory for a TTD CPU view");
                }
            }
        }
    }

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

        // The events of the instructions after the snapshot, up to and including instruction `position`.
        std::vector<access_event> events{};
        // The instruction after `position`: the CPU decodes it before it stops, so its bytes must be there too.
        std::optional<access_event> following{};
        if (replayed_instructions_)
        {
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
        }

        cpu_ = create_x86_64_emulator(backend_type::unicorn);
        auto& cpu = *cpu_;
        memory_ = std::make_unique<memory_manager>(cpu);
        std::vector<access_event> touched = events;
        if (following)
        {
            touched.push_back(*following);
        }
        map_touched_pages(*memory_, touched);
        // Each byte starts with the first value an instruction executed or read there (walking backwards, earlier events
        // overwrite later ones); guest writes in the interval change it later as they did while recording. Reads still
        // get their recorded bytes as they happen, but rewriting memory then would make the CPU retranslate code that
        // shares the page, so it only happens for memory that changed without a write (such as the shared user data).
        for (const auto& event : std::views::reverse(touched))
        {
            if (event.kind == access_kind::execute || event.kind == access_kind::read)
            {
                cpu.write_memory(event.address, event.payload.data(), static_cast<size_t>(event.size));
            }
        }
        cpu.restore_registers(recorded.snapshot_registers(index));
        // Snapshots are taken while the recording CPU runs, where the backend keeps the arithmetic and direction flags
        // outside the flags register; starting the CPU would rebuild them from the flags register and lose them.
        cpu.reg<uint64_t>(x86_register::rflags, cpu.reg<uint64_t>(x86_register::rflags));
        if (!replayed_instructions_)
        {
            return;
        }

        size_t cursor = 0;
        std::optional<std::string> divergence{};
        const auto expect = [&](const access_kind kind, const uint64_t address, const size_t size) -> const access_event* {
            if (divergence)
            {
                return nullptr;
            }
            if (cursor >= events.size())
            {
                divergence = describe("TTD replay produced an unrecorded", kind, address, size);
            }
            else if (const auto& event = events[cursor]; event.kind != kind || event.address != address || (size && event.size != size))
            {
                divergence = describe("TTD replay produced", kind, address, size) + " where the recording has " +
                             describe("", event.kind, event.address, static_cast<size_t>(event.size));
            }
            else
            {
                return &event;
            }
            cpu.stop();
            return nullptr;
        };
        const auto matches = [&](const access_event& event, const std::span<const std::byte> data) {
            if (data.size() == event.size && memcmp(data.data(), event.payload.data(), data.size()) == 0)
            {
                ++cursor;
                return;
            }
            divergence = describe("TTD replay produced other bytes for", event.kind, event.address, data.size());
            cpu.stop();
        };

        // The execute event of the instruction running now.
        std::optional<size_t> running{};
        std::vector<emulator_hook*> hooks{};
        hooks.push_back(cpu.hook_memory_execution_metadata([&](cpu_interface&, const uint64_t address, const size_t size) {
            // The backend can abandon an instruction before its effects land and run it again (when a store looks like
            // it could change translated code). Its events then repeat; any difference still shows as a divergence.
            const auto restarted =
                running && events[*running].address == address &&
                (cursor >= events.size() || events[cursor].kind != access_kind::execute || events[cursor].address != address);
            if (restarted)
            {
                cursor = *running;
            }
            if (expect(access_kind::execute, address, size))
            {
                running = cursor++;
            }
        }));
        hooks.push_back(cpu.hook_memory_read_before(0, UINT64_MAX, [&](cpu_interface&, const uint64_t address, const size_t size) {
            const auto* event = expect(access_kind::read, address, size);
            if (!event)
            {
                return;
            }
            std::array<uint8_t, inline_data_limit> current{};
            if (!cpu.try_read_memory(address, current.data(), size) || memcmp(current.data(), event->payload.data(), size) != 0)
            {
                cpu.write_memory(address, event->payload.data(), size);
            }
        }));
        hooks.push_back(
            cpu.hook_memory_read_data(0, UINT64_MAX, [&](cpu_interface&, const uint64_t address, const std::span<const std::byte> data) {
                if (const auto* event = expect(access_kind::read, address, data.size()))
                {
                    matches(*event, data);
                }
            }));
        hooks.push_back(
            cpu.hook_memory_write_data(0, UINT64_MAX, [&](cpu_interface&, const uint64_t address, const std::span<const std::byte> data) {
                if (const auto* event = expect(access_kind::write, address, data.size()))
                {
                    matches(*event, data);
                }
            }));

        // The backend's instruction count stops the CPU where its state is complete (a stop from a hook can leave the
        // flags uncomputed). A restarted instruction counts twice, so the rest runs again until every one ran.
        std::vector<size_t> instructions_from(events.size() + 1);
        for (auto i = events.size(); i-- > 0;)
        {
            instructions_from[i] = instructions_from[i + 1] + (events[i].kind == access_kind::execute ? 1 : 0);
        }
        while (!divergence)
        {
            // An instruction abandoned just before the count ran out has to run again.
            if (!instructions_from[cursor] && following && running && cpu.read_instruction_pointer() != following->address &&
                cpu.read_instruction_pointer() == events[*running].address)
            {
                cursor = *running;
            }
            if (!instructions_from[cursor])
            {
                break;
            }
            const auto before = cursor;
            cpu.start(instructions_from[cursor]);
            if (cursor == before)
            {
                break;
            }
        }
        for (auto* hook : hooks)
        {
            cpu.delete_hook(hook);
        }
        if (divergence)
        {
            std::string context{};
            for (auto i = cursor > 8 ? cursor - 8 : 0; i < std::min(cursor + 2, events.size()); ++i)
            {
                context += "\n  " + std::string(i == cursor ? "> " : "  ") +
                           describe("", events[i].kind, events[i].address, events[i].size) + " step=" + std::to_string(events[i].step);
            }
            throw divergence_error(*divergence + " replaying to position " + std::to_string(position) + context);
        }
        if (cursor != events.size())
        {
            throw divergence_error("TTD replay to position " + std::to_string(position) + " stopped after " + std::to_string(cursor) +
                                   " of " + std::to_string(events.size()) + " recorded events");
        }
    }
}
