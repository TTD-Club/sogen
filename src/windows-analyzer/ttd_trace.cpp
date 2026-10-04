#include "ttd_trace.hpp"
#include "snapshot.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <map>
#include <queue>
#include <sstream>
#include <set>
#include <stdexcept>
#include <unordered_map>

namespace sogen::ttd
{
    static_assert(std::endian::native == std::endian::little, "TTD trace requires a little-endian host");

    namespace
    {
        constexpr uint64_t page_size = 4096;

        struct v1_header
        {
            char magic[8]{};
            uint64_t snapshot_size{};
            uint64_t instruction_count{};
            uint64_t write_count{};
            uint64_t index_offset{};
            uint64_t index_count{};
        };

        static_assert(sizeof(v1_header) == 48);

        struct old_index_entry
        {
            uint64_t page;
            uint64_t event_number;
        };

        struct v3_access_event
        {
            uint64_t step;
            uint64_t ip;
            uint64_t address;
            uint64_t size;
            access_kind kind;
        };

        static_assert(sizeof(v3_access_event) == 40);

        template <typename T>
        void write_object(std::ostream& stream, const T& object)
        {
            stream.write(reinterpret_cast<const char*>(&object), sizeof(object));
            if (!stream)
            {
                throw std::runtime_error("TTD trace write failed");
            }
        }

        template <typename T>
        T read_object(std::istream& stream)
        {
            T object{};
            stream.read(reinterpret_cast<char*>(&object), sizeof(object));
            if (!stream)
            {
                throw std::runtime_error("Truncated TTD trace");
            }
            return object;
        }

        bool overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
        {
            return as && bs && a <= b + std::min(bs - 1, UINT64_MAX - b) && b <= a + std::min(as - 1, UINT64_MAX - a);
        }
    }

    recorder::recorder(windows_emulator& emu, const std::filesystem::path& path, const uint64_t access_mask)
        : emu_(emu),
          path_(path),
          file_(path, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc)
    {
        if (!file_)
        {
            throw std::runtime_error("Cannot create TTD trace: " + path.string());
        }
        // This also makes the initial process/thread state explicit in the snapshot.
        emu_.setup_process_if_necessary();
        const auto bytes = snapshot::create_emulator_snapshot(emu_);
        header_.snapshot_size = bytes.size();
        write_object(file_, header_);
        file_.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file_)
        {
            throw std::runtime_error("Cannot write TTD snapshot");
        }

        auto& cpu = emu_.emu();
        if (access_mask & static_cast<uint64_t>(access_kind::write))
        {
            write_hook_ =
                scoped_hook(cpu, cpu.hook_memory_write_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
                    append_event(access_kind::write, address, size);
                }));
        }
        if (access_mask & static_cast<uint64_t>(access_kind::read))
        {
            read_hook_ =
                scoped_hook(cpu, cpu.hook_memory_read_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
                    append_event(access_kind::read, address, size);
                }));
        }
        if (access_mask & static_cast<uint64_t>(access_kind::execute))
        {
            execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
                append_event(access_kind::execute, address, size);
            }));
        }
    }

    void recorder::append_event(access_kind kind, uint64_t address, size_t size)
    {
        if (!size)
        {
            return;
        }
        access_event event{emu_.get_executed_instructions(), emu_.emu().read_instruction_pointer(), address, size, kind};
        if (kind == access_kind::execute && size <= 15 && !emu_.emu().try_read_memory(address, event.instruction_bytes.data(), size))
        {
            throw std::runtime_error("Cannot read executed instruction bytes");
        }
        write_object(file_, event);
        ++header_.write_count;
    }

    recorder::~recorder()
    {
        try
        {
            finish();
        }
        catch (...)
        {
        }
    }

    void recorder::checkpoint()
    {
        if (finished_)
        {
            throw std::runtime_error("Cannot checkpoint a finished TTD trace");
        }
        const auto step = emu_.get_executed_instructions();
        if (!step || (!checkpoints_.empty() && step <= checkpoints_.back().step))
        {
            throw std::runtime_error("TTD checkpoints must have increasing instruction positions");
        }
        checkpoints_.push_back({step, snapshot::create_emulator_snapshot(emu_)});
    }

    void recorder::finish()
    {
        if (finished_)
        {
            return;
        }
        write_hook_.remove();
        read_hook_.remove();
        execute_hook_.remove();
        header_.instruction_count = emu_.get_executed_instructions();
        const auto index_less = [](const index_entry& a, const index_entry& b) {
            if (a.page != b.page)
            {
                return a.page < b.page;
            }
            if (a.kind != b.kind)
            {
                return a.kind < b.kind;
            }
            return a.event_number < b.event_number;
        };
        constexpr size_t index_chunk_limit = 4'000'000;
        std::vector<index_entry> index{};
        index.reserve(index_chunk_limit);

        struct index_runs
        {
            std::vector<std::filesystem::path> paths{};
            std::vector<uint64_t> counts{};

            ~index_runs()
            {
                for (const auto& path : paths)
                {
                    std::error_code error;
                    std::filesystem::remove(path, error);
                }
            }
        } runs;

        const auto flush_index_run = [&] {
            std::sort(index.begin(), index.end(), index_less);
            const auto path = std::filesystem::path(path_.string() + ".index-run-" + std::to_string(runs.paths.size()));
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            if (!output)
            {
                throw std::runtime_error("Cannot create TTD index run: " + path.string());
            }
            runs.paths.push_back(path);
            runs.counts.push_back(index.size());
            output.write(reinterpret_cast<const char*>(index.data()), static_cast<std::streamsize>(index.size() * sizeof(index_entry)));
            if (!output)
            {
                throw std::runtime_error("Cannot write TTD index run");
            }
            index.clear();
        };
        uint64_t index_count = 0;
        file_.flush();
        file_.seekg(static_cast<std::streamoff>(sizeof(header) + header_.snapshot_size));
        for (uint64_t number = 0; number < header_.write_count; ++number)
        {
            const auto event = read_object<access_event>(file_);
            const auto last = event.address + std::min<uint64_t>(event.size - 1, UINT64_MAX - event.address);
            for (auto page = event.address / page_size; page <= last / page_size; ++page)
            {
                index.push_back({page, number, event.kind});
                ++index_count;
                if (index.size() == index_chunk_limit)
                {
                    flush_index_run();
                }
            }
        }
        if (runs.paths.empty())
        {
            std::sort(index.begin(), index.end(), index_less);
        }
        else if (!index.empty())
        {
            flush_index_run();
        }
        file_.clear();
        file_.seekp(0, std::ios::end);
        std::vector<checkpoint_entry> table{};
        table.reserve(checkpoints_.size());
        for (const auto& checkpoint : checkpoints_)
        {
            const auto offset = static_cast<uint64_t>(file_.tellp());
            file_.write(reinterpret_cast<const char*>(checkpoint.snapshot.data()),
                        static_cast<std::streamsize>(checkpoint.snapshot.size()));
            if (!file_)
            {
                throw std::runtime_error("Cannot write TTD checkpoint");
            }
            table.push_back({checkpoint.step, offset, checkpoint.snapshot.size()});
        }
        header_.checkpoint_count = table.size();
        header_.checkpoint_table_offset = static_cast<uint64_t>(file_.tellp());
        for (const auto& entry : table)
        {
            write_object(file_, entry);
        }
        header_.index_offset = static_cast<uint64_t>(file_.tellp());
        header_.index_count = index_count;
        if (runs.paths.empty())
        {
            for (const auto& entry : index)
            {
                write_object(file_, entry);
            }
        }
        else
        {
            struct run_reader
            {
                std::ifstream file{};
                uint64_t remaining{};
                std::array<index_entry, 4096> buffer{};
                size_t next{};
                size_t available{};

                std::optional<index_entry> read()
                {
                    if (next == available)
                    {
                        if (!remaining)
                        {
                            return std::nullopt;
                        }
                        available = static_cast<size_t>(std::min<uint64_t>(remaining, buffer.size()));
                        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(available * sizeof(index_entry)));
                        if (!file)
                        {
                            throw std::runtime_error("Truncated TTD index run");
                        }
                        remaining -= available;
                        next = 0;
                    }
                    return buffer[next++];
                }
            };

            struct merge_item
            {
                index_entry entry{};
                size_t run{};
            };

            const auto greater = [&](const merge_item& a, const merge_item& b) { return index_less(b.entry, a.entry); };
            std::priority_queue<merge_item, std::vector<merge_item>, decltype(greater)> queue(greater);
            std::vector<run_reader> readers(runs.paths.size());
            for (size_t i = 0; i < readers.size(); ++i)
            {
                readers[i].file.open(runs.paths[i], std::ios::binary);
                if (!readers[i].file)
                {
                    throw std::runtime_error("Cannot read TTD index run");
                }
                readers[i].remaining = runs.counts[i];
                queue.push({*readers[i].read(), i});
            }
            while (!queue.empty())
            {
                const auto item = queue.top();
                queue.pop();
                write_object(file_, item.entry);
                if (const auto next = readers[item.run].read())
                {
                    queue.push({*next, item.run});
                }
            }
        }
        file_.seekp(0);
        write_object(file_, header_);
        file_.flush();
        if (!file_)
        {
            throw std::runtime_error("Cannot finalize TTD trace");
        }
        finished_ = true;
    }

    trace::trace(const std::filesystem::path& path, const bool load_index)
        : file_(path, std::ios::binary)
    {
        if (!file_)
        {
            throw std::runtime_error("Cannot open TTD trace: " + path.string());
        }
        char magic[8]{};
        file_.read(magic, sizeof(magic));
        if (!file_)
        {
            throw std::runtime_error("Truncated TTD trace");
        }
        file_.seekg(0);
        const header expected{};
        if (!memcmp(magic, "SOGTTD1\0", sizeof(magic)))
        {
            legacy_ = true;
            const auto old = read_object<v1_header>(file_);
            header_size_ = sizeof(v1_header);
            header_.snapshot_size = old.snapshot_size;
            header_.instruction_count = old.instruction_count;
            header_.write_count = old.write_count;
            header_.checkpoint_table_offset = old.index_offset;
            header_.index_offset = old.index_offset;
            header_.index_count = old.index_count;
        }
        else if (!memcmp(magic, "SOGTTD2\0", sizeof(magic)))
        {
            legacy_ = true;
            header_ = read_object<header>(file_);
        }
        else if (!memcmp(magic, "SOGTTD3\0", sizeof(magic)))
        {
            v3_ = true;
            header_ = read_object<header>(file_);
        }
        else if (!memcmp(magic, expected.magic, sizeof(magic)))
        {
            header_ = read_object<header>(file_);
        }
        else
        {
            throw std::runtime_error("Unsupported TTD trace format");
        }
        event_size_ = legacy_ ? sizeof(write_event) : v3_ ? sizeof(v3_access_event) : sizeof(access_event);
        file_.seekg(0, std::ios::end);
        const auto length = static_cast<uint64_t>(file_.tellg());
        if (length < header_size_ || header_.snapshot_size > length - header_size_)
        {
            throw std::runtime_error("Invalid TTD trace snapshot size");
        }
        const auto event_start = header_size_ + header_.snapshot_size;
        if (header_.write_count > (UINT64_MAX - event_start) / event_size_ ||
            header_.checkpoint_table_offset < event_start + header_.write_count * event_size_ ||
            header_.checkpoint_table_offset > header_.index_offset ||
            header_.checkpoint_count > (header_.index_offset - header_.checkpoint_table_offset) / sizeof(checkpoint_entry) ||
            header_.index_offset > length ||
            header_.index_count > (length - header_.index_offset) / (legacy_ ? sizeof(old_index_entry) : sizeof(index_entry)))
        {
            throw std::runtime_error("Invalid TTD trace offsets");
        }
        snapshot_.resize(static_cast<size_t>(header_.snapshot_size));
        file_.seekg(static_cast<std::streamoff>(header_size_));
        file_.read(reinterpret_cast<char*>(snapshot_.data()), static_cast<std::streamsize>(snapshot_.size()));
        if (!file_)
        {
            throw std::runtime_error("Truncated TTD snapshot");
        }
        file_.seekg(static_cast<std::streamoff>(header_.checkpoint_table_offset));
        uint64_t previous_step{};
        for (uint64_t i = 0; i < header_.checkpoint_count; ++i)
        {
            const auto entry = read_object<checkpoint_entry>(file_);
            if (!entry.step || entry.step <= previous_step || entry.step > header_.instruction_count ||
                entry.offset < event_start + header_.write_count * event_size_ || entry.offset > header_.checkpoint_table_offset ||
                entry.size > header_.checkpoint_table_offset - entry.offset)
            {
                throw std::runtime_error("Invalid TTD checkpoint entry");
            }
            checkpoints_.push_back(entry);
            previous_step = entry.step;
        }
        if (load_index)
        {
            load_page_index();
        }
    }

    void trace::load_page_index()
    {
        if (page_index_loaded_)
        {
            return;
        }
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(header_.index_offset));
        for (uint64_t i = 0; i < header_.index_count; ++i)
        {
            const auto entry = legacy_ ? [&] {
                const auto old = read_object<old_index_entry>(file_);
                return index_entry{old.page, old.event_number, access_kind::write};
            }()
                                       : read_object<index_entry>(file_);
            if (entry.event_number >= header_.write_count)
            {
                throw std::runtime_error("Invalid TTD index entry");
            }
            page_index_.push_back(entry);
        }
        std::sort(page_index_.begin(), page_index_.end(), [](const auto& a, const auto& b) {
            if (a.page != b.page)
            {
                return a.page < b.page;
            }
            if (a.kind != b.kind)
            {
                return a.kind < b.kind;
            }
            return a.event_number < b.event_number;
        });
        page_index_loaded_ = true;
    }

    checkpoint_state trace::checkpoint_for_step(uint64_t step)
    {
        if (step > header_.instruction_count)
        {
            throw std::out_of_range("TTD position is beyond end of trace");
        }
        auto it = std::upper_bound(checkpoints_.begin(), checkpoints_.end(), step,
                                   [](uint64_t value, const checkpoint_entry& entry) { return value < entry.step; });
        if (it == checkpoints_.begin())
        {
            return {0, snapshot_};
        }
        --it;
        checkpoint_state state{it->step, {}};
        state.snapshot.resize(static_cast<size_t>(it->size));
        file_.seekg(static_cast<std::streamoff>(it->offset));
        file_.read(reinterpret_cast<char*>(state.snapshot.data()), static_cast<std::streamsize>(state.snapshot.size()));
        if (!file_)
        {
            throw std::runtime_error("Truncated TTD checkpoint");
        }
        return state;
    }

    access_event trace::event_at(const uint64_t number)
    {
        if (number >= header_.write_count)
        {
            throw std::out_of_range("TTD event is beyond end of trace");
        }
        file_.clear();
        const auto offset = static_cast<std::streamoff>(header_size_ + header_.snapshot_size + number * event_size_);
        if (file_.tellg() != offset)
        {
            file_.seekg(offset);
        }
        if (legacy_)
        {
            const auto old = read_object<write_event>(file_);
            return {old.step, old.ip, old.address, old.size, access_kind::write};
        }
        if (v3_)
        {
            const auto old = read_object<v3_access_event>(file_);
            return {old.step, old.ip, old.address, old.size, old.kind};
        }
        return read_object<access_event>(file_);
    }

    std::vector<access_event> trace::accesses(uint64_t address, uint64_t size, uint64_t first_step, uint64_t last_step, uint64_t kind_mask)
    {
        std::vector<access_event> result{};
        if (!size || first_step > last_step)
        {
            return result;
        }
        load_page_index();
        const auto last = address + std::min(size - 1, UINT64_MAX - address);
        std::set<uint64_t> numbers{};
        for (auto page = address / page_size; page <= last / page_size; ++page)
        {
            for (const auto kind : {access_kind::read, access_kind::write, access_kind::execute})
            {
                if (!(kind_mask & static_cast<uint64_t>(kind)))
                {
                    continue;
                }
                const auto key = index_entry{page, 0, kind};
                auto it = std::lower_bound(page_index_.begin(), page_index_.end(), key, [](const auto& a, const auto& b) {
                    return a.page < b.page || (a.page == b.page && a.kind < b.kind);
                });
                while (it != page_index_.end() && it->page == page && it->kind == kind)
                {
                    numbers.insert((it++)->event_number);
                }
            }
        }
        for (const auto number : numbers)
        {
            const auto event = event_at(number);
            if (event.step >= first_step && event.step <= last_step && (kind_mask & static_cast<uint64_t>(event.kind)) &&
                overlaps(event.address, event.size, address, size))
            {
                result.push_back(event);
            }
        }
        return result;
    }

    std::optional<access_event> trace::next_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask)
    {
        if (step == UINT64_MAX)
        {
            return std::nullopt;
        }
        const auto events = accesses(address, size, step + 1, UINT64_MAX, kind_mask);
        if (events.empty())
        {
            return std::nullopt;
        }
        return events.front();
    }

    std::optional<access_event> trace::previous_access(uint64_t address, uint64_t size, uint64_t step, uint64_t kind_mask)
    {
        if (!step)
        {
            return std::nullopt;
        }
        const auto events = accesses(address, size, 0, step - 1, kind_mask);
        if (events.empty())
        {
            return std::nullopt;
        }
        return events.back();
    }

    std::vector<self_modifying_hit> trace::self_modifying_code()
    {
        using writer_page = std::array<uint64_t, page_size>;
        std::unordered_map<uint64_t, writer_page> writers{};

        struct pending_hit
        {
            access_event execution;
            uint64_t writer_number;
            uint64_t count;
        };

        std::map<uint64_t, pending_hit> hits{};
        for (uint64_t number = 0; number < header_.write_count; ++number)
        {
            const auto event = event_at(number);
            if (!event.size)
            {
                continue;
            }
            const auto last = event.address + std::min<uint64_t>(event.size ? event.size - 1 : 0, UINT64_MAX - event.address);
            if (event.kind == access_kind::write)
            {
                for (uint64_t address = event.address; address <= last; ++address)
                {
                    writers[address / page_size][address % page_size] = number + 1;
                    if (address == UINT64_MAX)
                    {
                        break;
                    }
                }
            }
            else if (event.kind == access_kind::execute)
            {
                for (uint64_t address = event.address; address <= last; ++address)
                {
                    const auto page = writers.find(address / page_size);
                    if (page != writers.end() && page->second[address % page_size])
                    {
                        auto [it, inserted] = hits.try_emplace(event.address, pending_hit{event, page->second[address % page_size] - 1, 0});
                        ++it->second.count;
                        break;
                    }
                    if (address == UINT64_MAX)
                    {
                        break;
                    }
                }
            }
        }
        std::vector<self_modifying_hit> result{};
        result.reserve(hits.size());
        for (const auto& [address, hit] : hits)
        {
            const auto write = event_at(hit.writer_number);
            result.push_back({address, hit.execution.size, write.step, write.ip, hit.execution.step, hit.execution.ip, hit.count});
        }
        return result;
    }

    replay_selfmod_scanner::replay_selfmod_scanner(windows_emulator& emu, trace& recorded_writes)
        : emu_(emu),
          recorded_writes_(recorded_writes)
    {
        auto& cpu = emu_.emu();
        write_hook_ = scoped_hook(cpu, cpu.hook_memory_write_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
            if (next_write_ >= recorded_writes_.metadata().write_count)
            {
                error_ = "TTD replay produced an unrecorded memory write";
                emu_.stop();
                return;
            }
            const auto expected = recorded_writes_.event_at(next_write_);
            const auto step = emu_.get_executed_instructions();
            const auto ip = emu_.emu().read_instruction_pointer();
            if (expected.kind != access_kind::write || expected.step != step || expected.ip != ip || expected.address != address ||
                expected.size != size)
            {
                std::ostringstream message;
                message << "TTD replay memory write diverged at event " << next_write_ << ": expected step=" << expected.step
                        << " ip=" << std::hex << expected.ip << " address=" << expected.address << std::dec << " size=" << expected.size
                        << ", observed step=" << step << " ip=" << std::hex << ip << " address=" << address << std::dec << " size=" << size;
                error_ = message.str();
                emu_.stop();
                return;
            }
            if (size)
            {
                const auto last = address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
                for (uint64_t byte = address; byte <= last; ++byte)
                {
                    writers_[byte / page_size][byte % page_size] = next_write_ + 1;
                    if (byte == UINT64_MAX)
                    {
                        break;
                    }
                }
            }
            ++next_write_;
        }));
        execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
            if (error_ || first_hit_ || !size)
            {
                return;
            }
            const auto last = address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
            for (uint64_t byte = address; byte <= last; ++byte)
            {
                const auto page = writers_.find(byte / page_size);
                if (page != writers_.end() && page->second[byte % page_size])
                {
                    const auto writer = recorded_writes_.event_at(page->second[byte % page_size] - 1);
                    first_hit_ = self_modifying_hit{
                        address, size, writer.step, writer.ip, emu_.get_executed_instructions(), emu_.emu().read_instruction_pointer(), 1};
                    return;
                }
                if (byte == UINT64_MAX)
                {
                    break;
                }
            }
        }));
    }

    void replay_selfmod_scanner::finish()
    {
        write_hook_.remove();
        execute_hook_.remove();
        if (error_)
        {
            throw std::runtime_error(*error_);
        }
        if (next_write_ != recorded_writes_.metadata().write_count)
        {
            throw std::runtime_error("TTD replay ended before all recorded writes occurred");
        }
    }
}
