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

        struct v4_header
        {
            char magic[8]{};
            uint64_t snapshot_size{};
            uint64_t instruction_count{};
            uint64_t event_count{};
            uint64_t checkpoint_count{};
            uint64_t checkpoint_table_offset{};
            uint64_t index_offset{};
            uint64_t index_count{};
        };

        static_assert(sizeof(v4_header) == 64);

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

        constexpr auto writes_required = "TTD replay scans require a trace recorded with write events";

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
        if (!(access_mask & all_access_kinds))
        {
            throw std::invalid_argument("A TTD recording needs at least one access kind");
        }
        if (!file_)
        {
            throw std::runtime_error("Cannot create TTD trace: " + path.string());
        }
        // This also makes the initial process/thread state explicit in the snapshot.
        emu_.setup_process_if_necessary();
        const auto bytes = snapshot::create_emulator_snapshot(emu_);
        header_.snapshot_size = bytes.size();
        header_.access_mask = access_mask & all_access_kinds;
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
        ++header_.event_count;
    }

    recorder::~recorder()
    {
        try
        {
            finish();
        }
        catch (const std::exception& e)
        {
            emu_.log.error("TTD trace %s was not finalized: %s\n", path_.string().c_str(), e.what());
        }
        catch (...)
        {
            emu_.log.error("TTD trace %s was not finalized\n", path_.string().c_str());
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
        finished_ = true;
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
        for (uint64_t number = 0; number < header_.event_count; ++number)
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
        const auto read_v4_header = [&] {
            const auto old = read_object<v4_header>(file_);
            header_size_ = sizeof(v4_header);
            header_.snapshot_size = old.snapshot_size;
            header_.instruction_count = old.instruction_count;
            header_.event_count = old.event_count;
            header_.checkpoint_count = old.checkpoint_count;
            header_.checkpoint_table_offset = old.checkpoint_table_offset;
            header_.index_offset = old.index_offset;
            header_.index_count = old.index_count;
        };
        const header expected{};
        if (!memcmp(magic, "SOGTTD1\0", sizeof(magic)))
        {
            legacy_ = true;
            const auto old = read_object<v1_header>(file_);
            header_size_ = sizeof(v1_header);
            header_.snapshot_size = old.snapshot_size;
            header_.instruction_count = old.instruction_count;
            header_.event_count = old.write_count;
            header_.checkpoint_table_offset = old.index_offset;
            header_.index_offset = old.index_offset;
            header_.index_count = old.index_count;
            access_mask_ = static_cast<uint64_t>(access_kind::write);
        }
        else if (!memcmp(magic, "SOGTTD2\0", sizeof(magic)))
        {
            legacy_ = true;
            read_v4_header();
            access_mask_ = static_cast<uint64_t>(access_kind::write);
        }
        else if (!memcmp(magic, "SOGTTD3\0", sizeof(magic)))
        {
            v3_ = true;
            read_v4_header();
        }
        else if (!memcmp(magic, "SOGTTD4\0", sizeof(magic)))
        {
            read_v4_header();
        }
        else if (!memcmp(magic, expected.magic, sizeof(magic)))
        {
            header_ = read_object<header>(file_);
            if (!header_.access_mask || (header_.access_mask & ~all_access_kinds))
            {
                throw std::runtime_error("Invalid TTD trace access mask");
            }
            access_mask_ = header_.access_mask;
        }
        else
        {
            throw std::runtime_error("Unsupported TTD trace format");
        }
        if (!header_.index_offset)
        {
            throw std::runtime_error("TTD trace was not finalized; the recording was interrupted");
        }
        event_size_ = legacy_ ? sizeof(write_event) : v3_ ? sizeof(v3_access_event) : sizeof(access_event);
        file_.seekg(0, std::ios::end);
        const auto length = static_cast<uint64_t>(file_.tellg());
        if (length < header_size_ || header_.snapshot_size > length - header_size_)
        {
            throw std::runtime_error("Invalid TTD trace snapshot size");
        }
        const auto event_start = header_size_ + header_.snapshot_size;
        if (header_.event_count > (UINT64_MAX - event_start) / event_size_ ||
            header_.checkpoint_table_offset < event_start + header_.event_count * event_size_ ||
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
                entry.offset < event_start + header_.event_count * event_size_ || entry.offset > header_.checkpoint_table_offset ||
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
            if (entry.event_number >= header_.event_count)
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
        if (number >= header_.event_count)
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

    size_t trace::read_events(const uint64_t first_number, const std::span<access_event> output)
    {
        if (first_number >= header_.event_count || output.empty())
        {
            return 0;
        }
        const auto count = static_cast<size_t>(std::min<uint64_t>(output.size(), header_.event_count - first_number));
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(header_size_ + header_.snapshot_size + first_number * event_size_));
        if (!legacy_ && !v3_)
        {
            file_.read(reinterpret_cast<char*>(output.data()), static_cast<std::streamsize>(count * sizeof(access_event)));
            if (!file_)
            {
                throw std::runtime_error("Truncated TTD trace");
            }
            return count;
        }
        std::vector<std::byte> raw(count * event_size_);
        file_.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
        if (!file_)
        {
            throw std::runtime_error("Truncated TTD trace");
        }
        for (size_t i = 0; i < count; ++i)
        {
            const auto* entry = raw.data() + i * event_size_;
            if (legacy_)
            {
                write_event old{};
                memcpy(&old, entry, sizeof(old));
                output[i] = {old.step, old.ip, old.address, old.size, access_kind::write};
            }
            else
            {
                v3_access_event old{};
                memcpy(&old, entry, sizeof(old));
                output[i] = {old.step, old.ip, old.address, old.size, old.kind};
            }
        }
        return count;
    }

    uint64_t trace::first_event_after(const uint64_t step)
    {
        uint64_t low = 0;
        uint64_t high = header_.event_count;
        while (low < high)
        {
            const auto middle = low + (high - low) / 2;
            if (event_at(middle).step <= step)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }
        return low;
    }

    uint64_t trace::access_mask()
    {
        if (!access_mask_)
        {
            uint64_t mask = 0;
            event_reader reader(*this);
            while (mask != all_access_kinds)
            {
                const auto event = reader.next();
                if (!event)
                {
                    break;
                }
                mask |= static_cast<uint64_t>(event->kind);
            }
            access_mask_ = mask;
        }
        return *access_mask_;
    }

    event_reader::event_reader(trace& recorded, const uint64_t first_number)
        : trace_(recorded),
          buffer_first_(first_number),
          last_number_(first_number ? first_number - 1 : 0)
    {
    }

    std::optional<access_event> event_reader::next(const uint64_t kind_mask)
    {
        constexpr size_t buffer_events = 16384;
        while (true)
        {
            if (position_ == buffer_.size())
            {
                buffer_first_ += buffer_.size();
                buffer_.resize(buffer_events);
                buffer_.resize(trace_.read_events(buffer_first_, buffer_));
                position_ = 0;
                if (buffer_.empty())
                {
                    return std::nullopt;
                }
            }
            const auto& event = buffer_[position_];
            last_number_ = buffer_first_ + position_++;
            if (kind_mask & static_cast<uint64_t>(event.kind))
            {
                return event;
            }
        }
    }

    replay_verifier::replay_verifier(windows_emulator& emu, trace& recorded, const uint64_t from_step)
        : emu_(emu),
          trace_(recorded),
          reader_(recorded, recorded.first_event_after(from_step)),
          access_mask_(recorded.access_mask())
    {
        auto& cpu = emu_.emu();
        if (access_mask_ & static_cast<uint64_t>(access_kind::write))
        {
            write_hook_ =
                scoped_hook(cpu, cpu.hook_memory_write_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
                    verify(access_kind::write, address, size);
                }));
        }
        if (access_mask_ & static_cast<uint64_t>(access_kind::read))
        {
            read_hook_ =
                scoped_hook(cpu, cpu.hook_memory_read_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
                    verify(access_kind::read, address, size);
                }));
        }
        if (access_mask_ & static_cast<uint64_t>(access_kind::execute))
        {
            execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
                verify(access_kind::execute, address, size);
            }));
        }
    }

    void replay_verifier::verify(const access_kind kind, const uint64_t address, const size_t size)
    {
        if (error_ || !size)
        {
            return;
        }
        access_event observed{emu_.get_executed_instructions(), emu_.emu().read_instruction_pointer(), address, size, kind};
        if (kind == access_kind::execute && trace_.has_instruction_bytes() && size <= 15)
        {
            emu_.emu().try_read_memory(address, observed.instruction_bytes.data(), size);
        }
        const auto expected = reader_.next(access_mask_);
        if (expected && expected->kind == observed.kind && expected->step == observed.step && expected->ip == observed.ip &&
            expected->address == observed.address && expected->size == observed.size &&
            (kind != access_kind::execute || !trace_.has_instruction_bytes() || expected->instruction_bytes == observed.instruction_bytes))
        {
            ++verified_events_;
            return;
        }
        const auto describe = [](std::ostream& stream, const access_event& event) {
            stream << (event.kind == access_kind::read    ? "read"
                       : event.kind == access_kind::write ? "write"
                                                          : "execute")
                   << " step=" << std::hex << event.step << " ip=" << event.ip << " address=" << event.address << std::dec
                   << " size=" << event.size;
        };
        std::ostringstream message;
        message << "TTD replay diverged from the recording";
        if (expected)
        {
            message << " at event " << reader_.last_number() << ": expected ";
            describe(message, *expected);
        }
        else
        {
            message << " after its last event: expected nothing";
        }
        message << ", observed ";
        describe(message, observed);
        error_ = message.str();
        emu_.stop();
    }

    void replay_verifier::finish()
    {
        write_hook_.remove();
        read_hook_.remove();
        execute_hook_.remove();
        if (error_)
        {
            throw std::runtime_error(*error_);
        }
        const auto position = emu_.get_executed_instructions();
        if (const auto missed = reader_.next(access_mask_); missed && missed->step <= position)
        {
            std::ostringstream message;
            message << "TTD replay reached position " << std::hex << position << " without recorded event " << std::dec
                    << reader_.last_number() << " at step " << std::hex << missed->step;
            throw std::runtime_error(message.str());
        }
    }

    std::optional<uint64_t> trace::latest_write_to_byte(const uint64_t page, const uint64_t address, const uint64_t first_number,
                                                        const uint64_t last_number)
    {
        if (first_number > last_number || !header_.index_count)
        {
            return std::nullopt;
        }
        const auto entry_size = legacy_ ? sizeof(old_index_entry) : sizeof(index_entry);
        const auto entry_at = [&](const uint64_t number) {
            file_.clear();
            file_.seekg(static_cast<std::streamoff>(header_.index_offset + number * entry_size));
            if (legacy_)
            {
                const auto old = read_object<old_index_entry>(file_);
                return index_entry{old.page, old.event_number, access_kind::write};
            }
            return read_object<index_entry>(file_);
        };
        const auto less_than_key = [](const index_entry& entry, const uint64_t key_page, const access_kind key_kind,
                                      const uint64_t key_number) {
            return entry.page < key_page ||
                   (entry.page == key_page && (entry.kind < key_kind || (entry.kind == key_kind && entry.event_number < key_number)));
        };
        const auto lower_bound_on_disk = [&](const uint64_t number) {
            uint64_t low = 0;
            uint64_t high = header_.index_count;
            while (low < high)
            {
                const auto middle = low + (high - low) / 2;
                if (less_than_key(entry_at(middle), page, access_kind::write, number))
                {
                    low = middle + 1;
                }
                else
                {
                    high = middle;
                }
            }
            return low;
        };
        const auto first = lower_bound_on_disk(first_number);
        auto end = last_number == UINT64_MAX ? header_.index_count : lower_bound_on_disk(last_number + 1);
        while (end > first)
        {
            const auto entry = entry_at(--end);
            if (entry.page != page || entry.kind != access_kind::write || entry.event_number >= header_.event_count)
            {
                continue;
            }
            const auto event = event_at(entry.event_number);
            if (event.kind == access_kind::write && event.address <= address && address - event.address < event.size)
            {
                return entry.event_number;
            }
        }
        return std::nullopt;
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
        for (uint64_t number = 0; number < header_.event_count; ++number)
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

    replay_selfmod_scanner::replay_selfmod_scanner(windows_emulator& emu, trace& recorded_writes, const uint64_t capture_address,
                                                   const size_t capture_size, const size_t capture_wave)
        : emu_(emu),
          recorded_writes_(recorded_writes),
          expected_writes_(recorded_writes),
          capture_address_(capture_address),
          capture_size_(capture_size),
          capture_wave_(capture_wave)
    {
        if (!(recorded_writes_.access_mask() & static_cast<uint64_t>(access_kind::write)))
        {
            throw std::runtime_error(writes_required);
        }
        auto& cpu = emu_.emu();
        emu_.memory.set_mapping_change_callback([this](const uint64_t address, const size_t size) {
            if (!size)
            {
                return;
            }
            const auto last = address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
            const auto first_page = address / page_size;
            const auto last_page = last / page_size;
            for (auto it = writers_.begin(); it != writers_.end();)
            {
                if (it->first >= first_page && it->first <= last_page)
                {
                    page_latest_write_.erase(it->first);
                    reported_page_writes_.erase(it->first);
                    it = writers_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        });
        write_hook_ = scoped_hook(cpu, cpu.hook_memory_write_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
            if (error_ || !size)
            {
                return;
            }
            const auto expected = expected_writes_.next(static_cast<uint64_t>(access_kind::write));
            if (!expected)
            {
                error_ = "TTD replay produced an unrecorded memory write";
                emu_.stop();
                return;
            }
            const auto number = expected_writes_.last_number();
            const auto step = emu_.get_executed_instructions();
            const auto ip = emu_.emu().read_instruction_pointer();
            if (expected->step != step || expected->ip != ip || expected->address != address || expected->size != size)
            {
                std::ostringstream message;
                message << "TTD replay memory write diverged at event " << number << ": expected step=" << expected->step
                        << " ip=" << std::hex << expected->ip << " address=" << expected->address << std::dec << " size=" << expected->size
                        << ", observed step=" << step << " ip=" << std::hex << ip << " address=" << address << std::dec << " size=" << size;
                error_ = message.str();
                emu_.stop();
                return;
            }
            const auto last = address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
            for (uint64_t byte = address; byte <= last; ++byte)
            {
                auto [it, inserted] = writers_.try_emplace(byte / page_size);
                if (inserted)
                {
                    it->second.first_number = number;
                }
                it->second.bytes[(byte % page_size) / 64] |= uint64_t{1} << (byte % 64);
                page_latest_write_[byte / page_size] = number + 1;
                if (byte == UINT64_MAX)
                {
                    break;
                }
            }
            last_write_number_ = number;
            ++verified_writes_;
        }));
        execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
            if (error_ || !size || hits_.size() >= 256)
            {
                return;
            }
            const auto last = address + std::min<uint64_t>(size - 1, UINT64_MAX - address);
            for (uint64_t byte = address; byte <= last; ++byte)
            {
                const auto page = writers_.find(byte / page_size);
                if (page != writers_.end() && (page->second.bytes[(byte % page_size) / 64] & (uint64_t{1} << (byte % 64))))
                {
                    const auto reported = reported_page_writes_.find(byte / page_size);
                    const auto latest = page_latest_write_.at(byte / page_size);
                    if (reported != reported_page_writes_.end() && reported->second >= latest)
                    {
                        continue;
                    }
                    const auto first_number = reported == reported_page_writes_.end() ? page->second.first_number : reported->second;
                    const auto writer_number =
                        recorded_writes_.latest_write_to_byte(byte / page_size, byte, first_number, last_write_number_);
                    if (!writer_number)
                    {
                        continue;
                    }
                    reported_page_writes_[byte / page_size] = latest;
                    const auto writer = recorded_writes_.event_at(*writer_number);
                    const auto hit = self_modifying_hit{
                        address, size, writer.step, writer.ip, emu_.get_executed_instructions(), emu_.emu().read_instruction_pointer(), 1};
                    if (!first_hit_)
                    {
                        first_hit_ = hit;
                    }
                    if (hits_.size() + 1 == capture_wave_ && capture_size_)
                    {
                        captured_memory_.resize(capture_size_);
                        for (size_t offset = 0; offset < capture_size_; offset += page_size)
                        {
                            const auto length = std::min<size_t>(page_size, capture_size_ - offset);
                            if (!emu_.emu().try_read_memory(capture_address_ + offset, captured_memory_.data() + offset, length))
                            {
                                std::fill_n(captured_memory_.data() + offset, length, uint8_t{0});
                                ++missing_capture_pages_;
                            }
                        }
                    }
                    if (hits_.size() < 256)
                    {
                        hits_.push_back(hit);
                    }
                    return;
                }
                if (byte == UINT64_MAX)
                {
                    break;
                }
            }
        }));
    }

    replay_selfmod_scanner::~replay_selfmod_scanner()
    {
        emu_.memory.set_mapping_change_callback({});
    }

    void replay_selfmod_scanner::finish()
    {
        emu_.memory.set_mapping_change_callback({});
        write_hook_.remove();
        execute_hook_.remove();
        if (error_)
        {
            throw std::runtime_error(*error_);
        }
        if (expected_writes_.next(static_cast<uint64_t>(access_kind::write)))
        {
            throw std::runtime_error("TTD replay ended before all recorded writes occurred");
        }
    }
}
