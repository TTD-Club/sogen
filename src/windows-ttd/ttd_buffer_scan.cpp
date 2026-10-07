#include "ttd_buffer_scan.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace sogen::ttd
{
    namespace
    {
        constexpr uint64_t nearby_bytes = 16;
        constexpr uint64_t nearby_steps = 250000;
        constexpr size_t maximum_region = 256 * 1024;
        constexpr size_t maximum_active_regions = 16384;
        constexpr size_t maximum_results = 20000;
        constexpr size_t maximum_retained_bytes = 64 * 1024 * 1024;

        bool printable(const uint8_t byte)
        {
            return byte >= 0x20 && byte <= 0x7e;
        }

        bool begins(std::span<const uint8_t> bytes, std::initializer_list<uint8_t> prefix)
        {
            return bytes.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), bytes.begin());
        }

        uint32_t little32(std::span<const uint8_t> bytes, const size_t offset)
        {
            return uint32_t{bytes[offset]} | (uint32_t{bytes[offset + 1]} << 8) | (uint32_t{bytes[offset + 2]} << 16) |
                   (uint32_t{bytes[offset + 3]} << 24);
        }

        std::string signature(std::span<const uint8_t> bytes)
        {
            if (begins(bytes, {'M', 'Z'}) && bytes.size() >= 0x40)
            {
                const auto pe_offset = little32(bytes, 0x3c);
                if (pe_offset <= bytes.size() - 4 && begins(bytes.subspan(pe_offset), {'P', 'E', 0, 0}))
                {
                    return "pe_image";
                }
            }
            if (begins(bytes, {0x7f, 'E', 'L', 'F'}))
            {
                return "elf_image";
            }
            if (begins(bytes, {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}))
            {
                return "png_image";
            }
            if (begins(bytes, {0xff, 0xd8, 0xff}))
            {
                return "jpeg_image";
            }
            if (begins(bytes, {'G', 'I', 'F', '8'}))
            {
                return "gif_image";
            }
            if (begins(bytes, {'B', 'M'}))
            {
                return "bmp_image";
            }
            if (begins(bytes, {'%', 'P', 'D', 'F', '-'}))
            {
                return "pdf_document";
            }
            if (begins(bytes, {'P', 'K', 3, 4}))
            {
                return "zip_archive";
            }
            if (begins(bytes, {0x1f, 0x8b, 0x08}))
            {
                return "gzip_stream";
            }
            if (begins(bytes, {'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', 0}))
            {
                return "sqlite_database";
            }
            if (begins(bytes, {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' '}))
            {
                const auto text = std::string(reinterpret_cast<const char*>(bytes.data()), std::min<size_t>(bytes.size(), 128));
                if (text.find("PRIVATE KEY-----") != std::string::npos)
                {
                    return "pem_private_key";
                }
                if (text.find("PUBLIC KEY-----") != std::string::npos)
                {
                    return "pem_public_key";
                }
            }
            return {};
        }

        double entropy(std::span<const uint8_t> bytes)
        {
            std::array<size_t, 256> counts{};
            for (const auto byte : bytes)
            {
                ++counts[byte];
            }
            double value = 0;
            for (const auto count : counts)
            {
                if (count)
                {
                    const auto probability = static_cast<double>(count) / static_cast<double>(bytes.size());
                    value -= probability * std::log2(probability);
                }
            }
            return value;
        }

        std::string preview(std::span<const uint8_t> bytes, const bool as_text)
        {
            std::ostringstream stream;
            for (const auto byte : bytes.first(std::min<size_t>(bytes.size(), 48)))
            {
                if (as_text)
                {
                    stream << (printable(byte) ? static_cast<char>(byte) : '.');
                }
                else
                {
                    stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
                }
            }
            return stream.str();
        }
    }

    buffer_scanner::buffer_scanner(windows_emulator& emu, trace& recorded_writes)
        : emu_(emu),
          trace_(recorded_writes),
          expected_writes_(recorded_writes, recorded_writes.first_event_after(emu.get_executed_instructions()))
    {
        if (!(trace_.access_mask() & static_cast<uint64_t>(access_kind::write)))
        {
            throw std::runtime_error("TTD buffer scan requires a trace recorded with write events");
        }
        auto& cpu = emu_.emu();
        emu_.memory.set_mapping_change_callback([this](const uint64_t address, const size_t size) {
            if (!size)
            {
                return;
            }
            const auto end = address + std::min<uint64_t>(size, UINT64_MAX - address);
            for (auto it = active_.begin(); it != active_.end();)
            {
                if (it->first < end && it->first + it->second.bytes.size() > address)
                {
                    auto& value = it->second;
                    const auto clear_begin = static_cast<size_t>(std::max(it->first, address) - it->first);
                    const auto clear_end = static_cast<size_t>(std::min(it->first + value.bytes.size(), end) - it->first);
                    region removed{};
                    removed.base = it->first + clear_begin;
                    removed.bytes.assign(value.bytes.begin() + static_cast<ptrdiff_t>(clear_begin),
                                         value.bytes.begin() + static_cast<ptrdiff_t>(clear_end));
                    removed.known.assign(value.known.begin() + static_cast<ptrdiff_t>(clear_begin),
                                         value.known.begin() + static_cast<ptrdiff_t>(clear_end));
                    removed.executed.assign(value.executed.begin() + static_cast<ptrdiff_t>(clear_begin),
                                            value.executed.begin() + static_cast<ptrdiff_t>(clear_end));
                    removed.first_step = value.first_step;
                    removed.last_step = value.last_step;
                    removed.writer_ip = value.writer_ip;
                    removed.writes = value.writes;
                    emit(std::move(removed));
                    std::fill(value.known.begin() + static_cast<ptrdiff_t>(clear_begin),
                              value.known.begin() + static_cast<ptrdiff_t>(clear_end), uint8_t{0});
                    std::fill(value.executed.begin() + static_cast<ptrdiff_t>(clear_begin),
                              value.executed.begin() + static_cast<ptrdiff_t>(clear_end), uint8_t{0});
                    if (std::none_of(value.known.begin(), value.known.end(), [](uint8_t byte) { return byte != 0; }))
                    {
                        it = active_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
                else
                {
                    ++it;
                }
            }
        });
        write_hook_ = scoped_hook(
            cpu, cpu.hook_memory_write_data(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, std::span<const std::byte> data) {
                const auto size = data.size();
                if (error_ || !size)
                {
                    return;
                }
                const auto expected = expected_writes_.next(static_cast<uint64_t>(access_kind::write));
                if (!expected)
                {
                    error_ = "TTD buffer scan produced an unrecorded write";
                    emu_.stop();
                    return;
                }
                const auto step = emu_.get_executed_instructions();
                const auto ip = emu_.emu().read_instruction_pointer();
                if (expected->step != step || expected->ip != ip || expected->address != address || expected->size != size)
                {
                    error_ = "TTD buffer scan replay diverged at write event " + std::to_string(expected_writes_.last_number());
                    emu_.stop();
                    return;
                }
                pending_.push_back({address, size, step, ip});
                ++verified_writes_;
            }));
        execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t address, size_t size) {
            flush_pending();
            if (!size)
            {
                return;
            }
            auto it = active_.upper_bound(address);
            while (it != active_.begin())
            {
                --it;
                if (address - it->first >= maximum_region)
                {
                    break;
                }
                if (address - it->first < it->second.known.size())
                {
                    const auto offset = static_cast<size_t>(address - it->first);
                    for (size_t byte = offset; byte < std::min(it->second.known.size(), offset + size); ++byte)
                    {
                        if (it->second.known[byte])
                        {
                            it->second.executed[byte] = 1;
                        }
                    }
                }
            }
        }));
    }

    buffer_scanner::~buffer_scanner()
    {
        emu_.memory.set_mapping_change_callback({});
    }

    void buffer_scanner::flush_pending()
    {
        for (const auto& write : pending_)
        {
            for (size_t offset = 0; offset < write.size;)
            {
                const auto length = std::min(maximum_region, write.size - offset);
                std::vector<uint8_t> bytes(length);
                if (emu_.emu().try_read_memory(write.address + offset, bytes.data(), length))
                {
                    ingest({write.address + offset, length, write.step, write.ip}, bytes);
                }
                else
                {
                    skipped_bytes_ += length;
                }
                offset += length;
            }
        }
        pending_.clear();
    }

    void buffer_scanner::ingest(const pending_write& write, std::span<const uint8_t> bytes)
    {
        if (write.address > UINT64_MAX - bytes.size())
        {
            return;
        }
        const auto end = write.address + bytes.size();
        auto it = active_.upper_bound(write.address);
        if (it != active_.begin())
        {
            --it;
            const auto old_end = it->first + it->second.bytes.size();
            if (old_end + std::min<uint64_t>(nearby_bytes, UINT64_MAX - old_end) < write.address)
            {
                ++it;
            }
        }
        if (it != active_.end() && it->first <= end + std::min<uint64_t>(nearby_bytes, UINT64_MAX - end))
        {
            auto& current = it->second;
            const auto combined_begin = std::min(it->first, write.address);
            const auto combined_end = std::max(it->first + current.bytes.size(), end);
            bool changes_executed_version = false;
            if (write.address < it->first + current.bytes.size())
            {
                const auto overlap_begin = std::max(it->first, write.address);
                const auto overlap_end = std::min(it->first + current.bytes.size(), end);
                for (auto address = overlap_begin; address < overlap_end; ++address)
                {
                    const auto old_offset = static_cast<size_t>(address - it->first);
                    if (current.executed[old_offset] && current.bytes[old_offset] != bytes[static_cast<size_t>(address - write.address)])
                    {
                        changes_executed_version = true;
                        break;
                    }
                }
            }
            if (changes_executed_version)
            {
                emit(std::move(current));
                active_.erase(it);
            }
            else if (write.step >= current.last_step &&
                     (write.address < it->first + current.bytes.size() || write.step - current.last_step <= nearby_steps) &&
                     combined_end - combined_begin <= maximum_region)
            {
                if (combined_begin < it->first)
                {
                    const auto prefix = static_cast<size_t>(it->first - combined_begin);
                    current.bytes.insert(current.bytes.begin(), prefix, 0);
                    current.known.insert(current.known.begin(), prefix, 0);
                    current.executed.insert(current.executed.begin(), prefix, 0);
                    current.base = combined_begin;
                    auto node = active_.extract(it);
                    node.key() = combined_begin;
                    it = active_.insert(std::move(node)).position;
                }
                current.bytes.resize(static_cast<size_t>(combined_end - combined_begin));
                current.known.resize(current.bytes.size());
                current.executed.resize(current.bytes.size());
                const auto offset = static_cast<size_t>(write.address - combined_begin);
                std::copy(bytes.begin(), bytes.end(), current.bytes.begin() + static_cast<ptrdiff_t>(offset));
                std::fill_n(current.known.begin() + static_cast<ptrdiff_t>(offset), bytes.size(), uint8_t{1});
                std::fill_n(current.executed.begin() + static_cast<ptrdiff_t>(offset), bytes.size(), uint8_t{0});
                current.last_step = write.step;
                current.writer_ip = write.ip;
                ++current.writes;
                return;
            }
            else if (write.address < it->first + current.bytes.size())
            {
                emit(std::move(current));
                active_.erase(it);
            }
        }
        region value{};
        value.base = write.address;
        value.bytes.assign(bytes.begin(), bytes.end());
        value.known.assign(bytes.size(), 1);
        value.executed.assign(bytes.size(), uint8_t{0});
        value.first_step = value.last_step = write.step;
        value.writer_ip = write.ip;
        value.writes = 1;
        if (auto existing = active_.find(write.address); existing != active_.end())
        {
            emit(std::move(existing->second));
            active_.erase(existing);
        }
        active_.emplace(write.address, std::move(value));
        if (active_.size() > maximum_active_regions)
        {
            evict_oldest();
        }
    }

    void buffer_scanner::evict_oldest()
    {
        const auto oldest = std::min_element(active_.begin(), active_.end(), [](const auto& a, const auto& b) {
            const auto a_small = a.second.bytes.size() < 512;
            const auto b_small = b.second.bytes.size() < 512;
            return a_small != b_small ? a_small : a.second.last_step < b.second.last_step;
        });
        emit(std::move(oldest->second));
        active_.erase(oldest);
    }

    void buffer_scanner::emit(region&& value)
    {
        const auto add = [&](const size_t begin, std::span<const uint8_t> bytes, std::string kind, const bool text,
                             const bool utf16 = false) {
            if (results_.size() == maximum_results || bytes.empty())
            {
                return;
            }
            std::string display = preview(bytes, text);
            if (utf16)
            {
                display.clear();
                for (size_t i = 0; i + 1 < std::min<size_t>(bytes.size(), 96); i += 2)
                {
                    display.push_back(static_cast<char>(bytes[i]));
                }
            }
            recovered_buffer result{value.base + begin, bytes.size(), value.first_step, value.last_step,
                                    value.writer_ip,    value.writes, std::move(kind),  std::move(display)};
            if (bytes.size() <= maximum_retained_bytes - retained_bytes_)
            {
                result.data.assign(bytes.begin(), bytes.end());
                retained_bytes_ += bytes.size();
            }
            results_.push_back(std::move(result));
        };
        for (size_t offset = 0; offset < value.known.size() && results_.size() < maximum_results;)
        {
            while (offset < value.known.size() && !value.known[offset])
            {
                ++offset;
            }
            const auto begin = offset;
            while (offset < value.known.size() && value.known[offset])
            {
                ++offset;
            }
            if (offset - begin < 16)
            {
                continue;
            }
            const auto bytes = std::span<const uint8_t>(value.bytes).subspan(begin, offset - begin);
            auto kind = signature(bytes);
            const auto text_count = static_cast<size_t>(std::count_if(bytes.begin(), bytes.end(), printable));
            const bool text = bytes.size() >= 32 && text_count * 100 >= bytes.size() * 90;
            if (kind.empty() &&
                std::any_of(value.executed.begin() + static_cast<ptrdiff_t>(begin), value.executed.begin() + static_cast<ptrdiff_t>(offset),
                            [](uint8_t byte) { return byte != 0; }))
            {
                kind = "contains_executed_code";
            }
            if (kind.empty() && text)
            {
                kind = "ascii_text";
            }
            if (kind.empty() && bytes.size() >= 32)
            {
                size_t pairs = 0;
                for (size_t i = 0; i + 1 < bytes.size(); i += 2)
                {
                    pairs += printable(bytes[i]) && !bytes[i + 1];
                }
                if (pairs * 100 >= (bytes.size() / 2) * 85)
                {
                    kind = "utf16le_text";
                }
            }
            if (kind.empty() && bytes.size() >= 256 && entropy(bytes) >= 7.5)
            {
                kind = "high_entropy_buffer";
            }
            if (kind.empty() && bytes.size() >= 512)
            {
                kind = "buffer";
            }
            if (!kind.empty())
            {
                add(begin, bytes, std::move(kind), text);
            }
            size_t strings = 0;
            for (size_t i = 0; i < bytes.size() && strings < 128 && results_.size() < maximum_results;)
            {
                if (!printable(bytes[i]))
                {
                    ++i;
                    continue;
                }
                size_t end = i;
                while (end < bytes.size() && printable(bytes[end]))
                {
                    ++end;
                }
                if (end - i >= 16 && !(text && i == 0 && end == bytes.size()))
                {
                    add(begin + i, bytes.subspan(i, end - i), "ascii_string", true);
                    ++strings;
                }
                i = end;
            }
            strings = 0;
            for (size_t i = 0; i + 1 < bytes.size() && strings < 128 && results_.size() < maximum_results; ++i)
            {
                if (!printable(bytes[i]) || bytes[i + 1] || (i >= 2 && printable(bytes[i - 2]) && !bytes[i - 1]))
                {
                    continue;
                }
                size_t end = i;
                while (end + 1 < bytes.size() && printable(bytes[end]) && !bytes[end + 1])
                {
                    end += 2;
                }
                if (end - i >= 24)
                {
                    add(begin + i, bytes.subspan(i, end - i), "utf16le_string", false, true);
                    ++strings;
                }
                i = end - 1;
            }
            size_t signatures = 0;
            for (size_t i = 1; i + 16 < bytes.size() && signatures < 64 && results_.size() < maximum_results; ++i)
            {
                const auto first = bytes[i];
                if (first != 'M' && first != 0x89 && first != 'G' && first != '%' && first != 'P' && first != 'S' && first != '-')
                {
                    continue;
                }
                const auto embedded = signature(bytes.subspan(i));
                if (!embedded.empty() && embedded != "bmp_image" && embedded != "jpeg_image")
                {
                    add(begin + i, bytes.subspan(i), embedded, false);
                    ++signatures;
                }
            }
        }
    }

    void buffer_scanner::finish()
    {
        if (finished_)
        {
            return;
        }
        write_hook_.remove();
        execute_hook_.remove();
        flush_pending();
        emu_.memory.set_mapping_change_callback({});
        for (auto& [address, value] : active_)
        {
            (void)address;
            emit(std::move(value));
        }
        active_.clear();
        finished_ = true;
        if (error_)
        {
            throw std::runtime_error(*error_);
        }
        if (expected_writes_.next(static_cast<uint64_t>(access_kind::write)))
        {
            throw std::runtime_error("TTD buffer scan ended before all recorded writes occurred");
        }
    }

    void buffer_scanner::save(const std::filesystem::path& path) const
    {
        const auto artifact_dir = std::filesystem::path(path.string() + ".buffers");
        std::filesystem::create_directories(artifact_dir);
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output)
        {
            throw std::runtime_error("Cannot create TTD buffer report: " + path.string());
        }
        output << "address\tsize\tfirst_step\tlast_step\twriter_ip\twrites\tkind\tpreview\tartifact\n";
        for (size_t index = 0; index < results_.size(); ++index)
        {
            const auto& result = results_[index];
            std::string artifact{};
            if (!result.data.empty())
            {
                std::ostringstream name;
                name << std::hex << result.address << '-' << std::dec << result.first_step << '-' << index << ".bin";
                artifact = name.str();
                std::ofstream bytes_file(artifact_dir / artifact, std::ios::binary | std::ios::trunc);
                bytes_file.write(reinterpret_cast<const char*>(result.data.data()), static_cast<std::streamsize>(result.data.size()));
                if (!bytes_file)
                {
                    throw std::runtime_error("Writing TTD buffer artifact failed");
                }
            }
            output << std::hex << result.address << '\t' << std::dec << result.size << '\t' << result.first_step << '\t' << result.last_step
                   << '\t' << std::hex << result.writer_ip << '\t' << std::dec << result.writes << '\t' << result.kind << '\t'
                   << result.preview << '\t' << artifact << '\n';
        }
        if (!output)
        {
            throw std::runtime_error("Writing TTD buffer report failed");
        }
    }
}
