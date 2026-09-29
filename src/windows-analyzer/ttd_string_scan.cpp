#include "ttd_string_scan.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace sogen::ttd
{
    namespace
    {
        constexpr uint64_t scan_chunk = 65536;
        constexpr uint64_t context_bytes = 512;
        constexpr size_t maximum_string_length = 4096;

        bool printable(uint8_t value)
        {
            return value >= 0x20 && value <= 0x7e;
        }
    }

    string_scanner::string_scanner(windows_emulator& emu, size_t minimum_length)
        : emu_(emu),
          minimum_length_(minimum_length)
    {
        if (minimum_length_ < 2 || minimum_length_ > maximum_string_length)
        {
            throw std::invalid_argument("Invalid TTD minimum string length");
        }
        auto& cpu = emu_.emu();
        write_hook_ = scoped_hook(cpu, cpu.hook_memory_write_metadata(0, UINT64_MAX, [this](cpu_interface&, uint64_t address, size_t size) {
            if (size)
            {
                pending_.emplace_back(address, size);
            }
        }));
        execute_hook_ = scoped_hook(cpu, cpu.hook_memory_execution_metadata([this](cpu_interface&, uint64_t, size_t) { flush_pending(); }));
    }

    void string_scanner::scan_initial_memory()
    {
        for (const auto& [base, reservation] : emu_.memory.get_reserved_regions())
        {
            (void)base;
            if (reservation.kind == memory_region_kind::mmio || reservation.kind == memory_region_kind::host_reserved)
            {
                continue;
            }
            for (const auto& [address, committed] : reservation.committed_regions)
            {
                scan_range(address, committed.length, 0);
            }
        }
    }

    void string_scanner::scan_range(uint64_t address, uint64_t size, uint64_t step)
    {
        for (uint64_t offset = 0; offset < size; offset += scan_chunk)
        {
            const auto begin = offset > context_bytes ? offset - context_bytes : 0;
            const auto end = std::min<uint64_t>(size, offset + scan_chunk + context_bytes);
            std::vector<uint8_t> bytes(static_cast<size_t>(end - begin));
            if (emu_.emu().try_read_memory(address + begin, bytes.data(), bytes.size()))
            {
                inspect(address + begin, bytes, step);
            }
            else
            {
                for (uint64_t page = begin; page < end; page += 4096)
                {
                    const auto length = static_cast<size_t>(std::min<uint64_t>(4096, end - page));
                    bytes.resize(length);
                    if (emu_.emu().try_read_memory(address + page, bytes.data(), bytes.size()))
                    {
                        inspect(address + page, bytes, step);
                    }
                }
            }
        }
    }

    void string_scanner::inspect(uint64_t address, const std::vector<uint8_t>& bytes, uint64_t step)
    {
        for (size_t i = 0; i < bytes.size();)
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
            if (end - i >= minimum_length_ && end - i <= maximum_string_length && end < bytes.size() && !bytes[end])
            {
                add(address + i, step, "ascii",
                    std::string(bytes.begin() + static_cast<ptrdiff_t>(i), bytes.begin() + static_cast<ptrdiff_t>(end)));
            }
            i = end;
        }
        for (size_t i = 0; i + 1 < bytes.size(); ++i)
        {
            if (!printable(bytes[i]) || bytes[i + 1] || (i >= 2 && printable(bytes[i - 2]) && !bytes[i - 1]))
            {
                continue;
            }
            size_t end = i;
            std::string value{};
            while (end + 1 < bytes.size() && printable(bytes[end]) && !bytes[end + 1] && value.size() < maximum_string_length)
            {
                value.push_back(static_cast<char>(bytes[end]));
                end += 2;
            }
            if (value.size() >= minimum_length_ && end + 1 < bytes.size() && !bytes[end] && !bytes[end + 1])
            {
                add(address + i, step, "utf16le", std::move(value));
            }
        }
    }

    void string_scanner::add(uint64_t address, uint64_t step, std::string encoding, std::string value)
    {
        auto& entries = strings_[address];
        for (auto& entry : entries)
        {
            if (entry.encoding != encoding)
            {
                continue;
            }
            if (entry.value == value)
            {
                return;
            }
            if (value.starts_with(entry.value))
            {
                entry.value = std::move(value);
                entry.step = step;
                return;
            }
        }
        entries.push_back({address, step, std::move(encoding), std::move(value)});
    }

    void string_scanner::flush_pending()
    {
        if (pending_.empty())
        {
            return;
        }
        const auto step = emu_.get_executed_instructions();
        auto pending = std::move(pending_);
        pending_.clear();
        for (const auto& [address, size] : pending)
        {
            const auto begin = address > context_bytes ? address - context_bytes : 0;
            const auto end = address + std::min<uint64_t>(size, UINT64_MAX - address);
            if (end <= begin)
            {
                continue;
            }
            scan_range(begin, end - begin + std::min<uint64_t>(context_bytes, UINT64_MAX - end), step);
        }
    }

    void string_scanner::finish()
    {
        write_hook_.remove();
        execute_hook_.remove();
        flush_pending();
    }

    void string_scanner::save(const std::filesystem::path& path) const
    {
        std::ofstream file(path, std::ios::binary);
        if (!file)
        {
            throw std::runtime_error("Cannot write TTD strings: " + path.string());
        }
        file << "address\tstep\tencoding\tvalue\n";
        for (const auto& [address, entries] : strings_)
        {
            for (const auto& entry : entries)
            {
                file << std::hex << address << '\t' << entry.step << '\t' << entry.encoding << '\t' << entry.value << '\n';
            }
        }
        if (!file)
        {
            throw std::runtime_error("Writing TTD strings failed");
        }
    }

    size_t string_scanner::count() const
    {
        size_t total{};
        for (const auto& [address, entries] : strings_)
        {
            (void)address;
            total += entries.size();
        }
        return total;
    }
}
