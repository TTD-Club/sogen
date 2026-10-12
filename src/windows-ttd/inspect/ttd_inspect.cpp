// ttd-inspect: reads a Sogen TTD trace with the reader alone (no emulator, no CPU backend).
//
//   ttd-inspect TRACE                                summary
//   ttd-inspect TRACE exceptions                     exceptions dispatched to user mode
//   ttd-inspect TRACE calls-to ADDRESS|module!name   entries into a function, with call sites and returns
//   ttd-inspect TRACE branches ADDRESS SIZE [jumps]  indirect call (and jump) targets in a range

#include <ttd_trace.hpp>

#include <cstdio>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using sogen::ttd::is_trace_file;
    using sogen::ttd::trace;

    uint64_t parse_number(const std::string& text)
    {
        return std::stoull(text, nullptr, 0);
    }

    uint64_t resolve(trace& recorded, const std::string& text)
    {
        if (text.find('!') == std::string::npos)
        {
            return parse_number(text);
        }
        for (const auto& found : recorded.find_exports(text))
        {
            if (found.symbol->forwarder.empty())
            {
                return found.module->base + found.symbol->rva;
            }
        }
        throw std::runtime_error("No export " + text);
    }

    std::string position_text(const uint64_t position)
    {
        return position == UINT64_MAX ? "-" : std::to_string(position);
    }

    void summary(trace& recorded)
    {
        const auto& metadata = recorded.metadata();
        std::printf("id            %s\n", recorded.id().c_str());
        std::printf("version       %u\n", recorded.version());
        std::printf("positions     %llu-%llu\n", static_cast<unsigned long long>(recorded.start_position()),
                    static_cast<unsigned long long>(metadata.instruction_count));
        std::printf("events        %llu\n", static_cast<unsigned long long>(metadata.event_count));
        std::printf("access mask   0x%llx\n", static_cast<unsigned long long>(recorded.access_mask()));
        std::printf("checkpoints   %zu\n", recorded.checkpoints().size() + 1);
        std::printf("modules       %zu\n", recorded.modules().size());
        std::printf("threads       %zu\n", recorded.threads().names.size());
        std::printf("syscalls      %zu\n", recorded.syscalls().size());
        std::printf("snapshots     %zu\n", recorded.register_snapshots().size());
    }

    void calls_to(trace& recorded, const uint64_t address)
    {
        std::printf("%-12s %-12s %-12s %-18s %-8s %s\n", "call", "entry", "return", "site", "thread", "kind");
        for (const auto& call : recorded.calls_to(address))
        {
            std::printf("%-12s %-12llu %-12s 0x%016llx %-8u %s\n", position_text(call.step).c_str(),
                        static_cast<unsigned long long>(call.entry_step), position_text(call.return_step).c_str(),
                        static_cast<unsigned long long>(call.site), call.thread_id, call.is_call ? "call" : "other");
        }
    }

    void exceptions(trace& recorded)
    {
        std::printf("%-12s %-12s %-8s %-10s %s\n", "position", "raised", "thread", "code", "address");
        for (const auto& exception : recorded.exceptions())
        {
            std::printf("%-12llu %-12s %-8u 0x%08x 0x%016llx\n", static_cast<unsigned long long>(exception.step),
                        position_text(exception.raise_step).c_str(), exception.thread_id, exception.code,
                        static_cast<unsigned long long>(exception.address));
        }
    }

    void branches(trace& recorded, const uint64_t address, const uint64_t size, const bool jumps)
    {
        const std::vector<std::pair<uint64_t, uint64_t>> ranges{{address, size}};
        std::printf("%-18s %-18s %-10s %-12s %s\n", "site", "target", "hits", "first", "kind");
        for (const auto& branch : recorded.indirect_branches(ranges, jumps))
        {
            std::printf("0x%016llx 0x%016llx %-10llu %-12llu %s\n", static_cast<unsigned long long>(branch.site),
                        static_cast<unsigned long long>(branch.target), static_cast<unsigned long long>(branch.hits),
                        static_cast<unsigned long long>(branch.first_step), branch.is_call ? "call" : "jump");
        }
    }
}

int main(const int argc, char** argv)
{
    try
    {
        const std::vector<std::string> args(argv + 1, argv + argc);
        if (args.empty())
        {
            std::fprintf(stderr, "Usage: ttd-inspect TRACE [exceptions | calls-to ADDRESS | branches ADDRESS SIZE [jumps]]\n");
            return 1;
        }
        if (!is_trace_file(args[0]))
        {
            std::fprintf(stderr, "%s is not a Sogen TTD trace\n", args[0].c_str());
            return 1;
        }
        trace recorded(args[0]);
        if (args.size() == 1)
        {
            summary(recorded);
        }
        else if (args[1] == "exceptions" && args.size() == 2)
        {
            exceptions(recorded);
        }
        else if (args[1] == "calls-to" && args.size() == 3)
        {
            calls_to(recorded, resolve(recorded, args[2]));
        }
        else if (args[1] == "branches" && (args.size() == 4 || args.size() == 5))
        {
            branches(recorded, resolve(recorded, args[2]), parse_number(args[3]), args.size() == 5 && args[4] == "jumps");
        }
        else
        {
            std::fprintf(stderr, "Unknown command\n");
            return 1;
        }
        return 0;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "ttd-inspect: %s\n", e.what());
        return 1;
    }
}
