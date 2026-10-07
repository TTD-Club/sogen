#include "std_include.hpp"

#include "ttd_cli.hpp"
#include "ttd_buffer_scan.hpp"
#include "ttd_string_scan.hpp"
#include "ttd_session.hpp"
#include "ttd_trace.hpp"
#include "snapshot.hpp"

#include <CLI/CLI.hpp>

#include <fstream>
#include <sstream>

namespace sogen::ttd
{
    namespace
    {
        uint64_t query_kinds(const std::string_view access)
        {
            if (access == "read")
            {
                return static_cast<uint64_t>(access_kind::read);
            }
            if (access == "write")
            {
                return static_cast<uint64_t>(access_kind::write) | static_cast<uint64_t>(access_kind::host_write);
            }
            if (access == "host-write")
            {
                return static_cast<uint64_t>(access_kind::host_write);
            }
            if (access == "execute")
            {
                return static_cast<uint64_t>(access_kind::execute);
            }
            return all_access_kinds;
        }

        std::string to_hex(const std::span<const std::byte> bytes, const size_t limit = SIZE_MAX)
        {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string text{};
            for (const auto byte : bytes.first(std::min(bytes.size(), limit)))
            {
                text += digits[static_cast<uint8_t>(byte) >> 4];
                text += digits[static_cast<uint8_t>(byte) & 0xf];
            }
            if (bytes.size() > limit)
            {
                text += "...";
            }
            return text;
        }

        uint64_t recorded_kinds(const cli_options& options)
        {
            const auto writes = static_cast<uint64_t>(access_kind::write) | static_cast<uint64_t>(access_kind::host_write);
            return (options.no_read_trace ? 0 : static_cast<uint64_t>(access_kind::read)) | (options.no_write_trace ? 0 : writes) |
                   (options.no_execute_trace ? 0 : static_cast<uint64_t>(access_kind::execute));
        }

        void print_hit(const self_modifying_hit& hit)
        {
            printf("address=%llx size=%llu write=%llx:0 write_ip=%llx execute=%llx:0 execute_ip=%llx",
                   static_cast<unsigned long long>(hit.address), static_cast<unsigned long long>(hit.size),
                   static_cast<unsigned long long>(hit.write_step), static_cast<unsigned long long>(hit.write_ip),
                   static_cast<unsigned long long>(hit.execute_step), static_cast<unsigned long long>(hit.execute_ip));
        }

        int run_first_selfmod(const cli_options& options)
        {
            trace recorded(options.first_selfmod);
            const auto filter_address = options.address.has_value() || options.size.has_value();
            const auto address = options.address.value_or(0);
            const auto size = options.size.value_or(1);
            std::optional<self_modifying_hit> first{};
            for (const auto& hit : recorded.self_modifying_code())
            {
                if (filter_address && (hit.address < address || hit.address - address >= size))
                {
                    continue;
                }
                if (!first || hit.execute_step < first->execute_step)
                {
                    first = hit;
                }
            }
            if (!first)
            {
                return 2;
            }
            print_hit(*first);
            printf("\n");
            return 0;
        }

        int run_selfmod(const cli_options& options)
        {
            trace recorded(options.selfmod);
            for (const auto& hit : recorded.self_modifying_code())
            {
                print_hit(hit);
                printf(" count=%llu\n", static_cast<unsigned long long>(hit.executions));
            }
            return 0;
        }

        int run_query(const cli_options& options)
        {
            if (options.next_access && options.previous_access)
            {
                throw std::runtime_error("Choose only one TTD access direction");
            }
            trace recorded(options.query);
            const auto kinds = query_kinds(options.access);
            const auto address = options.address.value_or(0);
            const auto size = options.size.value_or(1);
            std::vector<access_event> events{};
            if (options.next_access)
            {
                if (const auto event = recorded.next_access(address, size, options.from, kinds))
                {
                    events.push_back(*event);
                }
            }
            else if (options.previous_access)
            {
                if (const auto event = recorded.previous_access(address, size, options.from, kinds))
                {
                    events.push_back(*event);
                }
            }
            else
            {
                events = recorded.accesses(address, size, options.from, options.to, kinds);
            }
            for (const auto& event : events)
            {
                const auto print_kind = options.access != "write" || event.kind != access_kind::write;
                printf("%llx:0 ip=%llx address=%llx size=%llu%s%s", static_cast<unsigned long long>(event.step),
                       static_cast<unsigned long long>(event.ip), static_cast<unsigned long long>(event.address),
                       static_cast<unsigned long long>(event.size), print_kind ? " kind=" : "",
                       print_kind ? access_kind_name(event.kind) : "");
                if (recorded.has_instruction_bytes() && event.kind == access_kind::execute && event.size < inline_data_limit)
                {
                    printf(" bytes=%s", to_hex(std::as_bytes(std::span(event.payload)).first(static_cast<size_t>(event.size))).c_str());
                }
                if (recorded.has_access_data() && event.kind != access_kind::execute)
                {
                    printf(" data=%s", to_hex(recorded.access_data(event), 32).c_str());
                }
                printf("\n");
            }
            return 0;
        }

        int run_history(const cli_options& options)
        {
            constexpr uint64_t maximum_size = 256;
            trace recorded(options.history);
            if (!recorded.has_access_data())
            {
                throw std::runtime_error("TTD memory history needs a trace that records access data (format v5)");
            }
            const auto address = options.address.value_or(0);
            const auto size = options.size.value_or(8);
            if (!size || size > maximum_size)
            {
                throw std::runtime_error("TTD memory history size must be 1-256 bytes");
            }
            const auto kinds = static_cast<uint64_t>(access_kind::read) | static_cast<uint64_t>(access_kind::write) |
                               static_cast<uint64_t>(access_kind::host_write);
            std::vector<std::optional<std::byte>> value(static_cast<size_t>(size));
            for (const auto& event : recorded.accesses(address, size, 0, options.to, kinds))
            {
                const auto data = recorded.access_data(event);
                for (size_t i = 0; i < data.size(); ++i)
                {
                    const auto byte_address = event.address + i;
                    if (byte_address >= address && byte_address - address < size)
                    {
                        value[static_cast<size_t>(byte_address - address)] = data[i];
                    }
                }
                if (event.step < options.from)
                {
                    continue;
                }
                std::string current{};
                for (const auto& byte : value)
                {
                    current += byte ? to_hex(std::span(&*byte, 1)) : "??";
                }
                printf("%llx:0 ip=%llx kind=%s address=%llx size=%llu data=%s value=%s\n", static_cast<unsigned long long>(event.step),
                       static_cast<unsigned long long>(event.ip), access_kind_name(event.kind),
                       static_cast<unsigned long long>(event.address), static_cast<unsigned long long>(event.size),
                       to_hex(data, 32).c_str(), current.c_str());
            }
            return 0;
        }

        void write_file(const std::filesystem::path& path, const std::span<const uint8_t> data, const char* description)
        {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file)
            {
                throw std::runtime_error(std::string("Cannot open TTD ") + description);
            }
            file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
            if (!file)
            {
                throw std::runtime_error(std::string("Writing TTD ") + description + " failed");
            }
        }

        void require_start_at_zero(const trace& recorded)
        {
            if (recorded.start_position())
            {
                throw std::runtime_error("TTD replay scans need a trace that starts at position zero, not a forked one");
            }
        }

        // These scans replay from a fresh setup without event verification, which recorded window input needs.
        void require_no_ui_input(const trace& recorded)
        {
            if (!recorded.ui_inputs().empty())
            {
                throw std::runtime_error("This TTD replay scan cannot replay recorded window input; use sogen.ttd's Replay.buffers() or "
                                         "Replay.self_modifying_waves()");
            }
        }

        std::optional<std::string> run_to(windows_emulator& win_emu, const uint64_t position, const char* failure)
        {
            const auto before = win_emu.get_executed_instructions();
            if (position > before)
            {
                win_emu.start(static_cast<size_t>(position - before));
            }
            if (win_emu.get_executed_instructions() != position)
            {
                return failure;
            }
            return std::nullopt;
        }

        replay_result scan_strings(windows_emulator& win_emu, const cli_options& options)
        {
            trace recorded(options.replay);
            require_start_at_zero(recorded);
            replay_verifier verifier(win_emu, recorded, win_emu.get_executed_instructions());
            const ui_replay ui(win_emu, recorded.ui_inputs(), 0, [&verifier] { return verifier.next_event_number(); });
            string_scanner scanner(win_emu, options.min_string_length);
            scanner.scan_initial_memory();
            // One start() per checkpoint interval, as the recording ran: recorded window input arrives at those pumps.
            auto reached = true;
            for (const auto& checkpoint : recorded.checkpoints())
            {
                reached = !run_to(win_emu, checkpoint.step, "");
                if (!reached)
                {
                    break;
                }
            }
            if (reached)
            {
                run_to(win_emu, recorded.metadata().instruction_count, "");
            }
            verifier.finish();
            scanner.finish();
            scanner.save(options.strings);
            win_emu.log.log("TTD recovered %zu strings to %s\n", scanner.count(), options.strings.string().c_str());
            return {.exit_status = win_emu.process.exit_status};
        }

        replay_result scan_buffers(windows_emulator& win_emu, const cli_options& options)
        {
            trace recorded(options.replay);
            require_start_at_zero(recorded);
            require_no_ui_input(recorded);
            win_emu.setup_process_if_necessary();
            buffer_scanner scanner(win_emu, recorded);
            for (const auto& checkpoint : recorded.checkpoints())
            {
                if (auto failure = run_to(win_emu, checkpoint.step, "TTD buffer replay stopped before recorded checkpoint"))
                {
                    return {.failure = std::move(failure)};
                }
            }
            if (auto failure =
                    run_to(win_emu, recorded.metadata().instruction_count, "TTD buffer replay stopped before recorded instruction count"))
            {
                return {.failure = std::move(failure)};
            }
            scanner.finish();
            scanner.save(options.buffers);
            printf("TTD buffer scan verified %llu writes; recovered %zu candidates to %s; skipped %llu unreadable bytes\n",
                   static_cast<unsigned long long>(scanner.verified_writes()), scanner.count(), options.buffers.string().c_str(),
                   static_cast<unsigned long long>(scanner.skipped_bytes()));
            return {};
        }

        replay_result scan_selfmod(windows_emulator& win_emu, const cli_options& options)
        {
            trace recorded(options.replay);
            require_start_at_zero(recorded);
            require_no_ui_input(recorded);
            win_emu.setup_process_if_necessary();
            uint64_t capture_address = 0;
            size_t capture_size = 0;
            if (!options.dump_image.empty())
            {
                const auto& image = *win_emu.mod_manager.executable;
                capture_address = options.dump_address.value_or(image.image_base);
                const auto requested_size = options.dump_size.value_or(image.size_of_image);
                if (!requested_size || requested_size > 64ull * 1024 * 1024 || capture_address > UINT64_MAX - requested_size)
                {
                    throw std::runtime_error("TTD first-hit dump size is invalid or exceeds 64 MiB");
                }
                capture_size = static_cast<size_t>(requested_size);
            }
            replay_selfmod_scanner scanner(win_emu, recorded, capture_address, capture_size, options.dump_wave);
            for (const auto& checkpoint : recorded.checkpoints())
            {
                if (auto failure = run_to(win_emu, checkpoint.step, "TTD replay stopped before recorded checkpoint"))
                {
                    scanner.finish();
                    return {.failure = std::move(failure)};
                }
            }
            const auto failure =
                run_to(win_emu, recorded.metadata().instruction_count, "TTD replay stopped before recorded instruction count");
            scanner.finish();
            if (failure)
            {
                return {.failure = failure};
            }
            if (!scanner.captured_memory().empty() && capture_size)
            {
                write_file(options.dump_image, scanner.captured_memory(), "first-hit dump");
                printf("TTD wave %zu dump %s base=%llx size=%llx missing_pages=%llu\n", options.dump_wave,
                       options.dump_image.string().c_str(), static_cast<unsigned long long>(capture_address),
                       static_cast<unsigned long long>(capture_size), static_cast<unsigned long long>(scanner.missing_capture_pages()));
            }
            for (size_t index = 0; index < scanner.hits().size(); ++index)
            {
                print_hit(scanner.hits()[index]);
                printf(" wave=%zu\n", index + 1);
            }
            if (scanner.hits().size() == 256)
            {
                printf("TTD self-modifying-code report reached its 256-wave limit\n");
            }
            printf("TTD replay verified %llu writes across %llu instructions\n", static_cast<unsigned long long>(scanner.verified_writes()),
                   static_cast<unsigned long long>(win_emu.get_executed_instructions()));
            return {};
        }

        replay_result verify_checkpoints(windows_emulator& win_emu, const cli_options& options)
        {
            trace recorded(options.replay);
            size_t mismatches = 0;
            for (const auto& target : recorded.checkpoints())
            {
                const auto origin = recorded.checkpoint_for_step(target.step - 1);
                snapshot::load_emulator_state(win_emu, origin.state);
                replay_verifier verifier(win_emu, recorded, origin.step);
                const ui_replay ui(win_emu, recorded.ui_inputs(), recorded.checkpoint_index(origin.step),
                                   [&verifier] { return verifier.next_event_number(); });
                win_emu.start(static_cast<size_t>(target.step - origin.step));
                try
                {
                    verifier.finish();
                }
                catch (const std::runtime_error& e)
                {
                    ++mismatches;
                    printf("TTD checkpoint %llx:0 not reached: %s\n", static_cast<unsigned long long>(target.step), e.what());
                    continue;
                }
                if (win_emu.get_executed_instructions() != target.step)
                {
                    std::ostringstream message;
                    message << "TTD replay from checkpoint " << std::hex << origin.step << " reached position "
                            << win_emu.get_executed_instructions() << " instead of " << target.step;
                    return {.failure = message.str()};
                }
                const auto observed = snapshot::create_emulator_state(win_emu);
                const auto expected = recorded.checkpoint_for_step(target.step).state;
                const auto [observed_end, expected_end] = std::ranges::mismatch(observed, expected);
                if (observed_end == observed.end() && expected_end == expected.end())
                {
                    printf("TTD checkpoint %llx:0 matches (%llu events verified)\n", static_cast<unsigned long long>(target.step),
                           static_cast<unsigned long long>(verifier.verified_events()));
                    continue;
                }
                ++mismatches;
                printf("TTD checkpoint %llx:0 differs at state offset %llx (replayed %zu bytes, recorded %zu bytes)\n",
                       static_cast<unsigned long long>(target.step), static_cast<unsigned long long>(observed_end - observed.begin()),
                       observed.size(), expected.size());
            }
            if (mismatches)
            {
                return {.failure = std::to_string(mismatches) + " TTD checkpoints differ from their replay"};
            }
            return {};
        }

        void dump_image(windows_emulator& win_emu, const cli_options& options)
        {
            const auto& image = *win_emu.mod_manager.executable;
            const auto dump_address = options.dump_address.value_or(image.image_base);
            const auto dump_size = options.dump_size.value_or(image.size_of_image);
            if (!dump_size || dump_size > 512ull * 1024 * 1024 || dump_address > UINT64_MAX - dump_size)
            {
                throw std::runtime_error("TTD image dump size is invalid or exceeds 512 MiB");
            }
            std::ofstream dump(options.dump_image, std::ios::binary | std::ios::trunc);
            if (!dump)
            {
                throw std::runtime_error("Cannot open TTD image dump");
            }
            std::array<char, 4096> page{};
            uint64_t missing_pages = 0;
            for (uint64_t offset = 0; offset < dump_size; offset += page.size())
            {
                page.fill(0);
                const auto length = static_cast<size_t>(std::min<uint64_t>(page.size(), dump_size - offset));
                if (!win_emu.emu().try_read_memory(dump_address + offset, page.data(), length))
                {
                    ++missing_pages;
                }
                dump.write(page.data(), static_cast<std::streamsize>(length));
            }
            if (!dump)
            {
                throw std::runtime_error("Writing TTD image dump failed");
            }
            win_emu.log.log("TTD image dump %s base=%llx size=%llx missing_pages=%llu\n", options.dump_image.string().c_str(),
                            static_cast<unsigned long long>(dump_address), static_cast<unsigned long long>(dump_size),
                            static_cast<unsigned long long>(missing_pages));
        }

        replay_result seek(windows_emulator& win_emu, const cli_options& options)
        {
            trace recorded(options.replay);
            seek_result result{};
            try
            {
                result = ttd::seek(win_emu, recorded, options.seek);
            }
            catch (const std::runtime_error& e)
            {
                return {.failure = e.what()};
            }
            win_emu.log.log("TTD replay verified %llu recorded events\n", static_cast<unsigned long long>(result.verified_events));
            win_emu.log.log("TTD checkpoint %llx:0\n", static_cast<unsigned long long>(result.checkpoint));
            win_emu.log.log("TTD position %llx:0 RIP %llx\n", static_cast<unsigned long long>(options.seek),
                            static_cast<unsigned long long>(win_emu.emu().read_instruction_pointer()));
            if (options.read)
            {
                const auto value = win_emu.emu().read_memory<uint64_t>(*options.read);
                win_emu.log.log("TTD memory %llx = %llx\n", static_cast<unsigned long long>(*options.read),
                                static_cast<unsigned long long>(value));
            }
            if (!options.dump_image.empty())
            {
                dump_image(win_emu, options);
            }
            return {};
        }
    }

    void add_options(CLI::App& app, cli_options& options)
    {
        app.add_option("--ttd-record", options.record, "Record a checkpointed TTD trace");
        app.add_option("--ttd-replay", options.replay, "Restore a TTD trace snapshot");
        app.add_flag("--ttd-scan-selfmod", options.scan_selfmod, "Replay a TTD trace to find written-then-executed code waves");
        app.add_flag("--ttd-verify-checkpoints", options.verify_checkpoints,
                     "Replay each TTD checkpoint interval and compare the reached state with the next checkpoint");
        app.add_option("--ttd-seek", options.seek, "Replay through this instruction position");
        app.add_option("--ttd-checkpoint-interval", options.checkpoint_interval, "Instructions between recording checkpoints")
            ->capture_default_str();
        app.add_option("--ttd-max-instructions", options.max_instructions, "Stop recording after this many instructions");
        app.add_option("--ttd-dump-image", options.dump_image, "Dump mapped executable image at replay position");
        app.add_option("--ttd-dump-address", options.dump_address, "Guest base address for a replay memory dump");
        app.add_option("--ttd-dump-size", options.dump_size, "Guest byte length for a replay memory dump");
        app.add_option("--ttd-dump-wave", options.dump_wave, "Code-write wave to capture during a replay scan")->capture_default_str();
        app.add_flag("--ttd-no-checkpoints", options.no_checkpoints, "Record only the initial snapshot (baseline comparison)");
        app.add_flag("--ttd-no-read-trace", options.no_read_trace, "Disable memory-read event recording");
        app.add_flag("--ttd-no-write-trace", options.no_write_trace, "Disable memory-write event recording");
        app.add_flag("--ttd-no-execute-trace", options.no_execute_trace, "Disable instruction-execute event recording");
        app.add_option("--ttd-read", options.read, "Read eight guest bytes at the replay position");
        app.add_option("--ttd-strings", options.strings, "Recover strings during deterministic replay into a TSV file");
        app.add_option("--ttd-buffers", options.buffers, "Recover written buffers during deterministic replay into a TSV file");
        app.add_option("--ttd-min-string-length", options.min_string_length, "Minimum recovered string length")->capture_default_str();

        app.add_option("--ttd-query", options.query, "Query memory accesses in a TTD trace");
        app.add_option("--ttd-history", options.history,
                       "List every read and write of --ttd-address/--ttd-size in a TTD trace with the range's value after each");
        app.add_option("--ttd-selfmod", options.selfmod, "Find executed bytes written earlier in a TTD trace");
        app.add_option("--ttd-first-selfmod", options.first_selfmod,
                       "Find first written-then-executed instruction anywhere, or in an optional address range");
        app.add_option("--ttd-access", options.access, "Access type: read, write (guest and host), host-write, execute, or all")
            ->check(CLI::IsMember({"read", "write", "host-write", "execute", "all"}));
        app.add_option("--ttd-address", options.address, "First address for TTD access query or self-modifying-code filter");
        app.add_option("--ttd-size", options.size, "Byte length for TTD access query or self-modifying-code filter");
        app.add_option("--ttd-from", options.from, "First instruction position for TTD access query");
        app.add_option("--ttd-to", options.to, "Last instruction position for TTD access query");
        app.add_flag("--ttd-next-access,--ttd-next-write", options.next_access, "Find the next matching access after --ttd-from");
        app.add_flag("--ttd-prev-access,--ttd-prev-write", options.previous_access, "Find the previous matching access before --ttd-from");
    }

    void validate(const cli_options& options, const analyzer_configuration& configuration)
    {
        const auto active = options.records() || options.replays();
        if (active && configuration.vcpu_count != 1)
        {
            throw std::runtime_error("TTD POC requires --vcpus 1");
        }
        if (options.records() && options.replays())
        {
            throw std::runtime_error("TTD record and replay cannot be combined");
        }
        if (active && (configuration.gdb || configuration.snapshot_input))
        {
            throw std::runtime_error("TTD POC requires a fresh application run without GDB or snapshot input");
        }
        if (!options.replays() &&
            (options.seek || options.read || !options.dump_image.empty() || options.dump_address || options.dump_size))
        {
            throw std::runtime_error("TTD seek and memory inspection require --ttd-replay");
        }
        if (options.scan_selfmod && (!options.replays() || options.seek))
        {
            throw std::runtime_error("TTD self-modifying-code replay scan requires --ttd-replay from position zero");
        }
        if (options.verify_checkpoints && (!options.replays() || options.seek || options.scan_selfmod || !options.buffers.empty() ||
                                           !options.strings.empty() || options.read || !options.dump_image.empty()))
        {
            throw std::runtime_error("TTD checkpoint verification requires --ttd-replay and no other TTD replay mode");
        }
        if (!options.dump_wave || options.dump_wave > 256 ||
            (options.dump_wave != 1 && (!options.scan_selfmod || options.dump_image.empty())))
        {
            throw std::runtime_error("TTD dump wave must be 1-256 and requires a replay scan with a dump path");
        }
        if (options.dump_address.has_value() != options.dump_size.has_value() || (options.dump_address && options.dump_image.empty()))
        {
            throw std::runtime_error("TTD dump range requires --ttd-dump-image, --ttd-dump-address, and --ttd-dump-size");
        }
        if (!options.records() && options.max_instructions)
        {
            throw std::runtime_error("TTD instruction limit requires --ttd-record");
        }
        if (!options.strings.empty() && (!options.replays() || options.seek))
        {
            throw std::runtime_error("TTD string recovery requires --ttd-replay from position zero");
        }
        if (!options.buffers.empty() && (!options.replays() || options.seek || options.scan_selfmod || !options.strings.empty()))
        {
            throw std::runtime_error("TTD buffer recovery requires a dedicated --ttd-replay from position zero");
        }
        if (options.records() && !options.no_checkpoints && !options.checkpoint_interval)
        {
            throw std::runtime_error("TTD checkpoint interval must be positive");
        }
        if ((options.no_read_trace || options.no_write_trace || options.no_execute_trace) && !options.records())
        {
            throw std::runtime_error("TTD trace toggles require --ttd-record");
        }
        if (active && !configuration.instruction_precision)
        {
            throw std::runtime_error("TTD POC requires instruction precision");
        }
        if (active && !configuration.backend_name.empty() && configuration.backend_name != "unicorn")
        {
            throw std::runtime_error("TTD POC supports only the Unicorn backend");
        }
    }

    std::optional<int> run_offline(const cli_options& options)
    {
        if (!options.first_selfmod.empty())
        {
            return run_first_selfmod(options);
        }
        if (!options.selfmod.empty())
        {
            return run_selfmod(options);
        }
        if (!options.query.empty())
        {
            return run_query(options);
        }
        if (!options.history.empty())
        {
            return run_history(options);
        }
        return std::nullopt;
    }

    void prepare_replay(windows_emulator& win_emu, const cli_options& options)
    {
        // A plain seek restores its checkpoint itself; fresh-setup scans start from the application.
        if (!options.replays() || options.scan_selfmod || !options.buffers.empty() || options.is_plain_seek())
        {
            return;
        }
        trace recorded(options.replay);
        snapshot::load_emulator_state(win_emu, recorded.checkpoint_for_step(options.seek).state);
    }

    replay_result replay(windows_emulator& win_emu, const cli_options& options)
    {
        if (!options.strings.empty())
        {
            return scan_strings(win_emu, options);
        }
        if (!options.buffers.empty())
        {
            return scan_buffers(win_emu, options);
        }
        if (options.scan_selfmod)
        {
            return scan_selfmod(win_emu, options);
        }
        if (options.verify_checkpoints)
        {
            return verify_checkpoints(win_emu, options);
        }
        return seek(win_emu, options);
    }

    void record(windows_emulator& win_emu, const cli_options& options, const std::function<bool()>& interrupted)
    {
        ttd::record(win_emu,
                    {
                        .path = options.record,
                        .access_mask = recorded_kinds(options),
                        .checkpoint_interval = options.no_checkpoints ? 0 : options.checkpoint_interval,
                        .max_instructions = options.max_instructions,
                        .manifest = {{"tool", "analyzer"}},
                    },
                    interrupted);
        win_emu.log.log("TTD recorded %llu instructions\n", static_cast<unsigned long long>(win_emu.get_executed_instructions()));
    }
}
