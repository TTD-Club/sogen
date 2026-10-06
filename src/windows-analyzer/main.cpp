#include "std_include.hpp"

#include <CLI/CLI.hpp>

#include <windows_emulator.hpp>
#include <backend_selection.hpp>
#include <win_x86_64_gdb_stub_handler.hpp>
#include <minidump_loader.hpp>
#include <scoped_hook.hpp>
#include <registry/registry_file.hpp>

#include "object_watching.hpp"
#include "snapshot.hpp"
#include "analysis.hpp"
#include "analysis_reporter.hpp"
#include "jsonl_reporter.hpp"
#include "stdout_file_reporter.hpp"
#include "tenet_tracer.hpp"
#include "ttd_trace.hpp"
#include "ttd_string_scan.hpp"
#include "ttd_buffer_scan.hpp"

#include <utils/finally.hpp>
#include <utils/interupt_handler.hpp>

#if defined(OS_EMSCRIPTEN) && !defined(SOGEN_EMSCRIPTEN_SUPPORT_NODEJS)
#include <event_handler.hpp>
#endif

#ifndef _WIN32
#include <csignal>
#endif
#include <fstream>

namespace sogen
{
    namespace
    {
        std::filesystem::path get_current_binary_dir()
        {
#ifdef _WIN32
            std::array<wchar_t, MAX_PATH> buffer{};

            const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (length == 0 || length == buffer.size())
            {
                throw std::runtime_error("Resolving module file name failed");
            }

            return std::filesystem::path(buffer.data()).parent_path();
#else
            return "./";
#endif
        }

        struct analysis_options : analysis_settings
        {
            mutable bool use_gdb{false};
            std::string gdb_host{"127.0.0.1"};
            uint16_t gdb_port{28960};
            std::string gdb_architecture{"64bits"};
            bool log_executable_access{false};
            bool log_foreign_module_access{false};
            bool tenet_trace{false};
            std::filesystem::path ttd_record{};
            std::filesystem::path ttd_replay{};
            bool ttd_scan_selfmod{false};
            uint64_t ttd_seek{};
            uint64_t ttd_checkpoint_interval{500000};
            uint64_t ttd_max_instructions{};
            std::filesystem::path ttd_dump_image{};
            std::optional<uint64_t> ttd_dump_address{};
            std::optional<uint64_t> ttd_dump_size{};
            size_t ttd_dump_wave{1};
            bool ttd_no_checkpoints{false};
            bool ttd_no_read_trace{false};
            bool ttd_no_write_trace{false};
            bool ttd_no_execute_trace{false};
            std::optional<uint64_t> ttd_read{};
            std::filesystem::path ttd_strings{};
            std::filesystem::path ttd_buffers{};
            size_t ttd_min_string_length{6};
            bool prepend_call_count{false};
#if defined(OS_EMSCRIPTEN) && !defined(SOGEN_EMSCRIPTEN_SUPPORT_NODEJS)
            bool pause_before_start{false};
#endif
            std::optional<uint64_t> break_call{};
            std::filesystem::path dump{};
            std::filesystem::path minidump_path{};
            std::filesystem::path report_path{};
            std::filesystem::path stdout_path{};
            std::string report_format{"jsonl"};
            std::string whp_execution_hook_mode{"auto"};
            std::optional<backend_type> backend{};
            bool disable_instruction_precision{false};
            uint32_t vcpu_count{1};
            std::filesystem::path registry_path{get_current_binary_dir() / "registry"};
            std::vector<std::filesystem::path> registry_files{};
            std::filesystem::path emulation_root{};
            std::unordered_map<windows_path, std::filesystem::path> path_mappings{};
            utils::unordered_insensitive_u16string_map<std::u16string> environment{};
        };

        void split_and_insert(std::set<std::string, std::less<>>& container, const std::string_view str, const char splitter = ',')
        {
            size_t current_start = 0;
            for (size_t i = 0; i < str.size(); ++i)
            {
                const auto value = str[i];
                if (value != splitter)
                {
                    continue;
                }

                if (current_start < i)
                {
                    container.emplace(str.substr(current_start, i - current_start));
                }

                current_start = i + 1;
            }

            if (current_start < str.size())
            {
                container.emplace(str.substr(current_start));
            }
        }

        gdb_target_architecture parse_gdb_target_architecture(const std::string_view value)
        {
            if (value == "auto")
            {
                return gdb_target_architecture::automatic;
            }

            if (value == "32bits")
            {
                return gdb_target_architecture::bits_32;
            }

            if (value == "64bits")
            {
                return gdb_target_architecture::bits_64;
            }

            throw std::invalid_argument("Invalid GDB target architecture");
        }

        struct analysis_state
        {
            analysis_context& context_;
            windows_emulator& win_emu_;
            scoped_hook env_data_hook_;
            scoped_hook env_ptr_hook_;
            scoped_hook params_hook_;
            scoped_hook ldr_hook_;
            std::map<std::string, uint64_t> env_module_cache_{};
            std::shared_ptr<object_watching_state> params_state_ = std::make_shared<object_watching_state>();
            std::shared_ptr<object_watching_state> ldr_state_ = std::make_shared<object_watching_state>();
            std::set<std::string, std::less<>> modules_;
            bool verbose_;
            bool concise_;

            analysis_state(analysis_context& context, std::set<std::string, std::less<>> modules, const bool verbose, const bool concise)
                : context_(context),
                  win_emu_(*context.win_emu),
                  env_data_hook_(context.win_emu->emu()),
                  env_ptr_hook_(context.win_emu->emu()),
                  params_hook_(context.win_emu->emu()),
                  ldr_hook_(context.win_emu->emu()),
                  modules_(std::move(modules)),
                  verbose_(verbose),
                  concise_(concise)
            {
            }
        };

        emulator_object<RTL_USER_PROCESS_PARAMETERS64> get_process_params(windows_emulator& win_emu)
        {
            const auto peb = win_emu.process.peb64.read();
            return {win_emu.emu(), peb.ProcessParameters};
        }

        uint64_t get_environment_ptr(windows_emulator& win_emu)
        {
            const auto process_params = get_process_params(win_emu);
            return process_params.read().Environment;
        }

        size_t get_environment_size(const x86_64_emulator& emu, const uint64_t env)
        {
            std::array<uint8_t, 4> data{};
            std::array<uint8_t, 4> empty{};

            for (size_t i = 0; i < 0x100000; ++i)
            {
                if (!emu.try_read_memory(env + i, data.data(), data.size()))
                {
                    return i;
                }

                if (data == empty)
                {
                    return i + data.size();
                }
            }

            return 0;
        }

        emulator_hook* install_env_hook(const std::shared_ptr<analysis_state>& state)
        {
            const auto process_params = get_process_params(state->win_emu_);

            auto install_env_access_hook = [state] {
                const auto env_ptr = get_environment_ptr(state->win_emu_);
                const auto env_size = get_environment_size(state->win_emu_.emu(), env_ptr);
                if (!env_size)
                {
                    state->env_data_hook_.remove();
                    return;
                }

                auto hook_handler = [state, env_ptr](cpu_interface& cpu, const uint64_t address, const void*, const size_t size) {
                    state->win_emu_.dispatch_on_cpu(cpu, [&] {
                        const auto rip = state->win_emu_.active_cpu().read_instruction_pointer();
                        const auto* mod = state->win_emu_.mod_manager.find_by_address(rip);
                        const auto is_main_access =
                            !mod || (mod == state->win_emu_.mod_manager.executable || state->modules_.contains(mod->name));

                        if (!is_main_access && !state->verbose_)
                        {
                            return;
                        }

                        if (state->concise_)
                        {
                            const auto count = ++state->env_module_cache_[mod ? mod->name : "<N/A>"];
                            if (count > 30 && count % 1000 != 0)
                            {
                                return;
                            }
                        }

                        state->context_.emit_observation<environment_access_event>([&](auto& event) {
                            event.main_access = is_main_access;
                            event.offset = address - env_ptr;
                            event.size = size;
                        });
                    });
                };

                state->env_data_hook_ = state->win_emu_.emu().hook_memory_read(env_ptr, env_size, std::move(hook_handler));
            };

            install_env_access_hook();

            auto& win_emu = state->win_emu_;
            return state->win_emu_.emu().hook_memory_write(
                process_params.value() + offsetof(RTL_USER_PROCESS_PARAMETERS64, Environment), 0x8,
                [&win_emu, install = std::move(install_env_access_hook)](cpu_interface&, const uint64_t address, const void*, size_t) {
                    const auto new_process_params = get_process_params(win_emu);

                    const auto target_address = new_process_params.value() + offsetof(RTL_USER_PROCESS_PARAMETERS64, Environment);

                    if (address == target_address)
                    {
                        install();
                    }
                });
        }

        void watch_system_objects(analysis_context& c, const std::set<std::string, std::less<>>& modules, const bool verbose,
                                  const bool concise)
        {
            auto& win_emu = *c.win_emu;
            win_emu.setup_process_if_necessary();

            auto emit_object_access = [&c](object_access_info info) {
                c.emit_observation<object_access_event>([&](auto& event) {
                    event.main_access = info.main_access;
                    event.type_name = std::move(info.type_name);
                    event.offset = info.offset;
                    event.size = info.size;
                    event.member_name = std::move(info.member_name);
                });
            };

            watch_object(win_emu, modules, *win_emu.current_thread().teb64, verbose, emit_object_access);
            watch_object(win_emu, modules, win_emu.process.peb64, verbose, emit_object_access);
            watch_object<KUSER_SHARED_DATA64>(win_emu, modules, kusd_mmio::address(), verbose, emit_object_access);

            auto state = std::make_shared<analysis_state>(c, modules, verbose, concise);

            state->params_hook_ =
                watch_object(win_emu, modules, win_emu.process.process_params64, verbose, emit_object_access, state->params_state_);
            state->ldr_hook_ = watch_object<PEB_LDR_DATA64>(win_emu, modules, win_emu.process.peb64.read().Ldr, verbose, emit_object_access,
                                                            state->ldr_state_);

            const auto update_env_hook = [state] {
                state->env_ptr_hook_ = install_env_hook(state); //
            };

            update_env_hook();

            win_emu.emu().hook_memory_write(
                win_emu.process.peb64.value() + offsetof(PEB64, ProcessParameters), 0x8,
                [state, emit_object_access, update_env = std::move(update_env_hook)](cpu_interface&, const uint64_t, const void*, size_t) {
                    const auto new_ptr = state->win_emu_.process.peb64.read().ProcessParameters;
                    state->params_hook_ = watch_object<RTL_USER_PROCESS_PARAMETERS64>(
                        state->win_emu_, state->modules_, new_ptr, state->verbose_, emit_object_access, state->params_state_);
                    update_env();
                });

            win_emu.emu().hook_memory_write(win_emu.process.peb64.value() + offsetof(PEB64, Ldr), 0x8,
                                            [state, emit_object_access](cpu_interface&, const uint64_t, const void*, size_t) {
                                                const auto new_ptr = state->win_emu_.process.peb64.read().Ldr;
                                                state->ldr_hook_ =
                                                    watch_object<PEB_LDR_DATA64>(state->win_emu_, state->modules_, new_ptr, state->verbose_,
                                                                                 emit_object_access, state->ldr_state_);
                                            });
        }

        bool read_yes_no_answer()
        {
            while (true)
            {
                const auto chr = static_cast<char>(getchar());
                if (chr == 'y')
                {
                    return true;
                }

                if (chr == 'n')
                {
                    return false;
                }
            }
        }

        std::vector<instruction_summary_entry> build_instruction_summary(const analysis_context& c)
        {
            std::map<uint64_t, std::vector<uint32_t>> instruction_counts{};

            for (const auto& [instruction, count] : c.instructions)
            {
                instruction_counts[count].push_back(instruction);
            }

            std::vector<instruction_summary_entry> entries{};
            for (const auto& [count, instructions] : instruction_counts)
            {
                for (const auto& instruction : instructions)
                {
                    const auto& e = c.win_emu;
                    auto& emu = e->emu();
                    const auto reg_cs = emu.reg<uint16_t>(x86_register::cs);
                    const auto handle = c.d.resolve_handle(emu, reg_cs);
                    const auto* mnemonic = cs_insn_name(handle, instruction);
                    entries.emplace_back(instruction_summary_entry{.mnemonic = mnemonic ? mnemonic : "<N/A>", .count = count});
                }
            }

            return entries;
        }

        void do_post_emulation_work(const analysis_context& c)
        {
            if (c.settings->instruction_summary)
            {
                c.emit_summary<instruction_summary_event>([&](auto& event) { event.entries = build_instruction_summary(c); });
            }

            if (c.settings->buffer_stdout)
            {
                c.emit_summary<buffered_stdout_event>([&](auto& event) { event.data = c.output; });
            }
        }

        void flush_reporters(const analysis_context& c)
        {
            for (auto* reporter : c.reporters)
            {
                reporter->flush();
            }
        }

        bool run_emulation(const analysis_context& c, const analysis_options& options)
        {
            auto& win_emu = *c.win_emu;

            std::atomic_uint32_t signals_received{0};
            utils::interupt_handler _{[&] {
                const auto value = signals_received++;
                if (value == 1)
                {
                    win_emu.log.log("Exit already requested. Press CTRL+C again to force kill!\n");
                }
                else if (value >= 2)
                {
                    _Exit(1);
                }

                win_emu.stop();
            }};

            std::optional<NTSTATUS> exit_status{};
#if defined(OS_EMSCRIPTEN) && !defined(SOGEN_EMSCRIPTEN_SUPPORT_NODEJS)
            const auto _1 = utils::finally([&] {
                debugger::handle_exit(win_emu, exit_status); //
            });
#endif

            auto emit_failure = [&](std::string message) {
                do_post_emulation_work(c);
                c.emit_summary<run_failed_event>([&](auto& event) {
                    event.rip = win_emu.emu().read_instruction_pointer();
                    event.message = std::move(message);
                });
                flush_reporters(c);
                return false;
            };

            std::optional<ttd::recorder> ttd_recorder{};
            try
            {
                if (options.use_gdb)
                {
                    const auto address = network::address{options.gdb_host, options.gdb_port};
                    win_emu.log.force_print(color::pink, "Waiting for GDB connection on %s...\n", address.to_string().c_str());

                    const auto should_stop = [&] { return signals_received > 0; };

                    win_x86_64_gdb_stub_handler handler{win_emu, should_stop, parse_gdb_target_architecture(options.gdb_architecture)};
                    gdb_stub::run_gdb_stub(address, handler);
                }
                else if (!options.minidump_path.empty())
                {
                    // For minidumps, don't start execution automatically; just report ready state
                    win_emu.log.print(color::green, "Minidump loaded successfully. Process state ready for analysis.\n");
                    c.emit_summary<run_finished_event>([&](auto& event) {
                        event.success = true;
                        event.exit_status = std::nullopt;
                    });
                    flush_reporters(c);
                    return true;
                }
                else
                {
#if defined(OS_EMSCRIPTEN) && !defined(SOGEN_EMSCRIPTEN_SUPPORT_NODEJS)
                    if (options.pause_before_start)
                    {
                        debugger::enter_breakpoint(win_emu, win_emu.mod_manager.executable->entry_point);
                    }
#endif
                    if (!options.ttd_record.empty())
                    {
                        const auto writes =
                            static_cast<uint64_t>(ttd::access_kind::write) | static_cast<uint64_t>(ttd::access_kind::host_write);
                        const auto access_mask = (options.ttd_no_read_trace ? 0 : static_cast<uint64_t>(ttd::access_kind::read)) |
                                                 (options.ttd_no_write_trace ? 0 : writes) |
                                                 (options.ttd_no_execute_trace ? 0 : static_cast<uint64_t>(ttd::access_kind::execute));
                        ttd_recorder.emplace(win_emu, options.ttd_record, access_mask);
                    }
                    if (!options.ttd_strings.empty())
                    {
                        ttd::string_scanner scanner(win_emu, options.ttd_min_string_length);
                        scanner.scan_initial_memory();
                        win_emu.start();
                        scanner.finish();
                        scanner.save(options.ttd_strings);
                        win_emu.log.log("TTD recovered %zu strings to %s\n", scanner.count(), options.ttd_strings.string().c_str());
                        do_post_emulation_work(c);
                        c.emit_summary<run_finished_event>([&](auto& event) {
                            event.success = true;
                            event.exit_status = win_emu.process.exit_status;
                        });
                        flush_reporters(c);
                        return true;
                    }
                    if (!options.ttd_replay.empty())
                    {
                        if (!options.ttd_buffers.empty())
                        {
                            ttd::trace buffer_trace(options.ttd_replay, false);
                            win_emu.setup_process_if_necessary();
                            ttd::buffer_scanner scanner(win_emu, buffer_trace);
                            for (const auto& checkpoint : buffer_trace.checkpoints())
                            {
                                const auto before = win_emu.get_executed_instructions();
                                win_emu.start(static_cast<size_t>(checkpoint.step - before));
                                if (win_emu.get_executed_instructions() != checkpoint.step)
                                {
                                    return emit_failure("TTD buffer replay stopped before recorded checkpoint");
                                }
                            }
                            const auto before = win_emu.get_executed_instructions();
                            win_emu.start(static_cast<size_t>(buffer_trace.metadata().instruction_count - before));
                            if (win_emu.get_executed_instructions() != buffer_trace.metadata().instruction_count)
                            {
                                return emit_failure("TTD buffer replay stopped before recorded instruction count");
                            }
                            scanner.finish();
                            scanner.save(options.ttd_buffers);
                            printf("TTD buffer scan verified %llu writes; recovered %zu candidates to %s; skipped %llu unreadable bytes\n",
                                   static_cast<unsigned long long>(scanner.verified_writes()), scanner.count(),
                                   options.ttd_buffers.string().c_str(), static_cast<unsigned long long>(scanner.skipped_bytes()));
                            do_post_emulation_work(c);
                            c.emit_summary<run_finished_event>([&](auto& event) {
                                event.success = true;
                                event.exit_status = std::nullopt;
                            });
                            flush_reporters(c);
                            return true;
                        }
                        if (options.ttd_scan_selfmod)
                        {
                            ttd::trace replay_trace(options.ttd_replay, false);
                            win_emu.setup_process_if_necessary();
                            uint64_t capture_address = 0;
                            size_t capture_size = 0;
                            if (!options.ttd_dump_image.empty())
                            {
                                const auto& image = *win_emu.mod_manager.executable;
                                capture_address = options.ttd_dump_address.value_or(image.image_base);
                                const auto requested_size = options.ttd_dump_size.value_or(image.size_of_image);
                                if (!requested_size || requested_size > 64ull * 1024 * 1024 ||
                                    capture_address > UINT64_MAX - requested_size)
                                {
                                    throw std::runtime_error("TTD first-hit dump size is invalid or exceeds 64 MiB");
                                }
                                capture_size = static_cast<size_t>(requested_size);
                            }
                            ttd::replay_selfmod_scanner scanner(win_emu, replay_trace, capture_address, capture_size,
                                                                options.ttd_dump_wave);
                            for (const auto& checkpoint : replay_trace.checkpoints())
                            {
                                const auto before = win_emu.get_executed_instructions();
                                win_emu.start(static_cast<size_t>(checkpoint.step - before));
                                if (win_emu.get_executed_instructions() != checkpoint.step)
                                {
                                    scanner.finish();
                                    return emit_failure("TTD replay stopped before recorded checkpoint");
                                }
                            }
                            const auto before = win_emu.get_executed_instructions();
                            win_emu.start(static_cast<size_t>(replay_trace.metadata().instruction_count - before));
                            scanner.finish();
                            if (win_emu.get_executed_instructions() != replay_trace.metadata().instruction_count)
                            {
                                return emit_failure("TTD replay stopped before recorded instruction count");
                            }
                            if (!scanner.captured_memory().empty())
                            {
                                if (capture_size)
                                {
                                    std::ofstream dump(options.ttd_dump_image, std::ios::binary | std::ios::trunc);
                                    if (!dump)
                                    {
                                        throw std::runtime_error("Cannot open TTD first-hit dump");
                                    }
                                    const auto& data = scanner.captured_memory();
                                    dump.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
                                    if (!dump)
                                    {
                                        throw std::runtime_error("Writing TTD first-hit dump failed");
                                    }
                                    printf("TTD wave %zu dump %s base=%llx size=%llx missing_pages=%llu\n", options.ttd_dump_wave,
                                           options.ttd_dump_image.string().c_str(), static_cast<unsigned long long>(capture_address),
                                           static_cast<unsigned long long>(capture_size),
                                           static_cast<unsigned long long>(scanner.missing_capture_pages()));
                                }
                            }
                            for (size_t index = 0; index < scanner.hits().size(); ++index)
                            {
                                const auto& hit = scanner.hits()[index];
                                printf("address=%llx size=%llu write=%llx:0 write_ip=%llx execute=%llx:0 execute_ip=%llx wave=%zu\n",
                                       static_cast<unsigned long long>(hit.address), static_cast<unsigned long long>(hit.size),
                                       static_cast<unsigned long long>(hit.write_step), static_cast<unsigned long long>(hit.write_ip),
                                       static_cast<unsigned long long>(hit.execute_step), static_cast<unsigned long long>(hit.execute_ip),
                                       index + 1);
                            }
                            if (scanner.hits().size() == 256)
                            {
                                printf("TTD self-modifying-code report reached its 256-wave limit\n");
                            }
                            printf("TTD replay verified %llu writes across %llu instructions\n",
                                   static_cast<unsigned long long>(scanner.verified_writes()),
                                   static_cast<unsigned long long>(win_emu.get_executed_instructions()));
                            do_post_emulation_work(c);
                            c.emit_summary<run_finished_event>([&](auto& event) {
                                event.success = true;
                                event.exit_status = std::nullopt;
                            });
                            flush_reporters(c);
                            return true;
                        }
                        const auto checkpoint_step = win_emu.get_executed_instructions();
                        ttd::trace seek_trace(options.ttd_replay, false);
                        ttd::replay_verifier verifier(win_emu, seek_trace, checkpoint_step);
                        if (options.ttd_seek > checkpoint_step)
                        {
                            win_emu.start(static_cast<size_t>(options.ttd_seek - checkpoint_step));
                        }
                        verifier.finish();
                        win_emu.log.log("TTD replay verified %llu recorded events\n",
                                        static_cast<unsigned long long>(verifier.verified_events()));
                        if (const auto reached = win_emu.get_executed_instructions(); reached != options.ttd_seek)
                        {
                            char message[160]{};
                            snprintf(message, sizeof(message), "TTD replay reached position %llx instead of %llx",
                                     static_cast<unsigned long long>(reached), static_cast<unsigned long long>(options.ttd_seek));
                            return emit_failure(message);
                        }
                        win_emu.log.log("TTD checkpoint %llx:0\n", static_cast<unsigned long long>(checkpoint_step));
                        win_emu.log.log("TTD position %llx:0 RIP %llx\n", static_cast<unsigned long long>(options.ttd_seek),
                                        static_cast<unsigned long long>(win_emu.emu().read_instruction_pointer()));
                        if (options.ttd_read)
                        {
                            const auto value = win_emu.emu().read_memory<uint64_t>(*options.ttd_read);
                            win_emu.log.log("TTD memory %llx = %llx\n", static_cast<unsigned long long>(*options.ttd_read),
                                            static_cast<unsigned long long>(value));
                        }
                        if (!options.ttd_dump_image.empty())
                        {
                            const auto& image = *win_emu.mod_manager.executable;
                            const auto dump_address = options.ttd_dump_address.value_or(image.image_base);
                            const auto dump_size = options.ttd_dump_size.value_or(image.size_of_image);
                            if (!dump_size || dump_size > 512ull * 1024 * 1024 || dump_address > UINT64_MAX - dump_size)
                            {
                                throw std::runtime_error("TTD image dump size is invalid or exceeds 512 MiB");
                            }
                            std::ofstream dump(options.ttd_dump_image, std::ios::binary | std::ios::trunc);
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
                            win_emu.log.log("TTD image dump %s base=%llx size=%llx missing_pages=%llu\n",
                                            options.ttd_dump_image.string().c_str(), static_cast<unsigned long long>(dump_address),
                                            static_cast<unsigned long long>(dump_size), static_cast<unsigned long long>(missing_pages));
                        }
                        do_post_emulation_work(c);
                        c.emit_summary<run_finished_event>([&](auto& event) {
                            event.success = true;
                            event.exit_status = std::nullopt;
                        });
                        flush_reporters(c);
                        return true;
                    }
                    if (ttd_recorder && !options.ttd_no_checkpoints)
                    {
                        while (!win_emu.process.exit_status && !signals_received)
                        {
                            const auto before = win_emu.get_executed_instructions();
                            if (options.ttd_max_instructions && before >= options.ttd_max_instructions)
                            {
                                break;
                            }
                            const auto budget = options.ttd_max_instructions
                                                    ? std::min(options.ttd_checkpoint_interval, options.ttd_max_instructions - before)
                                                    : options.ttd_checkpoint_interval;
                            win_emu.start(static_cast<size_t>(budget));
                            if (win_emu.process.exit_status || signals_received)
                            {
                                break;
                            }
                            if (win_emu.get_executed_instructions() - before < budget)
                            {
                                break;
                            }
                            if (!options.ttd_max_instructions || win_emu.get_executed_instructions() < options.ttd_max_instructions)
                            {
                                ttd_recorder->checkpoint();
                            }
                        }
                    }
                    else
                    {
                        win_emu.start(ttd_recorder && options.ttd_max_instructions ? static_cast<size_t>(options.ttd_max_instructions) : 0);
                    }
                    if (ttd_recorder)
                    {
                        ttd_recorder->finish();
                        win_emu.log.log("TTD recorded %llu instructions\n",
                                        static_cast<unsigned long long>(win_emu.get_executed_instructions()));
                    }
                }

                if (signals_received > 0)
                {
                    options.use_gdb = false;

                    win_emu.log.log("Do you want to create a snapshot? (y/n)\n");
                    const auto write_snapshot = read_yes_no_answer();

                    if (write_snapshot)
                    {
                        snapshot::write_emulator_snapshot(win_emu);
                    }
                }
            }
            catch (const gdb_stub::binding_error& e)
            {
                win_emu.log.error("Cannot bind to address %s\n", e.what());
                options.use_gdb = false;
                return emit_failure("Cannot bind to address "s + e.what());
            }
            catch (const std::exception& e)
            {
                return emit_failure(e.what());
            }
            catch (...)
            {
                return emit_failure("Unknown exception");
            }

            exit_status = win_emu.process.exit_status;
            if (!exit_status.has_value())
            {
                if (!options.ttd_record.empty() && options.ttd_max_instructions &&
                    win_emu.get_executed_instructions() >= options.ttd_max_instructions)
                {
                    do_post_emulation_work(c);
                    c.emit_summary<run_finished_event>([&](auto& event) {
                        event.success = true;
                        event.exit_status = std::nullopt;
                    });
                    flush_reporters(c);
                    return true;
                }
                return emit_failure("Emulation terminated without status");
            }

            const auto success = *exit_status == STATUS_SUCCESS;
            do_post_emulation_work(c);
            win_emu.log.disable_output(false);
            c.emit_summary<run_finished_event>([&](auto& event) {
                event.success = success;
                event.exit_status = static_cast<uint32_t>(*exit_status);
            });
            flush_reporters(c);
            return success;
        }

        std::vector<std::u16string> parse_arguments(const std::span<const std::string_view> args)
        {
            std::vector<std::u16string> wide_args{};
            wide_args.reserve(args.size() - 1);

            for (size_t i = 1; i < args.size(); ++i)
            {
                const auto& arg = args[i];
                wide_args.emplace_back(arg.begin(), arg.end());
            }

            return wide_args;
        }

        emulator_settings create_emulator_settings(const analysis_options& options)
        {
            return {
                .use_relative_time = options.reproducible,
                .use_instruction_precision = !options.disable_instruction_precision,
                .emulation_root = options.emulation_root,
                .registry_directory = options.registry_path,
                .path_mappings = options.path_mappings,
            };
        }

        hook_interface::memory_execution_hook_mode parse_memory_execution_hook_mode(const std::string_view mode)
        {
            if (mode == "auto")
            {
                return hook_interface::memory_execution_hook_mode::automatic;
            }

            if (mode == "int3")
            {
                return hook_interface::memory_execution_hook_mode::int3;
            }

            throw std::runtime_error("WHP memory execution hook mode must be auto or int3");
        }

        std::unique_ptr<x86_64_emulator> create_configured_backend(const analysis_options& options)
        {
            auto emu = options.backend ? create_x86_64_emulator(*options.backend, options.vcpu_count)
                                       : create_x86_64_emulator_from_environment(options.vcpu_count);
            emu->set_memory_execution_hook_mode(parse_memory_execution_hook_mode(options.whp_execution_hook_mode));
            return emu;
        }

        std::unique_ptr<windows_emulator> create_empty_emulator(const analysis_options& options)
        {
            const auto settings = create_emulator_settings(options);
            return std::make_unique<windows_emulator>(create_configured_backend(options), settings);
        }

        std::unique_ptr<windows_emulator> create_application_emulator(const analysis_options& options,
                                                                      const std::span<const std::string_view> args)
        {
            if (args.empty())
            {
                throw std::runtime_error("No args provided");
            }

            application_settings app_settings{
                .application = std::u8string(args[0].begin(), args[0].end()),
                .arguments = parse_arguments(args),
                .environment = options.environment,
            };

            const auto settings = create_emulator_settings(options);
            return std::make_unique<windows_emulator>(create_configured_backend(options), std::move(app_settings), settings);
        }

        void apply_registry_files(windows_emulator& win_emu, const analysis_options& options)
        {
            for (const auto& file : options.registry_files)
            {
                import_registry_file(win_emu.registry, file);
            }
        }

        std::unique_ptr<windows_emulator> setup_emulator(const analysis_options& options, const std::span<const std::string_view> args)
        {
            if (!options.dump.empty())
            {
                // load snapshot
                auto win_emu = create_empty_emulator(options);
                snapshot::load_emulator_snapshot(*win_emu, options.dump);
                return win_emu;
            }
            if (!options.minidump_path.empty())
            {
                // load minidump
                auto win_emu = create_empty_emulator(options);
                minidump_loader::load_minidump_into_emulator(*win_emu, options.minidump_path);
                return win_emu;
            }

            // default: load application
            return create_application_emulator(options, args);
        }

        const char* get_module_memory_region_name(const mapped_module& mod, const uint64_t address)
        {
            if (!mod.contains(address))
            {
                return "outside???";
            }

            uint64_t first_section = mod.image_base + mod.size_of_image;

            for (const auto& section : mod.sections)
            {
                first_section = std::min(first_section, section.region.start);

                if (is_within_start_and_length(address, section.region.start, section.region.length))
                {
                    return section.name.c_str();
                }
            }

            if (address < first_section)
            {
                return "header";
            }

            return "?";
        }

        bool run(const analysis_options& options, const std::span<const std::string_view> args)
        {
            analysis_context context{
                .settings = &options,
                .auto_break_before_call = options.break_call,
            };

            const auto concise_logging = options.concise_logging;
            const auto win_emu = setup_emulator(options, args);
            std::optional<ttd::trace> replay_trace{};
            if (!options.ttd_replay.empty())
            {
                replay_trace.emplace(options.ttd_replay, false);
                if (!options.ttd_scan_selfmod && options.ttd_buffers.empty())
                {
                    const auto checkpoint = replay_trace->checkpoint_for_step(options.ttd_seek);
                    snapshot::load_emulator_snapshot(*win_emu, checkpoint.snapshot);
                }
            }
            apply_registry_files(*win_emu, options);
            context.win_emu = win_emu.get();

            std::vector<std::unique_ptr<analysis_reporter>> reporters{};
            reporters.emplace_back(create_console_reporter(win_emu->log, console_reporter_settings{
                                                                             .silent = options.silent,
                                                                             .buffer_stdout = options.buffer_stdout,
                                                                             .prepend_call_count = options.prepend_call_count,
                                                                         }));

            if (!options.report_path.empty())
            {
                if (options.report_format != "jsonl")
                {
                    throw std::runtime_error("Unsupported report format: " + options.report_format);
                }

                reporters.emplace_back(create_jsonl_reporter(options.report_path));
            }

            if (!options.stdout_path.empty())
            {
                reporters.emplace_back(create_stdout_file_reporter(options.stdout_path));
            }

            context.reporters.reserve(reporters.size());
            for (const auto& reporter : reporters)
            {
                context.reporters.push_back(reporter.get());
            }

            win_emu->log.disable_output(concise_logging);

            std::vector<std::string> application_args{};
            if (!args.empty())
            {
                application_args.reserve(args.size() - 1);
                for (size_t i = 1; i < args.size(); ++i)
                {
                    application_args.emplace_back(args[i]);
                }
            }

            const auto* run_mode = "application";
            if (!options.minidump_path.empty())
            {
                run_mode = "minidump";
            }
            else if (!options.dump.empty())
            {
                run_mode = "snapshot";
            }

            context.emit_summary<run_started_event>([&](auto& event) {
                event.backend_name = win_emu->emu().get_name();
                event.mode = run_mode;
                event.application = args.empty() ? std::string{} : std::string(args[0]);
                event.arguments = std::move(application_args);
            });

            std::optional<tenet_tracer> tenet_tracer{};
            if (options.tenet_trace)
            {
                win_emu->log.log("Tenet Tracer enabled. Output: tenet_trace.log\n");
                tenet_tracer.emplace(*win_emu, "tenet_trace.log");
            }

            register_analysis_callbacks(context);
            watch_system_objects(context, options.modules, options.verbose_logging, options.concise_logging);

            const auto& exe = *win_emu->mod_manager.executable;
            const auto is_whp = win_emu->emu().get_name() == "Windows Hypervisor Platform";

            win_emu->emu().hook_instruction(x86_hookable_instructions::cpuid, [&](cpu_interface& cpu, uint64_t) {
                return win_emu->dispatch_on_cpu(cpu, [&] {
                    auto& emu = win_emu->active_cpu();

                    const auto rip = emu.read_instruction_pointer();
                    const auto leaf = emu.reg<uint32_t>(x86_register::eax);
                    const auto mod = get_module_if_interesting(win_emu->mod_manager, options.modules, rip);

                    if (mod.has_value() && (!concise_logging || context.cpuid_cache.insert({rip, leaf}).second))
                    {
                        context.emit_observation<cpuid_event>([&](auto& event) { event.leaf = leaf; });
                    }

                    if (leaf == 1 && !is_whp)
                    {
                        // NOTE: We hard-code these values to disable SSE4.x and AVX
                        //       See: https://github.com/momo5502/sogen/issues/560
                        emu.reg<uint32_t>(x86_register::eax, 0x000906EA);
                        emu.reg<uint32_t>(x86_register::ebx, 0x00100800);
                        emu.reg<uint32_t>(x86_register::ecx, 0xEFE2F38F);
                        emu.reg<uint32_t>(x86_register::edx, 0xBFEBFBFF);

                        return instruction_hook_continuation::skip_instruction;
                    }

                    if (leaf == 0x40000000 && !is_whp)
                    {
                        // Microsoft Hv vendor string
                        emu.reg<uint32_t>(x86_register::eax, 0x40000003);
                        emu.reg<uint32_t>(x86_register::ebx, 0x7263694d);
                        emu.reg<uint32_t>(x86_register::ecx, 0x666f736f);
                        emu.reg<uint32_t>(x86_register::edx, 0x76482074);

                        return instruction_hook_continuation::skip_instruction;
                    }

                    if (leaf == 0x40000003 && !is_whp)
                    {
                        emu.reg<uint32_t>(x86_register::eax, 0x00000000);
                        emu.reg<uint32_t>(x86_register::ebx, 0x00000001);
                        emu.reg<uint32_t>(x86_register::ecx, 0x00000000);
                        emu.reg<uint32_t>(x86_register::edx, 0x00000000);

                        return instruction_hook_continuation::skip_instruction;
                    }

                    return instruction_hook_continuation::run_instruction;
                });
            });

            if (options.log_foreign_module_access)
            {
                auto module_cache = std::make_shared<std::map<std::string, uint64_t>>();
                win_emu->emu().hook_memory_read(0, std::numeric_limits<uint64_t>::max(),
                                                [&, module_cache](cpu_interface& cpu, const uint64_t address, const void*, size_t size) {
                                                    win_emu->dispatch_on_cpu(cpu, [&] {
                                                        const auto rip = win_emu->active_cpu().read_instruction_pointer();
                                                        const auto accessor =
                                                            get_module_if_interesting(win_emu->mod_manager, options.modules, rip);

                                                        if (!accessor.has_value())
                                                        {
                                                            return;
                                                        }

                                                        const auto* mod = win_emu->mod_manager.find_by_address(address);
                                                        if (!mod || mod == *accessor)
                                                        {
                                                            return;
                                                        }

                                                        if (concise_logging)
                                                        {
                                                            const auto count = ++(*module_cache)[mod->name];
                                                            if (count > 30 && count % 100000 != 0)
                                                            {
                                                                return;
                                                            }
                                                        }

                                                        const auto* region_name = get_module_memory_region_name(*mod, address);
                                                        context.emit_observation<foreign_module_read_event>([&](auto& event) {
                                                            event.address = address;
                                                            event.size = size;
                                                            event.module_name = mod->name;
                                                            event.region_name = region_name;
                                                        });
                                                    });
                                                });
            }

            if (options.log_executable_access)
            {
                for (const auto& section : exe.sections)
                {
                    if ((section.region.permissions & memory_permission::exec) != memory_permission::exec)
                    {
                        continue;
                    }

                    const auto read_count = std::make_shared<uint64_t>(0);
                    const auto write_count = std::make_shared<uint64_t>(0);

                    auto read_handler = [&, section, concise_logging, read_count](cpu_interface&, const uint64_t address, const void*,
                                                                                  size_t size) {
                        const auto rip = win_emu->emu().read_instruction_pointer();
                        const auto accessor = get_module_if_interesting(win_emu->mod_manager, options.modules, rip);

                        if (!accessor.has_value())
                        {
                            return;
                        }

                        if (concise_logging)
                        {
                            const auto count = ++*read_count;
                            if (count > 20 && count % 100000 != 0)
                            {
                                return;
                            }
                        }

                        context.emit_observation<executable_read_event>([&](auto& event) {
                            event.address = address;
                            event.size = size;
                            event.section_name = section.name;
                        });
                    };

                    auto write_handler = [&, section, concise_logging, write_count](cpu_interface&, const uint64_t address,
                                                                                    const void* value, size_t size) {
                        if (concise_logging)
                        {
                            const auto count = ++*write_count;
                            if (count > 30 && count % 100000 != 0)
                            {
                                return;
                            }
                        }

                        uint64_t int_value{};
                        memcpy(&int_value, value, std::min(size, sizeof(int_value)));
                        context.emit_observation<executable_write_event>([&](auto& event) {
                            event.address = address;
                            event.size = size;
                            event.value = int_value;
                            event.section_name = section.name;
                        });
                    };

                    win_emu->emu().hook_memory_read(section.region.start, section.region.length, std::move(read_handler));
                    win_emu->emu().hook_memory_write(section.region.start, section.region.length, std::move(write_handler));
                }
            }

            return run_emulation(context, options);
        }

        int run_main(int argc, char** argv)
        {
#ifndef _WIN32
            signal(SIGPIPE, SIG_IGN);
#endif

            CLI::App app{"Sogen Windows Analyzer"};

            // On Windows this resolves the UTF-8 arguments from the wide command line; elsewhere it is a no-op.
            argv = app.ensure_utf8(argv);

            // Stop parsing at the first positional (the application to analyze) and forward everything after it
            // verbatim to the emulated program.
            app.prefix_command();
            app.footer("Examples:\n"
                       "  analyzer -v -e path/to/root myapp.exe\n"
                       "  analyzer --report run.jsonl test-sample.exe\n"
                       "  analyzer -e path/to/root -p c:/analysis-sample.exe /path/to/sample.exe c:/analysis-sample.exe");

            analysis_options options{};

            auto* const debug_option = app.add_flag("-d,--debug", options.use_gdb, "Enable GDB debugging mode");
            app.add_option("--bind", options.gdb_host, "IP or hostname to bind to in GDB mode")->capture_default_str()->needs(debug_option);
            app.add_option("--port", options.gdb_port, "Port to listen to in GDB mode")->capture_default_str()->needs(debug_option);
            app.add_option("--gdb-arch", options.gdb_architecture, "GDB target architecture: auto, 64bits or 32bits")
                ->capture_default_str()
                ->check(CLI::IsMember({"auto", "64bits", "32bits"}))
                ->needs(debug_option);
            app.add_option("--break-call", options.break_call, "In GDB mode, stop before the specified traced function/syscall call")
                ->needs(debug_option);

            app.add_flag("-s,--silent", options.silent, "Silent mode");
            app.add_flag("-v,--verbose", options.verbose_logging, "Verbose logging");
            app.add_flag("-b,--buffer", options.buffer_stdout, "Buffer stdout");
            app.add_flag("-f,--foreign", options.log_foreign_module_access, "Log read access to foreign modules");
            app.add_flag("-c,--concise", options.concise_logging, "Concise logging");
            app.add_flag_callback(
                "--very-concise",
                [&] {
                    options.concise_logging = true;
                    options.skip_syscalls = true;
                    options.skip_generic_activity = true;
                },
                "Very concise logging");
            app.add_flag("-x,--exec", options.log_executable_access, "Log r/w access to executable memory");
            app.add_flag("-t,--tenet-trace", options.tenet_trace, "Enable Tenet tracer");
            app.add_option("--ttd-record", options.ttd_record, "Record a checkpointed TTD trace");
            app.add_option("--ttd-replay", options.ttd_replay, "Restore a TTD trace snapshot");
            app.add_flag("--ttd-scan-selfmod", options.ttd_scan_selfmod,
                         "Replay write-only TTD trace to find written-then-executed code waves");
            app.add_option("--ttd-seek", options.ttd_seek, "Replay through this instruction position");
            app.add_option("--ttd-checkpoint-interval", options.ttd_checkpoint_interval, "Instructions between recording checkpoints")
                ->capture_default_str();
            app.add_option("--ttd-max-instructions", options.ttd_max_instructions, "Stop recording after this many instructions");
            app.add_option("--ttd-dump-image", options.ttd_dump_image, "Dump mapped executable image at replay position");
            app.add_option("--ttd-dump-address", options.ttd_dump_address, "Guest base address for a replay memory dump");
            app.add_option("--ttd-dump-size", options.ttd_dump_size, "Guest byte length for a replay memory dump");
            app.add_option("--ttd-dump-wave", options.ttd_dump_wave, "Code-write wave to capture during a replay scan")
                ->capture_default_str();
            app.add_flag("--ttd-no-checkpoints", options.ttd_no_checkpoints, "Record only the initial snapshot (baseline comparison)");
            app.add_flag("--ttd-no-read-trace", options.ttd_no_read_trace, "Disable memory-read event recording");
            app.add_flag("--ttd-no-write-trace", options.ttd_no_write_trace, "Disable memory-write event recording");
            app.add_flag("--ttd-no-execute-trace", options.ttd_no_execute_trace, "Disable instruction-execute event recording");
            app.add_option("--ttd-read", options.ttd_read, "Read eight guest bytes at the replay position");
            app.add_option("--ttd-strings", options.ttd_strings, "Recover strings during deterministic replay into a TSV file");
            app.add_option("--ttd-buffers", options.ttd_buffers, "Recover written buffers during deterministic replay into a TSV file");
            app.add_option("--ttd-min-string-length", options.ttd_min_string_length, "Minimum recovered string length")
                ->capture_default_str();
            std::filesystem::path ttd_query{};
            std::filesystem::path ttd_selfmod{};
            std::filesystem::path ttd_first_selfmod{};
            uint64_t ttd_address{}, ttd_size{1}, ttd_from{}, ttd_to{UINT64_MAX};
            bool ttd_next_write{}, ttd_prev_write{};
            std::string ttd_access{"write"};
            app.add_option("--ttd-query", ttd_query, "Query memory accesses in a TTD trace");
            app.add_option("--ttd-selfmod", ttd_selfmod, "Find executed bytes written earlier in a TTD trace");
            app.add_option("--ttd-first-selfmod", ttd_first_selfmod,
                           "Find first written-then-executed instruction anywhere, or in an optional address range");
            app.add_option("--ttd-access", ttd_access, "Access type: read, write (guest and host), host-write, execute, or all")
                ->check(CLI::IsMember({"read", "write", "host-write", "execute", "all"}));
            auto* ttd_address_option =
                app.add_option("--ttd-address", ttd_address, "First address for TTD write query or self-modifying-code filter");
            auto* ttd_size_option = app.add_option("--ttd-size", ttd_size, "Byte length for TTD write query or self-modifying-code filter");
            app.add_option("--ttd-from", ttd_from, "First instruction position for TTD write query");
            app.add_option("--ttd-to", ttd_to, "Last instruction position for TTD write query");
            app.add_flag("--ttd-next-access,--ttd-next-write", ttd_next_write, "Find the next matching access after --ttd-from");
            app.add_flag("--ttd-prev-access,--ttd-prev-write", ttd_prev_write, "Find the previous matching access before --ttd-from");
            app.add_flag("--first-exec", options.log_first_section_execution, "Print first executions of sections");
            app.add_flag("--inst-summary", options.instruction_summary, "Print a summary of executed instructions of the analyzed modules");
            app.add_flag("--skip-syscalls", options.skip_syscalls, "Skip the logging of regular syscalls");
            app.add_flag("--reproducible", options.reproducible, "Stub clocks and other mechanisms to make executions reproducible");
            app.add_flag("--no-inst-precision", options.disable_instruction_precision,
                         "Disable per-instruction precision (faster, less precise)");
            app.add_flag("--call-count", options.prepend_call_count, "Prefix function and syscall lines with a traced-call count");
#if defined(OS_EMSCRIPTEN) && !defined(SOGEN_EMSCRIPTEN_SUPPORT_NODEJS)
            app.add_flag("--break-start", options.pause_before_start, "Pause before executing the first instruction");
#endif

            app.add_option("-e,--emulation", options.emulation_root, "Set emulation root path");
            app.add_option("-a,--snapshot", options.dump, "Load snapshot dump from path");
            app.add_option("--minidump", options.minidump_path, "Load minidump from path");
            app.add_option("--report", options.report_path, "Write machine-readable analysis events to a file");
            app.add_option("--report-format", options.report_format, "Report format (supported: jsonl)")->capture_default_str();
            app.add_option("--stdout", options.stdout_path, "Write guest console output to a file");
            app.add_option("--whp-exec-hook", options.whp_execution_hook_mode, "WHP memory execution hook mode")
                ->capture_default_str()
                ->check(CLI::IsMember({"auto", "int3"}));
            app.add_option("-r,--registry", options.registry_path, "Set registry path");
            app.add_option("--reg-file", options.registry_files, "Import registry values from a .reg file")
                ->type_name("FILE")
                ->expected(1)
                ->allow_extra_args(false);

            app.add_option("--vcpus", options.vcpu_count, "Number of virtual CPUs (requires a backend with multi-vCPU support)")
                ->capture_default_str();

            std::string backend_name{};
            app.add_option("--backend", backend_name, "Select CPU backend: unicorn, icicle, whp, kvm or fex (overrides env)")
                ->check(CLI::IsMember({"unicorn", "icicle", "whp", "kvm", "fex"}));

            std::vector<std::string> tracked_modules{};
            app.add_option("-m,--module", tracked_modules, "Specify module(s) to track")->allow_extra_args(false);

            std::vector<std::string> ignored_functions{};
            app.add_option("-i,--ignore", ignored_functions, "Comma-separated list of functions to ignore")->allow_extra_args(false);

            std::vector<std::pair<std::string, std::string>> path_mappings{};
            app.add_option("-p,--path", path_mappings, "Map a Windows path to a host path")->type_name("SRC DST")->allow_extra_args(false);

            std::vector<std::pair<std::string, std::string>> environment{};
            app.add_option("--env", environment, "Set an environment variable")->type_name("NAME VALUE")->allow_extra_args(false);

            CLI11_PARSE(app, argc, argv);

            if (argc <= 1)
            {
                puts(app.help().c_str());
                return 1;
            }

            try
            {
                if (!ttd_first_selfmod.empty())
                {
                    ttd::trace trace(ttd_first_selfmod);
                    std::optional<ttd::self_modifying_hit> first{};
                    const bool filter_address = ttd_address_option->count() || ttd_size_option->count();
                    for (const auto& hit : trace.self_modifying_code())
                    {
                        if (filter_address && (hit.address < ttd_address || hit.address - ttd_address >= ttd_size))
                        {
                            continue;
                        }
                        if (!first || hit.execute_step < first->execute_step)
                        {
                            first = hit;
                        }
                    }
                    if (first)
                    {
                        printf("address=%llx size=%llu write=%llx:0 write_ip=%llx execute=%llx:0 execute_ip=%llx\n",
                               static_cast<unsigned long long>(first->address), static_cast<unsigned long long>(first->size),
                               static_cast<unsigned long long>(first->write_step), static_cast<unsigned long long>(first->write_ip),
                               static_cast<unsigned long long>(first->execute_step), static_cast<unsigned long long>(first->execute_ip));
                    }
                    return first ? 0 : 2;
                }
                if (!ttd_selfmod.empty())
                {
                    ttd::trace trace(ttd_selfmod);
                    for (const auto& hit : trace.self_modifying_code())
                    {
                        printf("address=%llx size=%llu write=%llx:0 write_ip=%llx execute=%llx:0 execute_ip=%llx count=%llu\n",
                               static_cast<unsigned long long>(hit.address), static_cast<unsigned long long>(hit.size),
                               static_cast<unsigned long long>(hit.write_step), static_cast<unsigned long long>(hit.write_ip),
                               static_cast<unsigned long long>(hit.execute_step), static_cast<unsigned long long>(hit.execute_ip),
                               static_cast<unsigned long long>(hit.executions));
                    }
                    return 0;
                }
                if (!ttd_query.empty())
                {
                    ttd::trace trace(ttd_query);
                    const auto kind_mask = ttd_access == "read"         ? static_cast<uint64_t>(ttd::access_kind::read)
                                           : ttd_access == "write"      ? static_cast<uint64_t>(ttd::access_kind::write) |
                                                                              static_cast<uint64_t>(ttd::access_kind::host_write)
                                           : ttd_access == "host-write" ? static_cast<uint64_t>(ttd::access_kind::host_write)
                                           : ttd_access == "execute"    ? static_cast<uint64_t>(ttd::access_kind::execute)
                                                                        : ttd::all_access_kinds;
                    if (ttd_next_write && ttd_prev_write)
                    {
                        throw std::runtime_error("Choose only one TTD access direction");
                    }
                    std::vector<ttd::access_event> writes{};
                    if (ttd_next_write)
                    {
                        if (auto event = trace.next_access(ttd_address, ttd_size, ttd_from, kind_mask))
                        {
                            writes.push_back(*event);
                        }
                    }
                    else if (ttd_prev_write)
                    {
                        if (auto event = trace.previous_access(ttd_address, ttd_size, ttd_from, kind_mask))
                        {
                            writes.push_back(*event);
                        }
                    }
                    else
                    {
                        writes = trace.accesses(ttd_address, ttd_size, ttd_from, ttd_to, kind_mask);
                    }
                    for (const auto& write : writes)
                    {
                        const auto print_kind = ttd_access != "write" || write.kind != ttd::access_kind::write;
                        printf("%llx:0 ip=%llx address=%llx size=%llu%s%s", static_cast<unsigned long long>(write.step),
                               static_cast<unsigned long long>(write.ip), static_cast<unsigned long long>(write.address),
                               static_cast<unsigned long long>(write.size), print_kind ? " kind=" : "",
                               print_kind ? ttd::access_kind_name(write.kind) : "");
                        if (trace.has_instruction_bytes() && write.kind == ttd::access_kind::execute && write.size <= 15)
                        {
                            printf(" bytes=");
                            for (size_t i = 0; i < write.size; ++i)
                            {
                                printf("%02x", write.instruction_bytes[i]);
                            }
                        }
                        printf("\n");
                    }
                    return 0;
                }
                if ((!options.ttd_record.empty() || !options.ttd_replay.empty()) && options.vcpu_count != 1)
                {
                    throw std::runtime_error("TTD POC requires --vcpus 1");
                }
                if (!options.ttd_record.empty() && !options.ttd_replay.empty())
                {
                    throw std::runtime_error("TTD record and replay cannot be combined");
                }
                if ((!options.ttd_record.empty() || !options.ttd_replay.empty()) &&
                    (options.use_gdb || !options.dump.empty() || !options.minidump_path.empty()))
                {
                    throw std::runtime_error("TTD POC requires a fresh application run without GDB or snapshot input");
                }
                if (options.ttd_replay.empty() && (options.ttd_seek || options.ttd_read || !options.ttd_dump_image.empty() ||
                                                   options.ttd_dump_address || options.ttd_dump_size))
                {
                    throw std::runtime_error("TTD seek and memory inspection require --ttd-replay");
                }
                if (options.ttd_scan_selfmod && (options.ttd_replay.empty() || options.ttd_seek))
                {
                    throw std::runtime_error("TTD self-modifying-code replay scan requires --ttd-replay from position zero");
                }
                if (!options.ttd_dump_wave || options.ttd_dump_wave > 256 ||
                    (options.ttd_dump_wave != 1 && (!options.ttd_scan_selfmod || options.ttd_dump_image.empty())))
                {
                    throw std::runtime_error("TTD dump wave must be 1-256 and requires a replay scan with a dump path");
                }
                if (options.ttd_dump_address.has_value() != options.ttd_dump_size.has_value() ||
                    (options.ttd_dump_address && options.ttd_dump_image.empty()))
                {
                    throw std::runtime_error("TTD dump range requires --ttd-dump-image, --ttd-dump-address, and --ttd-dump-size");
                }
                if (options.ttd_record.empty() && options.ttd_max_instructions)
                {
                    throw std::runtime_error("TTD instruction limit requires --ttd-record");
                }
                if (!options.ttd_strings.empty() && (options.ttd_replay.empty() || options.ttd_seek))
                {
                    throw std::runtime_error("TTD string recovery requires --ttd-replay from position zero");
                }
                if (!options.ttd_buffers.empty() &&
                    (options.ttd_replay.empty() || options.ttd_seek || options.ttd_scan_selfmod || !options.ttd_strings.empty()))
                {
                    throw std::runtime_error("TTD buffer recovery requires a dedicated --ttd-replay from position zero");
                }
                if (!options.ttd_record.empty() && !options.ttd_no_checkpoints && !options.ttd_checkpoint_interval)
                {
                    throw std::runtime_error("TTD checkpoint interval must be positive");
                }
                if ((options.ttd_no_read_trace || options.ttd_no_write_trace || options.ttd_no_execute_trace) && options.ttd_record.empty())
                {
                    throw std::runtime_error("TTD trace toggles require --ttd-record");
                }
                if ((!options.ttd_record.empty() || !options.ttd_replay.empty()) && options.disable_instruction_precision)
                {
                    throw std::runtime_error("TTD POC requires instruction precision");
                }
                if ((!options.ttd_record.empty() || !options.ttd_replay.empty()) && !backend_name.empty() && backend_name != "unicorn")
                {
                    throw std::runtime_error("TTD POC supports only the Unicorn backend");
                }
                if (!options.ttd_record.empty() || !options.ttd_replay.empty())
                {
                    options.backend = backend_type::unicorn;
                    options.reproducible = true;
                }
                if (options.use_gdb && options.vcpu_count > 1)
                {
                    throw std::runtime_error("GDB debugging requires --vcpus 1");
                }

                if (!backend_name.empty())
                {
                    static const std::map<std::string, backend_type> backends{
                        {"unicorn", backend_type::unicorn}, {"icicle", backend_type::icicle}, {"whp", backend_type::whp},
                        {"kvm", backend_type::kvm},         {"fex", backend_type::fex},
                    };
                    options.backend = backends.at(backend_name);
                }

                for (auto& module_name : tracked_modules)
                {
                    options.modules.insert(std::move(module_name));
                }

                for (const auto& functions : ignored_functions)
                {
                    split_and_insert(options.ignored_functions, functions);
                }

                for (const auto& [source, target] : path_mappings)
                {
                    options.path_mappings[windows_path(source)] = std::filesystem::absolute(target);
                }

                for (const auto& [name, value] : environment)
                {
                    options.environment[std::u16string(name.begin(), name.end())] = std::u16string(value.begin(), value.end());
                }

                const auto application = app.remaining();
                const std::vector<std::string_view> args{application.begin(), application.end()};

                bool result{};

                do
                {
                    result = run(options, args);
                } while (options.use_gdb);

                return result ? 0 : 1;
            }
            catch (std::exception& e)
            {
                puts(e.what());
            }
            catch (...)
            {
                puts("An unknown exception occured");
            }

            return 1;
        }
    }

    int windows_main(const int argc, char** argv)
    {
        return run_main(argc, argv);
    }
}
