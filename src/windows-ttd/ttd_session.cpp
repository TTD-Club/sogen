#include "ttd_session.hpp"
#include "snapshot.hpp"
#include "ttd_build_info.hpp"

#include <address_utils.hpp>
#include <utils/finally.hpp>

#include <algorithm>
#include <exception>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#define XXH_INLINE_ALL
#include <common/xxhash.h>

namespace sogen::ttd
{
    namespace
    {
        std::string path_text(const std::filesystem::path& path)
        {
            const auto text = path.u8string();
            return {text.begin(), text.end()};
        }

        // XXH64 over each file's name, size, and full contents (about 0.1 s for the hives; replays compute it only
        // when asked or when they diverge). It detects changed files, not deliberate collisions.
        class file_fingerprint
        {
          public:
            file_fingerprint()
            {
                XXH64_reset(&this->state_, 0);
            }

            void add_file(const std::string_view name, const std::filesystem::path& file)
            {
                this->add(name.data(), name.size());
                std::error_code error{};
                const auto size = std::filesystem::file_size(file, error);
                std::ifstream stream(file, std::ios::binary);
                if (error || !stream)
                {
                    constexpr std::string_view missing = "missing";
                    this->add(missing.data(), missing.size());
                    return;
                }
                this->add(&size, sizeof(size));
                std::vector<char> buffer(read_size);
                while (stream)
                {
                    stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                    this->add(buffer.data(), static_cast<size_t>(stream.gcount()));
                }
                if (!stream.eof())
                {
                    constexpr std::string_view unreadable = "unreadable";
                    this->add(unreadable.data(), unreadable.size());
                }
            }

            std::string text() const
            {
                std::ostringstream text;
                text << std::hex << std::setw(16) << std::setfill('0') << XXH64_digest(&this->state_);
                return text.str();
            }

          private:
            static constexpr size_t read_size = 1024 * 1024;
            XXH64_state_t state_{};

            // Not inlined: GCC 13 then reports out-of-bounds accesses inside XXH64_update for small objects passed here.
#if defined(__GNUC__) && !defined(__clang__)
            __attribute__((noinline))
#endif
            void add(const void* data, const size_t size)
            {
                XXH64_update(&this->state_, data, size);
            }
        };

        std::string registry_fingerprint(const windows_emulator& win_emu)
        {
            const auto& directory = win_emu.registry.get_hive_path();
            if (directory.empty())
            {
                return {};
            }
            file_fingerprint fingerprint{};
            for (const auto* hive : {"SYSTEM", "SECURITY", "SAM", "SOFTWARE", "HARDWARE", "NTUSER.DAT"})
            {
                fingerprint.add_file(hive, directory / hive);
            }
            return fingerprint.text();
        }

        // The DLLs every process loads, from the emulation root or, in host mode, the host.
        std::string system_dll_fingerprint(const windows_emulator& win_emu)
        {
            const auto& system_root = win_emu.version.get_system_root();
            if (system_root.is_relative())
            {
                return {};
            }
            file_fingerprint fingerprint{};
            for (const auto* dll : {"ntdll.dll", "kernel32.dll", "kernelbase.dll"})
            {
                fingerprint.add_file(dll, win_emu.file_sys.translate(system_root / windows_path{"System32"} / windows_path{dll}));
            }
            return fingerprint.text();
        }

        std::string command_line(windows_emulator& win_emu)
        {
            const auto parameters = win_emu.process.process_params64.read();
            return u16_to_u8(read_unicode_string(win_emu.emu(), parameters.CommandLine));
        }

        std::string windows_version(const windows_emulator& win_emu)
        {
            const auto& version = win_emu.version;
            return std::to_string(version.get_major_version()) + "." + std::to_string(version.get_minor_version()) + "." +
                   std::to_string(version.get_windows_build_number()) + "." + std::to_string(version.get_windows_update_build_revision());
        }

        manifest_entries recording_manifest(windows_emulator& win_emu, const record_settings& settings)
        {
            win_emu.setup_process_if_necessary();
            const auto* executable = win_emu.mod_manager.executable;
            manifest_entries manifest{
                {"build", build_commit},
                {"backend", win_emu.emu().get_name()},
                {"cpuid", std::string(cpuid_scheme)},
                {"ui", dynamic_cast<const recordable_ui_backend*>(&win_emu.ui()) ? "recorded" : "headless"},
                {"emulation_root", path_text(win_emu.emulation_root)},
                {"registry", registry_fingerprint(win_emu)},
                {"system_dlls", system_dll_fingerprint(win_emu)},
                {"windows_version", windows_version(win_emu)},
                {"executable", executable ? path_text(executable->path) : std::string()},
                {"command_line", command_line(win_emu)},
                {"checkpoint_interval", std::to_string(settings.checkpoint_interval)},
            };
            manifest.insert(manifest.end(), settings.manifest.begin(), settings.manifest.end());
            return manifest;
        }

        void check_manifest(const windows_emulator& win_emu, const trace& recorded)
        {
            const auto backend = win_emu.emu().get_name();
            if (const auto recorded_backend = recorded.manifest_value("backend"); recorded_backend && *recorded_backend != backend)
            {
                throw std::runtime_error("TTD trace was recorded with the " + std::string(*recorded_backend) + " backend, not " + backend);
            }
            if (const auto cpuid = recorded.manifest_value("cpuid"); cpuid && *cpuid != cpuid_scheme)
            {
                throw std::runtime_error("TTD trace was recorded with CPUID results " + std::string(*cpuid) + "; this build reports " +
                                         std::string(cpuid_scheme));
            }
        }

        std::string difference_suffix(const std::vector<std::string>& differences)
        {
            std::string suffix{};
            for (const auto& difference : differences)
            {
                suffix += "; " + difference;
            }
            return suffix;
        }
    }

    std::vector<std::string> manifest_differences(const windows_emulator& win_emu, const trace& recorded)
    {
        std::vector<std::string> differences{};
        const auto compare = [&](const std::string_view key, const std::string& replayed) {
            if (const auto value = recorded.manifest_value(key); value && *value != replayed)
            {
                differences.push_back(std::string(key) + " differs: recorded \"" + std::string(*value) + "\", replay \"" + replayed + "\"");
            }
        };
        compare("emulation_root", path_text(win_emu.emulation_root));
        compare("registry", registry_fingerprint(win_emu));
        compare("system_dlls", system_dll_fingerprint(win_emu));
        compare("build", build_commit);
        return differences;
    }

    std::optional<cpuid_result> cpuid_override(const uint32_t leaf, const bool hide_rdrand)
    {
        switch (leaf)
        {
        case 1: {
            // SSE4.x and AVX are hidden; see https://github.com/momo5502/sogen/issues/560
            constexpr uint32_t rdrand_feature = 1U << 30;
            constexpr uint32_t features = 0xEFE2F38F;
            return cpuid_result{
                .eax = 0x000906EA, .ebx = 0x00100800, .ecx = hide_rdrand ? features & ~rdrand_feature : features, .edx = 0xBFEBFBFF};
        }
        case 0x40000000:
            // Microsoft Hv vendor string
            return cpuid_result{.eax = 0x40000003, .ebx = 0x7263694d, .ecx = 0x666f736f, .edx = 0x76482074};
        case 0x40000003:
            return cpuid_result{.eax = 0, .ebx = 1, .ecx = 0, .edx = 0};
        default:
            return std::nullopt;
        }
    }

    void install_cpuid_overrides(windows_emulator& win_emu)
    {
        win_emu.emu().hook_instruction(x86_hookable_instructions::cpuid, [&win_emu](cpu_interface& cpu, uint64_t) {
            return win_emu.dispatch_on_cpu(cpu, [&] {
                auto& emu = win_emu.active_cpu();
                const auto result = cpuid_override(emu.reg<uint32_t>(x86_register::eax), true);
                if (!result)
                {
                    return instruction_hook_continuation::run_instruction;
                }
                emu.reg<uint32_t>(x86_register::eax, result->eax);
                emu.reg<uint32_t>(x86_register::ebx, result->ebx);
                emu.reg<uint32_t>(x86_register::ecx, result->ecx);
                emu.reg<uint32_t>(x86_register::edx, result->edx);
                return instruction_hook_continuation::skip_instruction;
            });
        });
    }

    void require_deterministic(const windows_emulator& win_emu)
    {
        if (win_emu.vcpu_count() != 1)
        {
            throw std::runtime_error("TTD requires one vCPU");
        }
        if (!win_emu.uses_instruction_precision())
        {
            throw std::runtime_error("TTD requires instruction precision");
        }
        if (!win_emu.uses_relative_time())
        {
            throw std::runtime_error("TTD requires the relative clock (reproducible mode)");
        }
        if (!dynamic_cast<const null_ui_backend*>(&win_emu.ui()) && !dynamic_cast<const recordable_ui_backend*>(&win_emu.ui()))
        {
            throw std::runtime_error("TTD requires a recordable or headless UI: live window input (focus, mouse, keys) must be "
                                     "recorded to be replayed (use ttd.create_emulator)");
        }
    }

    void record(windows_emulator& win_emu, const record_settings& settings, const std::function<bool()>& interrupted)
    {
        require_deterministic(win_emu);
        const auto stop_requested = [&] { return interrupted && interrupted(); };
        recorder trace_recorder(win_emu, settings.path, settings.access_mask, recording_manifest(win_emu, settings));
        if (!settings.checkpoint_interval)
        {
            win_emu.start(static_cast<size_t>(settings.max_instructions));
        }
        else
        {
            const auto start = win_emu.get_executed_instructions();
            const auto end = settings.max_instructions ? start + std::min(settings.max_instructions, UINT64_MAX - start) : UINT64_MAX;
            while (!win_emu.process.exit_status && !stop_requested())
            {
                const auto before = win_emu.get_executed_instructions();
                if (before >= end)
                {
                    break;
                }
                const auto budget = std::min(settings.checkpoint_interval, end - before);
                win_emu.start(static_cast<size_t>(budget));
                if (win_emu.process.exit_status || stop_requested() || win_emu.get_executed_instructions() - before < budget)
                {
                    break;
                }
                if (win_emu.get_executed_instructions() < end)
                {
                    trace_recorder.checkpoint();
                }
            }
        }
        trace_recorder.finish();
    }

    namespace
    {
        // Runs the emulator to `position` with one start() per checkpoint interval, as the recording ran: window input
        // is pumped at each boundary. Also stops at `keyframe_stops` (sorted) and calls `at_keyframe` there. Returns
        // whether it got there.
        bool run_intervals(windows_emulator& win_emu, trace& recorded, const uint64_t position,
                           const std::span<const uint64_t> keyframe_stops = {}, const std::function<void()>& at_keyframe = {})
        {
            const auto run_to = [&](const uint64_t target) {
                const auto before = win_emu.get_executed_instructions();
                if (target > before)
                {
                    win_emu.start(static_cast<size_t>(target - before));
                }
                return win_emu.get_executed_instructions() == target;
            };

            const auto from = win_emu.get_executed_instructions();
            std::vector<uint64_t> stops{};
            for (const auto& checkpoint : recorded.checkpoints())
            {
                stops.push_back(checkpoint.step);
            }
            stops.insert(stops.end(), keyframe_stops.begin(), keyframe_stops.end());
            std::erase_if(stops, [&](const uint64_t stop) { return stop <= from || stop >= position; });
            std::ranges::sort(stops);
            stops.erase(std::ranges::unique(stops).begin(), stops.end());

            for (const auto stop : stops)
            {
                if (!run_to(stop))
                {
                    return false;
                }
                if (std::ranges::binary_search(keyframe_stops, stop))
                {
                    at_keyframe();
                }
            }
            return run_to(position);
        }

        // Where a replay from `from` to `position` keeps keyframes: with `every_interval`, at every checkpoint and
        // keyframe_interval on the way (to prepare a trace); otherwise only at the last keyframe_interval before
        // `position`, so that moving back from there is cheap while a single seek stays about as fast as without.
        std::vector<uint64_t> keyframe_stops(const trace& recorded, const uint64_t from, const uint64_t position, const bool every_interval)
        {
            std::vector<uint64_t> stops{};
            if (!every_interval)
            {
                if (const auto last = (position - 1) / keyframe_interval * keyframe_interval; position && last > from)
                {
                    stops.push_back(last);
                }
                return stops;
            }
            for (auto stop = (from / keyframe_interval + 1) * keyframe_interval; stop < position; stop += keyframe_interval)
            {
                stops.push_back(stop);
            }
            for (const auto& checkpoint : recorded.checkpoints())
            {
                if (checkpoint.step > from && checkpoint.step < position)
                {
                    stops.push_back(checkpoint.step);
                }
            }
            std::ranges::sort(stops);
            stops.erase(std::ranges::unique(stops).begin(), stops.end());
            return stops;
        }

        // Replays from `from`, where the emulator holds the recorded state, to `position`. With `keyframes`, keeps states
        // on the way (see keyframe_stops) and finally notes what the emulator holds (keyframe_store::note_state);
        // `exact_start` tells that the state at `from` was reached without substituting inputs.
        seek_result replay_range(windows_emulator& win_emu, trace& recorded, const uint64_t from, const uint64_t position,
                                 const bool strict, const bool from_checkpoint, keyframe_store* keyframes = nullptr,
                                 const bool exact_start = true, const bool every_interval = false)
        {
            try
            {
                replay_verifier verifier(win_emu, recorded, from, strict);
                const auto clock = [&verifier] { return verifier.next_event_number(); };
                std::optional<ui_replay> ui{};
                if (from_checkpoint)
                {
                    ui.emplace(win_emu, recorded.ui_inputs(), recorded.checkpoint_index(from), clock);
                }
                else
                {
                    ui.emplace(win_emu, recorded.ui_inputs(), ui_replay::after_events{verifier.next_event_number()}, clock);
                }
                // Keyframes captured on the way read only the memory the replay changed since the previous one.
                std::vector<uint64_t> written_pages{};
                std::vector<std::pair<uint64_t, uint64_t>> remapped{};
                auto baseline = from;
                const auto incremental = keyframes && verifier.observes_all_writes();
                if (incremental)
                {
                    verifier.observe_writes([&](const uint64_t address, const size_t size) {
                        for (auto page = page_align_down(address); page < address + size; page += 0x1000)
                        {
                            if (written_pages.empty() || written_pages.back() != page)
                            {
                                written_pages.push_back(page);
                            }
                        }
                    });
                    win_emu.memory.set_mapping_change_callback(
                        [&](const uint64_t address, const size_t size) { remapped.emplace_back(address, size); });
                }
                const auto stop_tracking = utils::finally([&] {
                    if (incremental)
                    {
                        win_emu.memory.set_mapping_change_callback({});
                    }
                });
                const auto sort_written_pages = [&] {
                    std::ranges::sort(written_pages);
                    written_pages.erase(std::ranges::unique(written_pages).begin(), written_pages.end());
                };
                const auto at_stop = [&] {
                    if (verifier.diverged())
                    {
                        return;
                    }
                    const auto exact = exact_start && !verifier.substituted_inputs();
                    if (incremental)
                    {
                        sort_written_pages();
                        keyframes->capture(win_emu, exact, baseline, written_pages, remapped);
                    }
                    else
                    {
                        keyframes->capture(win_emu, exact);
                    }
                    baseline = win_emu.get_executed_instructions();
                    written_pages.clear();
                    remapped.clear();
                };

                const auto stops = keyframes ? keyframe_stops(recorded, from, position, every_interval) : std::vector<uint64_t>{};
                run_intervals(win_emu, recorded, position, stops, at_stop);
                verifier.finish();
                if (const auto reached = win_emu.get_executed_instructions(); reached != position)
                {
                    std::ostringstream message;
                    message << "TTD replay reached position " << std::hex << reached << " instead of " << position;
                    throw divergence_error(message.str());
                }
                if (incremental)
                {
                    sort_written_pages();
                    keyframes->note_state(win_emu, baseline, std::move(written_pages), std::move(remapped));
                }
                return {
                    .checkpoint = from, .verified_events = verifier.verified_events(), .substituted_inputs = verifier.substituted_inputs()};
            }
            catch (const divergence_error& e)
            {
                throw divergence_error(e.what() + difference_suffix(manifest_differences(win_emu, recorded)));
            }
        }
    }

    seek_result seek(windows_emulator& win_emu, trace& recorded, const uint64_t position, const bool strict)
    {
        require_deterministic(win_emu);
        check_manifest(win_emu, recorded);
        auto& keyframes = recorded.keyframes();
        const auto checkpoint_step = recorded.checkpoint_step_for(position);
        auto from = checkpoint_step;
        auto exact = true;
        // A strict seek must check every input from the checkpoint on, so it starts only from exact keyframes.
        if (const auto keyframe = keyframes.restore_latest(win_emu, checkpoint_step, position, strict))
        {
            std::tie(from, exact) = *keyframe;
        }
        else
        {
            snapshot::load_emulator_state(win_emu, *recorded.checkpoint_for_step(position).state);
        }
        return replay_range(win_emu, recorded, from, position, strict, from == checkpoint_step, &keyframes, exact);
    }

    void prepare_keyframes(trace& recorded, const std::span<windows_emulator* const> emulators)
    {
        for (auto* emulator : emulators)
        {
            require_deterministic(*emulator);
            check_manifest(*emulator, recorded);
        }

        const auto end = recorded.metadata().instruction_count;
        std::vector<uint64_t> starts{recorded.start_position()};
        for (const auto& checkpoint : recorded.checkpoints())
        {
            if (checkpoint.step > starts.back() && checkpoint.step < end)
            {
                starts.push_back(checkpoint.step);
            }
        }

        // Each emulator replays a contiguous run of checkpoint intervals, so it decodes one checkpoint and then keeps
        // going forward. Every emulator needs its own reader: a trace is not safe to use from several threads.
        const auto workers = std::min(emulators.size(), starts.size());
        std::vector<std::exception_ptr> failures(workers);
        std::vector<std::thread> threads{};
        for (size_t worker = 0; worker < workers; ++worker)
        {
            const auto first = starts[worker * starts.size() / workers];
            const auto next = (worker + 1) * starts.size() / workers;
            const auto last = next < starts.size() ? starts[next] : end;
            threads.emplace_back([&recorded, &failures, emulator = emulators[worker], worker, first, last] {
                try
                {
                    trace reader(recorded.path());
                    reader.share_keyframes(recorded);
                    snapshot::load_emulator_state(*emulator, *reader.checkpoint_for_step(first).state);
                    reader.keyframes().capture(*emulator, true);
                    replay_range(*emulator, reader, first, last, false, true, &reader.keyframes(), true, true);
                }
                catch (...)
                {
                    failures[worker] = std::current_exception();
                }
            });
        }
        for (auto& thread : threads)
        {
            thread.join();
        }
        for (const auto& failure : failures)
        {
            if (failure)
            {
                std::rethrow_exception(failure);
            }
        }
    }

    seek_result run_to(windows_emulator& win_emu, trace& recorded, const uint64_t position, const bool strict)
    {
        require_deterministic(win_emu);
        check_manifest(win_emu, recorded);
        const auto from = win_emu.get_executed_instructions();
        if (from < recorded.start_position() || from > recorded.metadata().instruction_count)
        {
            throw std::out_of_range("The emulator is not at a position of the TTD trace");
        }
        if (position < from)
        {
            throw std::out_of_range("TTD run_to cannot move backwards; seek instead");
        }
        if (position > recorded.metadata().instruction_count)
        {
            throw std::out_of_range("TTD position is beyond end of trace");
        }
        return replay_range(win_emu, recorded, from, position, strict, false);
    }

    seek_result replay_to_end(windows_emulator& win_emu, trace& recorded, const std::function<void()>& attach, const bool strict,
                              const bool restore)
    {
        require_deterministic(win_emu);
        const auto start = recorded.start_position();
        const auto end = recorded.metadata().instruction_count;
        if (restore)
        {
            check_manifest(win_emu, recorded);
            snapshot::load_emulator_state(win_emu, *recorded.checkpoint_for_step(start).state);
        }
        else
        {
            if (start || win_emu.get_executed_instructions())
            {
                throw std::runtime_error("A TTD replay from the application's setup needs a trace and an emulator at position 0, "
                                         "not a forked trace");
            }
            win_emu.setup_process_if_necessary();
            check_manifest(win_emu, recorded);
        }
        attach();
        try
        {
            replay_verifier verifier(win_emu, recorded, start, strict);
            const ui_replay ui(win_emu, recorded.ui_inputs(), 0, [&verifier] { return verifier.next_event_number(); });
            const auto reached = run_intervals(win_emu, recorded, end);
            verifier.finish();
            if (!reached)
            {
                std::ostringstream message;
                message << "TTD replay reached position " << std::hex << win_emu.get_executed_instructions() << " instead of " << end;
                throw divergence_error(message.str());
            }
            return {
                .checkpoint = start, .verified_events = verifier.verified_events(), .substituted_inputs = verifier.substituted_inputs()};
        }
        catch (const divergence_error& e)
        {
            throw divergence_error(e.what() + difference_suffix(manifest_differences(win_emu, recorded)));
        }
    }
}
