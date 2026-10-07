#include "ttd_session.hpp"
#include "snapshot.hpp"

#include <sstream>
#include <stdexcept>

namespace sogen::ttd
{
    namespace
    {
        std::string path_text(const std::filesystem::path& path)
        {
            const auto text = path.u8string();
            return {text.begin(), text.end()};
        }

        manifest_entries recording_manifest(windows_emulator& win_emu, const record_settings& settings)
        {
            win_emu.setup_process_if_necessary();
            const auto* executable = win_emu.mod_manager.executable;
            manifest_entries manifest{
                {"backend", win_emu.emu().get_name()},
                {"cpuid", std::string(cpuid_scheme)},
                {"emulation_root", path_text(win_emu.emulation_root)},
                {"executable", executable ? path_text(executable->path) : std::string()},
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

        // Settings outside the checkpointed state that can make a replay diverge: syscalls read files from the
        // emulation root again during the replay.
        std::string replay_differences(const windows_emulator& win_emu, const trace& recorded)
        {
            const auto root = path_text(win_emu.emulation_root);
            if (const auto recorded_root = recorded.manifest_value("emulation_root"); recorded_root && *recorded_root != root)
            {
                return "; the recording used emulation root \"" + std::string(*recorded_root) + "\", this replay \"" + root + "\"";
            }
            return {};
        }
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

    seek_result seek(windows_emulator& win_emu, trace& recorded, const uint64_t position)
    {
        require_deterministic(win_emu);
        check_manifest(win_emu, recorded);
        const auto checkpoint = recorded.checkpoint_for_step(position);
        snapshot::load_emulator_state(win_emu, checkpoint.state);
        try
        {
            replay_verifier verifier(win_emu, recorded, checkpoint.step);
            if (position > checkpoint.step)
            {
                win_emu.start(static_cast<size_t>(position - checkpoint.step));
            }
            verifier.finish();
            if (const auto reached = win_emu.get_executed_instructions(); reached != position)
            {
                std::ostringstream message;
                message << "TTD replay reached position " << std::hex << reached << " instead of " << position;
                throw divergence_error(message.str());
            }
            return {.checkpoint = checkpoint.step, .verified_events = verifier.verified_events()};
        }
        catch (const divergence_error& e)
        {
            throw divergence_error(e.what() + replay_differences(win_emu, recorded));
        }
    }
}
