#include "ttd_session.hpp"
#include "snapshot.hpp"
#include "ttd_build_info.hpp"

#include <array>
#include <fstream>
#include <iomanip>
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

        // FNV-1a over file names, sizes, and leading bytes. A registry hive's first 4 KiB is its base block, which
        // holds the hive's write sequence numbers, timestamp, and checksum; a PE's holds its headers with the link
        // timestamp and checksum. Hashing just those identifies a file version without reading whole hives.
        class file_fingerprint
        {
          public:
            void add_file(const std::string_view name, const std::filesystem::path& file)
            {
                this->add(std::as_bytes(std::span(name)));
                std::error_code error{};
                const auto size = std::filesystem::file_size(file, error);
                if (error)
                {
                    constexpr std::string_view missing = "missing";
                    this->add(std::as_bytes(std::span(missing)));
                    return;
                }
                this->add(std::as_bytes(std::span(&size, 1)));
                std::array<char, leading_bytes> bytes{};
                std::ifstream stream(file, std::ios::binary);
                stream.read(bytes.data(), bytes.size());
                this->add(std::as_bytes(std::span(bytes).first(static_cast<size_t>(stream.gcount()))));
            }

            std::string text() const
            {
                std::ostringstream text;
                text << std::hex << std::setw(16) << std::setfill('0') << this->hash_;
                return text.str();
            }

          private:
            static constexpr size_t leading_bytes = 4096;
            uint64_t hash_{0xcbf29ce484222325};

            void add(const std::span<const std::byte> bytes)
            {
                for (const auto byte : bytes)
                {
                    this->hash_ = (this->hash_ ^ static_cast<uint8_t>(byte)) * 0x100000001b3;
                }
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
            throw divergence_error(e.what() + difference_suffix(manifest_differences(win_emu, recorded)));
        }
    }

    seek_result replay_to_end(windows_emulator& win_emu, trace& recorded, const std::function<void()>& attach)
    {
        require_deterministic(win_emu);
        check_manifest(win_emu, recorded);
        const auto start = recorded.start_position();
        const auto end = recorded.metadata().instruction_count;
        snapshot::load_emulator_state(win_emu, recorded.checkpoint_for_step(start).state);
        attach();
        try
        {
            replay_verifier verifier(win_emu, recorded, start);
            const auto run_to = [&](const uint64_t position) {
                const auto before = win_emu.get_executed_instructions();
                if (position > before)
                {
                    win_emu.start(static_cast<size_t>(position - before));
                }
                return win_emu.get_executed_instructions() == position;
            };
            auto reached = true;
            for (const auto& checkpoint : recorded.checkpoints())
            {
                reached = run_to(checkpoint.step);
                if (!reached)
                {
                    break;
                }
            }
            reached = reached && run_to(end);
            verifier.finish();
            if (!reached)
            {
                std::ostringstream message;
                message << "TTD replay reached position " << std::hex << win_emu.get_executed_instructions() << " instead of " << end;
                throw divergence_error(message.str());
            }
            return {.checkpoint = start, .verified_events = verifier.verified_events()};
        }
        catch (const divergence_error& e)
        {
            throw divergence_error(e.what() + difference_suffix(manifest_differences(win_emu, recorded)));
        }
    }
}
