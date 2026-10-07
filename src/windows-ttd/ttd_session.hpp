#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <windows_emulator.hpp>

#include "ttd_format.hpp"
#include "ttd_trace.hpp"
#include "ttd_ui.hpp"

namespace sogen::ttd
{
    struct cpuid_result
    {
        uint32_t eax{};
        uint32_t ebx{};
        uint32_t ecx{};
        uint32_t edx{};
    };

    // The CPUID results Sogen's tools report instead of executing CPUID. A recording depends on them, so every tool that
    // records or replays a trace reports the same ones, with RDRAND hidden: Unicorn serves it from the host's random
    // source outside MSVC builds, which a replay cannot repeat.
    std::optional<cpuid_result> cpuid_override(uint32_t leaf, bool hide_rdrand);

    // Hooks CPUID with the overrides (RDRAND hidden) on an emulator that nothing else hooks CPUID on, for recording or
    // replaying without the analyzer.
    void install_cpuid_overrides(windows_emulator& win_emu);

    // Throws unless the emulator runs the way TTD recording and replay require: one vCPU, instruction precision, the
    // relative clock, and a UI whose input can be recorded and replayed (recordable_ui_backend) or none
    // (null_ui_backend): host window events arrive whenever the desktop delivers them.
    void require_deterministic(const windows_emulator& win_emu);

    struct record_settings
    {
        std::filesystem::path path{};
        uint64_t access_mask{all_access_kinds};
        // Zero records only the initial state.
        uint64_t checkpoint_interval{500000};
        // Instructions to record from the current position; zero runs until the process exits.
        uint64_t max_instructions{};
        // Front-end entries, stored after the ones record() adds: build, backend, cpuid, emulation_root, registry
        // and system_dlls (fingerprints of the hives and of ntdll/kernel32/kernelbase), windows_version, executable,
        // command_line, checkpoint_interval.
        manifest_entries manifest{};
    };

    // Identifies the cpuid_override results. Change it whenever they change: replays refuse traces recorded with other
    // results instead of diverging at the first CPUID.
    constexpr std::string_view cpuid_scheme = "1";

    // Records the emulator from its current state until the process exits, the instruction limit is reached, or
    // `interrupted` returns true, and finalizes the trace. Recording after a seek forks the replayed trace into a new
    // one that starts at the seek position.
    void record(windows_emulator& win_emu, const record_settings& settings, const std::function<bool()>& interrupted = {});

    // The recorded inputs that live outside the checkpoints (emulation root, hives, system DLLs, build) and differ for
    // this emulator, one description each; a replay reads them again, so any of them can explain a divergence. Use
    // it on an emulator that holds a restored checkpoint: the system root comes from the emulator state.
    std::vector<std::string> manifest_differences(const windows_emulator& win_emu, const trace& recorded);

    struct seek_result
    {
        uint64_t checkpoint{};
        uint64_t verified_events{};
        // Syscalls whose live writes or result, and host writes outside syscalls whose live bytes, differed from the
        // recording and were replaced by the recorded ones.
        uint64_t substituted_inputs{};
    };

    // Restores the last checkpoint at or before `position` and replays to it, verifying every recorded event. Throws
    // divergence_error when the replay diverges from the recording or stops before `position`, naming the manifest
    // settings this replay does not share with the recording, and refuses a trace recorded with another backend or
    // other CPUID results.
    // Unless `strict`, syscalls and host writes with other results than recorded take the recorded ones (see
    // replay_verifier).
    seek_result seek(windows_emulator& win_emu, trace& recorded, uint64_t position, bool strict = false);

    // Restores the trace's initial state, calls `attach` (to hook analyses such as the replay scans onto the restored
    // emulator), and replays the whole trace, one checkpoint interval at a time as it was recorded, verifying every
    // recorded event. Throws like seek.
    seek_result replay_to_end(windows_emulator& win_emu, trace& recorded, const std::function<void()>& attach, bool strict = false);
}
