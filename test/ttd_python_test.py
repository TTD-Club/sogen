"""Check the sogen.ttd Python bindings against ttd-step-sample, across the CLI and Python.

Usage: ttd_python_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]. The sogen module is imported from the analyzer's
directory. SAMPLE is a host path (host mode), or a guest path when EMULATOR_ARGS is `-e ROOT`.
"""

import gc
import pathlib
import random
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import ttd_format  # noqa: E402

OLD_VALUE = 0x1111111111111111
NEW_VALUE = 0x2222222222222222
FORKED_VALUE = 0x4444444444444444
WM_APP = 0x8000
UI_VALUE = 0x5A5A


def main() -> None:
    analyzer = pathlib.Path(sys.argv[1]).resolve()
    sample = sys.argv[2]
    emulator_args = sys.argv[3:]
    sys.path.insert(0, str(analyzer.parent))
    import sogen  # noqa: E402
    from sogen import ttd  # noqa: E402

    settings = {"registry_directory": str(analyzer.parent / "registry"), "disable_logging": True}
    if emulator_args[:1] == ["-e"]:
        settings["emulation_root"] = emulator_args[1]

    def run(*args: str) -> str:
        result = subprocess.run([str(analyzer), *args], text=True, capture_output=True, cwd=analyzer.parent)
        if result.returncode != 0:
            raise AssertionError(f"analyzer {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
        return result.stdout

    def read_u64(emulator, address: int) -> int:
        return int.from_bytes(emulator.read_memory(address, 8), "little")

    with tempfile.TemporaryDirectory() as directory:
        cli_trace = str(pathlib.Path(directory) / "cli.sogttd")
        recording = run("--ttd-record", cli_trace, "--ttd-checkpoint-interval", "100000", *emulator_args, sample)
        address = int(re.search(r"ttd-value ([0-9A-Fa-f]+)", recording).group(1), 16)

        # Offline queries on a CLI recording.
        trace = ttd.Trace(cli_trace)
        assert trace.checkpoints[0] == 0 and len(trace.checkpoints) > 1
        writes = trace.accesses(address, 8, kinds=ttd.WRITE)
        reads = trace.accesses(address, 8, kinds=ttd.READ)
        assert len(writes) == 1 and len(reads) == 1, (writes, reads)
        store, load = writes[0], reads[0]
        assert store.data == NEW_VALUE.to_bytes(8, "little") and load.data == store.data
        assert trace.next_access(address, 8, position=0, kinds=ttd.WRITE).position == store.position
        assert trace.previous_access(address, 8, position=load.position + 1, kinds=ttd.READ).position == load.position
        execute = trace.accesses(store.ip, 1, kinds=ttd.EXECUTE, start=store.position, end=store.position)
        assert len(execute) == 1 and execute[0].data, execute
        history = trace.history(address, 8)
        assert [entry.event.position for entry in history][-2:] == [store.position, load.position]
        assert history[-1].value == list(NEW_VALUE.to_bytes(8, "little"))
        first = next(trace.events(kinds=ttd.EXECUTE))
        assert first.kind == ttd.EXECUTE and first.position == 1

        # tools/ttd_format.py decodes the filtered bulk blocks (mapped images) exactly like the library.
        large = [event.data for event in trace.events(kinds=ttd.HOST_WRITE) if len(event.data) > ttd_format.INLINE_DATA_LIMIT]
        mirrored = [event.data for event in ttd_format.Trace(cli_trace).events()
                    if event.kind == ttd_format.HOST_WRITE and event.size > ttd_format.INLINE_DATA_LIMIT]
        assert large and large == mirrored

        # Replaying a CLI recording in Python: the CPUID results and settings must match the analyzer's.
        emulator = ttd.create_emulator(sample, **settings)
        replay = ttd.Replay(trace, emulator)
        replay.seek(store.position - 1)
        assert read_u64(emulator, address) == OLD_VALUE
        result = replay.seek(store.position)
        assert replay.position == store.position and result.verified_events > 0
        assert read_u64(emulator, address) == NEW_VALUE

        # Fork: change memory after the store and run on without verification, then return to the recording.
        emulator.write_memory(address, FORKED_VALUE.to_bytes(8, "little"))
        emulator.start(load.position - store.position)
        assert emulator.executed_instructions == load.position
        assert read_u64(emulator, address) == FORKED_VALUE
        replay.seek(load.position)
        assert read_u64(emulator, address) == NEW_VALUE

        # run_to moves forward from where the replay stopped without restoring a checkpoint, across checkpoints too,
        # and reaches the same state as a seek. It refuses to move back, or to go on after the emulator ran.
        replay.seek(store.position - 1)
        result = replay.run_to(store.position)
        assert result.checkpoint == store.position - 1 and result.verified_events > 0, result
        assert read_u64(emulator, address) == NEW_VALUE
        later = min(trace.instruction_count, trace.checkpoints[-1] + 10)
        assert any(store.position < checkpoint < later for checkpoint in trace.checkpoints), trace.checkpoints
        replay.run_to(later)
        stepped = emulator.serialize_state()
        replay.seek(later)
        assert emulator.serialize_state() == stepped
        try:
            replay.run_to(later - 1)
        except IndexError as error:
            assert "backwards" in str(error), error
        else:
            raise AssertionError("run_to moved backwards")
        emulator.start(10)
        try:
            replay.run_to(later + 20)
        except RuntimeError as error:
            assert "ran since" in str(error), error
        else:
            raise AssertionError("run_to went on after the emulator ran")

        # cpu_at: the registers at a position from the nearest register snapshot and a replay on a standalone CPU. They
        # equal a full replay's everywhere but right before a thread switch, where cpu_at already has the next
        # thread's registers. memory_at and read_memory: the bytes at a position from the recorded accesses.
        assert trace.has_register_snapshots
        mirror = ttd_format.Trace(cli_trace)
        snapshot_positions = [entry[0] for entry in mirror.register_snapshots]
        assert snapshot_positions[0] == 0 and snapshot_positions[-1] == trace.instruction_count, snapshot_positions[:3]
        assert snapshot_positions == sorted(snapshot_positions) and mirror.mapping_changes, len(mirror.mapping_changes)
        assert all(base is None or mirror.register_snapshots[base][4] is None for *_, base in mirror.register_snapshots)
        names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                 "rip", "rflags"]
        before_switch = {switch.position - 1 for switch in trace.thread_switches}
        rng = random.Random(4)
        positions = {store.position - 1, store.position, load.position, trace.instruction_count}
        for syscall in trace.syscalls[:15]:
            positions.update(syscall.position + delta for delta in (-1, 0, 1))
        for switch in trace.thread_switches[1:8]:
            positions.update({switch.position, switch.position + 1})
        positions.update(rng.randrange(1, trace.instruction_count + 1) for _ in range(25))
        compared = 0
        for position in sorted(p for p in positions - before_switch if 0 < p <= trace.instruction_count):
            view = trace.cpu_at(position)
            assert view.position == position and view.replayed_instructions < 30000, view
            replay.seek(position)
            for name in names:
                register = getattr(sogen.Register, name)
                assert view.read_register(register) == emulator.read_register(register), (position, name)
            rsp = view.read_register(sogen.Register.rsp)
            for index, byte in enumerate(trace.memory_at(position, rsp, 64)):
                assert byte is None or byte == emulator.read_memory(rsp + index, 1)[0], (position, hex(rsp + index))
            compared += 1
        assert compared > 40, compared
        for position in sorted(before_switch)[:5]:
            trace.cpu_at(position)
        assert len(trace.cpu_at(store.position).read_register_bytes(sogen.Register.xmm0)) == 16
        # The global's old value comes from the image, and no access shows it before the store changes it.
        assert trace.memory_at(store.position - 1, address, 8) == [None] * 8
        assert trace.read_memory(store.position, address, 8) == NEW_VALUE.to_bytes(8, "little")
        assert trace.read_memory(load.position - 1, address, 8) == NEW_VALUE.to_bytes(8, "little")
        assert trace.memory_at(store.position, 0x10, 4) == [None] * 4
        try:
            trace.read_memory(store.position, 0x10, 4)
        except ValueError as error:
            assert "0x10" in str(error), error
        else:
            raise AssertionError("read_memory returned bytes no access shows")
        try:
            trace.cpu_at(trace.instruction_count + 1)
        except IndexError:
            pass
        else:
            raise AssertionError("cpu_at went beyond the end of the trace")

        # Keyframes: seeks keep states on the way that later seeks restore, and prepare_seeks keeps them over the whole
        # trace on several emulators at once. Every state reached from a keyframe equals the one a full replay from the
        # checkpoint reaches (a second reader with no keyframe budget), including after a fork and in strict seeks.
        plain = ttd.Trace(cli_trace)
        plain.keyframe_budget = 0
        plain_replay = ttd.Replay(plain, ttd.create_emulator(sample, **settings))
        keyed = ttd.Trace(cli_trace)
        keyed_replay = ttd.Replay(keyed, keyed_emulator := ttd.create_emulator(sample, **settings))
        positions = [load.position, load.position - 30000, load.position - 1, store.position, keyed.instruction_count]
        for position in positions:
            keyed_replay.seek(position)
            plain_replay.seek(position)
            assert keyed_emulator.serialize_state() == plain_replay.emulator.serialize_state(), position
        assert plain.keyframe_count == 0 and 0 < keyed.keyframe_count <= len(positions), keyed.keyframe_count
        keyed.prepare_seeks([ttd.create_emulator(sample, **settings) for _ in range(3)])
        assert keyed.keyframe_count > len(keyed.checkpoints) and keyed.keyframe_memory > 0, keyed.keyframe_count
        rng = random.Random(1)
        for position in [rng.randrange(1, keyed.instruction_count + 1) for _ in range(8)] + [store.position - 1]:
            result = keyed_replay.seek(position)
            plain_replay.seek(position)
            assert 0 < position - result.checkpoint < 25000 or position == result.checkpoint, (position, result.checkpoint)
            assert keyed_emulator.serialize_state() == plain_replay.emulator.serialize_state(), position
        keyed_emulator.write_memory(address, FORKED_VALUE.to_bytes(8, "little"))
        keyed_emulator.start(1000)
        for strict_replay in (keyed_replay, ttd.Replay(keyed, keyed_emulator, strict=True)):
            strict_replay.seek(load.position)
            plain_replay.seek(load.position)
            assert read_u64(keyed_emulator, address) == NEW_VALUE
            assert keyed_emulator.serialize_state() == plain_replay.emulator.serialize_state()
        del plain_replay, keyed_replay, strict_replay
        plain.close()
        keyed.close()

        # The manifest says how a trace was recorded; tools/ttd_format.py reads the same entries.
        manifest = trace.manifest
        assert manifest["tool"] == "analyzer" and manifest["cpuid"] == "1", manifest
        assert manifest["backend"] == emulator.backend_name and manifest["checkpoint_interval"] == "100000", manifest
        assert manifest["build"] and manifest["build"] != "unknown", manifest
        assert re.fullmatch(r"[0-9a-f]{16}", manifest["registry"]) and re.fullmatch(r"[0-9a-f]{16}", manifest["system_dlls"])
        assert re.fullmatch(r"10\.0\.\d+\.\d+", manifest["windows_version"]), manifest
        assert pathlib.PurePath(sample).name.lower() in manifest["command_line"].lower(), manifest
        assert ttd_format.Trace(cli_trace).manifest == manifest
        assert replay.manifest_differences() == []

        # Replay scans: the transient string, the generated function's write-then-execute wave, and written buffers.
        transient = [found for found in replay.strings() if "SOGEN_TTD_TRANSIENT_STRING_FOR_RECOVERY" in found.value]
        assert any(found.position > 0 for found in transient), transient
        assert replay.position == trace.instruction_count
        code = int(re.search(r"ttd-code ([0-9A-Fa-f]+)", recording).group(1), 16)
        waves = replay.self_modifying_waves()
        assert any(wave.address == code and wave.size == 5 for wave in waves), waves
        buffers = replay.buffers()
        assert buffers and all(buffer.size == len(buffer.data) for buffer in buffers), buffers

        # Recording after a seek forks the trace: the new trace starts at the seek position and replays on its own,
        # in Python and in the CLI.
        fork_trace = str(pathlib.Path(directory) / "fork.sogttd")
        replay.seek(store.position)
        emulator.write_memory(address, FORKED_VALUE.to_bytes(8, "little"))
        fork_length = load.position - store.position + 20000
        with ttd.record(emulator, fork_trace, checkpoint_interval=5000, max_instructions=fork_length,
                        manifest={"parent": "cli"}) as fork:
            assert fork.start_position == store.position and fork.checkpoints[0] == store.position, fork.checkpoints
            assert fork.checkpoints[1:] == list(range(store.position + 5000, fork.instruction_count, 5000)), fork.checkpoints
            assert len(fork.checkpoints) > 1
            assert load.position <= fork.instruction_count <= store.position + fork_length
            assert fork.manifest["parent"] == "cli" and fork.manifest["tool"] == "sogen.ttd", fork.manifest
            assert fork.module_at(store.ip, store.position).load_position == store.position
            assert fork.thread_switches[0].position > store.position
            assert len(list(fork.events(kinds=ttd.EXECUTE))) == fork.instruction_count - fork.start_position
            forked_loads = fork.accesses(address, 8, kinds=ttd.READ)
            assert [event.position for event in forked_loads] == [load.position], forked_loads
            assert forked_loads[0].data == FORKED_VALUE.to_bytes(8, "little")

            # Comparing the fork with its parent finds the load of the changed value.
            difference = ttd.first_difference(trace, fork)
            assert difference.first.position == load.position and difference.first.kind == ttd.READ, difference.first
            assert difference.first.data == NEW_VALUE.to_bytes(8, "little"), difference.first
            assert difference.second.data == FORKED_VALUE.to_bytes(8, "little"), difference.second
            assert trace.event(difference.first_number).position == load.position
            assert fork.event(difference.second_number).position == load.position
            assert ttd.first_difference(fork, fork) is None and ttd.first_difference(trace, trace) is None

            fork_replay = ttd.Replay(fork, ttd.create_emulator(sample, **settings))
            fork_replay.seek(load.position)
            assert read_u64(fork_replay.emulator, address) == FORKED_VALUE
            fork_replay.seek(fork.instruction_count)
            assert all(found.position >= fork.start_position for found in fork_replay.strings())
            assert all(buffer.first_position > fork.start_position for buffer in fork_replay.buffers())
            try:
                fork_replay.seek(store.position - 1)
            except IndexError as error:
                assert "before the start" in str(error)
            else:
                raise AssertionError("A fork replay restored a position before the fork")
            del fork_replay
        output = run("--ttd-replay", fork_trace, "--ttd-seek", hex(load.position), "--ttd-read", hex(address), *emulator_args,
                     sample)
        assert int(re.search(r"TTD memory [0-9a-f]+ = ([0-9a-f]+)", output).group(1), 16) == FORKED_VALUE, output

        # A replay that does not repeat the recording raises DivergenceError, a RuntimeError.
        tampered = str(pathlib.Path(directory) / "tampered.sogttd")
        shutil.copyfile(cli_trace, tampered)
        mirror = ttd_format.Trace(tampered)
        store_chunk = next(index for index, (_, _, first, last, _, _) in enumerate(mirror.chunks)
                           if first <= store.position <= last)
        chunk_events = mirror.chunk_events(store_chunk)
        recorded_store = next(event for event in chunk_events
                              if (event.step, event.address, event.kind) == (store.position, address, ttd_format.WRITE))
        recorded_store.data = (0x3333333333333333).to_bytes(8, "little")
        ttd_format.replace_chunk(tampered, store_chunk, chunk_events)
        # It also names recorded inputs that differ for the replay, such as the registry hives.
        ttd_format.replace_manifest(tampered, {**manifest, "registry": "0" * 16})
        with ttd.Trace(tampered) as tampered_trace:
            tampered_replay = ttd.Replay(tampered_trace, emulator)
            try:
                tampered_replay.seek(store.position)
            except ttd.DivergenceError as error:
                assert isinstance(error, RuntimeError) and "accessed different data" in str(error), error
                assert "registry differs" in str(error), error
                assert [difference.split(":")[0] for difference in tampered_replay.manifest_differences()] == [
                    "registry differs"]
            else:
                raise AssertionError("A tampered recording replayed without divergence")
            del tampered_replay

        # Host writes are the environment's input: a replay takes recorded bytes over live ones (a live network answer,
        # a host-assigned port) and counts them; strict replays report them instead. Tamper with a small host write and
        # replay up to it (later guest reads would see the tampered value).
        host_write = next(event for event in trace.events(kinds=ttd.HOST_WRITE)
                          if 0 < len(event.data) <= ttd_format.INLINE_DATA_LIMIT and event.position > 1000)
        input_trace = str(pathlib.Path(directory) / "input.sogttd")
        shutil.copyfile(cli_trace, input_trace)
        mirror = ttd_format.Trace(input_trace)
        input_chunk = next(index for index, (_, _, first, last, _, _) in enumerate(mirror.chunks)
                           if first <= host_write.position <= last)
        chunk_events = mirror.chunk_events(input_chunk)
        recorded_write = next(event for event in chunk_events
                              if (event.step, event.address, event.kind) == (host_write.position, host_write.address,
                                                                               ttd_format.HOST_WRITE))
        recorded_write.data = bytes(byte ^ 0xFF for byte in recorded_write.data)
        ttd_format.replace_chunk(input_trace, input_chunk, chunk_events)
        with ttd.Trace(input_trace) as input_recording:
            result = ttd.Replay(input_recording, emulator_for_inputs := ttd.create_emulator(sample, headless=True, **settings)).seek(
                host_write.position)
            assert result.substituted_inputs == 1, result.substituted_inputs
            replaced = emulator_for_inputs.read_memory(host_write.address, len(host_write.data))
            assert replaced == recorded_write.data, (replaced, recorded_write.data)
            try:
                ttd.Replay(input_recording, ttd.create_emulator(sample, headless=True, **settings), strict=True).seek(
                    host_write.position)
            except ttd.DivergenceError as error:
                assert "accessed different data" in str(error), error
            else:
                raise AssertionError("A strict replay accepted a host write with other bytes")
            del emulator_for_inputs

        # Every syscall is recorded with the events its handler produced and the result it returned; VirtualQuery's
        # output is NtQueryVirtualMemory's host write. tools/ttd_format.py reads the same entries.
        info = int(re.search(r"ttd-info ([0-9A-Fa-f]+)", recording).group(1), 16)
        info_write = trace.accesses(info, 8, kinds=ttd.HOST_WRITE)[0]
        syscalls = trace.syscalls
        query = next(syscall for syscall in syscalls if syscall.position == info_write.position)
        assert query.name == "NtQueryVirtualMemory" and query.result == 0 and query.event_count >= 1, query
        assert trace.event(query.event_number).position == info_write.position
        mirror_trace = ttd_format.Trace(cli_trace)
        mirrored = mirror_trace.syscalls
        assert [(s.step, s.event_number, s.event_count, s.result, s.id, s.name) for s in mirrored] == [
            (s.position, s.event_number, s.event_count, s.result, s.id, s.name) for s in syscalls]

        # Modules and threads: the sample's store runs in its own image on the main thread, the first one to run.
        sample_name = pathlib.PureWindowsPath(sample).name.lower()
        modules = trace.modules
        assert {"ntdll.dll", "kernel32.dll", sample_name} <= {module.name.lower() for module in modules}, modules
        image = trace.module_at(store.ip, store.position)
        assert image.name.lower() == sample_name and image.load_position == 0 and image.unload_position is None, image
        assert trace.module_at(store.ip, 0).base == image.base and trace.module_at(0x10, store.position) is None
        kernel32 = next(module for module in modules if module.name.lower() == "kernel32.dll")
        assert kernel32.load_position > 0 and trace.module_at(kernel32.base, kernel32.load_position - 1) is None
        switches = trace.thread_switches
        main_thread = switches[0].thread_id
        assert switches[0].position == 1 and switches[0].event_number == 0, switches[0]
        assert trace.thread_at(store.position) == main_thread and trace.thread_at(0) is None
        assert set(trace.thread_names) == {switch.thread_id for switch in switches}
        assert all(trace.thread_at(switch.position) == switch.thread_id for switch in switches)
        per_thread = {thread: sum(1 for _ in trace.events(kinds=ttd.EXECUTE, thread=thread)) for thread in trace.thread_names}
        assert len(per_thread) > 1 and sum(per_thread.values()) == trace.instruction_count, per_thread
        assert [(m.base, m.size, m.load_position, m.unload_position, m.name, m.path) for m in modules] == [
            (m["base"], m["size"], m["load_step"], m["unload_step"], m["name"], m["path"]) for m in mirror_trace.modules]
        assert [(s.position, s.event_number, s.thread_id) for s in switches] == mirror_trace.thread_switches
        assert trace.thread_names == mirror_trace.thread_names

        # Exports name addresses and find the calls of a function: the sample calls VirtualQuery once.
        assert [[(e.rva, e.ordinal, e.name) for e in m.exports] for m in modules] == [m["exports"] for m in mirror_trace.modules]
        assert all([(e.rva, e.name) for e in m.exports] == sorted((e.rva, e.name) for e in m.exports) for m in modules)
        assert sum(len(m.exports) for m in modules) > 1000
        found = trace.find_exports("kernel32!VirtualQuery")
        assert [module.name.lower() for module, _ in found] == ["kernel32.dll"], found
        assert len(trace.find_exports("VirtualQuery")) >= len(found)
        calls = trace.calls("kernel32!VirtualQuery")
        assert len(calls) == 1 and calls[0].kind == ttd.EXECUTE, calls
        assert calls[0].address == found[0][0].base + found[0][1].rva and calls[0].position < trace.instruction_count
        assert [c.position for c in trace.calls("KERNEL32.DLL!VirtualQuery")] == [calls[0].position]
        assert trace.calls("kernel32!VirtualQuery", start=calls[0].position + 1) == []
        assert trace.symbol(calls[0].address, calls[0].position).lower() == "kernel32.dll!virtualquery"
        assert trace.symbol(calls[0].address + 1, calls[0].position).lower() == "kernel32.dll!virtualquery+0x1"
        assert trace.symbol(store.ip, store.position).lower().startswith(sample_name)
        assert trace.symbol(0x10, store.position) is None and trace.find_exports("kernel32!NoSuchExport") == []

        # Forwarded exports name their targets, API sets resolved, and their calls are the target's.
        assert [{e.ordinal: e.forwarder for e in m.exports if e.forwarder} for m in modules] == [
            m.get("forwarders", {}) for m in mirror_trace.modules]
        forwarded = [e for m in modules for e in m.exports if e.forwarder]
        assert len(forwarded) > 100 and all("!" in e.forwarder for e in forwarded), forwarded[:5]
        assert sum(e.forwarder.startswith(("api-", "ext-")) for e in forwarded) < len(forwarded) // 10, forwarded[:5]
        (kernel32, heap_alloc), = trace.find_exports("kernel32!HeapAlloc")
        assert heap_alloc.forwarder == "ntdll.dll!RtlAllocateHeap", heap_alloc
        # Before kernel32 loads, ntdll's function runs but kernel32's name for it does not exist yet.
        positions = lambda name, start=0: [(c.position, c.address) for c in trace.calls(name, start=start)]
        allocations = positions("ntdll!RtlAllocateHeap", kernel32.load_position)
        assert allocations and positions("kernel32!HeapAlloc") == allocations
        assert positions("HeapAlloc") == positions("RtlAllocateHeap", kernel32.load_position) == allocations
        assert not (trace.symbol(kernel32.base + heap_alloc.rva, allocations[0][0]) or "").lower().endswith("!heapalloc")
        assert [(m.name, e.name) for m, e in trace.find_exports(f"kernel32!#{heap_alloc.ordinal}")] == [(kernel32.name, "HeapAlloc")]

        # Live input that changes a syscall's outcome: ttd-input.txt exists while recording and is gone for the replay,
        # so NtQueryAttributesFile fails and writes nothing. A strict replay names the syscall; others undo its live
        # effects, give the guest the recorded output and status, and go on to the end.
        input_address = int(re.search(r"ttd-input ([0-9A-Fa-f]+)", recording).group(1), 16)
        if "emulation_root" in settings:
            guest = pathlib.PureWindowsPath(sample)
            input_file = pathlib.Path(settings["emulation_root"], "filesys", guest.drive.rstrip(":").lower(),
                                      *guest.parent.parts[1:], "ttd-input.txt")
        else:
            input_file = pathlib.Path(sample).parent / "ttd-input.txt"
        file_trace = str(pathlib.Path(directory) / "file.sogttd")
        input_file.write_text("ttd")
        try:
            ttd.record(ttd.create_emulator(sample, headless=True, **settings), file_trace, checkpoint_interval=100000).close()
        finally:
            input_file.unlink()
        with ttd.Trace(file_trace) as file_recording:
            attributes = file_recording.accesses(input_address, 4, kinds=ttd.WRITE)[-1]
            assert attributes.data != b"\xff\xff\xff\xff", attributes.data
            file_query = [syscall for syscall in file_recording.syscalls
                          if syscall.name == "NtQueryAttributesFile" and syscall.position < attributes.position][-1]
            assert file_query.result == 0 and file_query.event_count == 1, file_query
            try:
                ttd.Replay(file_recording, ttd.create_emulator(sample, headless=True, **settings), strict=True).seek(
                    attributes.position)
            except ttd.DivergenceError as error:
                assert "NtQueryAttributesFile" in str(error), error
            else:
                raise AssertionError("A strict replay accepted a syscall with another outcome")
            file_replay = ttd.Replay(file_recording, ttd.create_emulator(sample, headless=True, **settings))
            result = file_replay.seek(attributes.position)
            assert result.substituted_inputs == 1, result.substituted_inputs
            assert file_replay.emulator.read_memory(input_address, 4) == attributes.data
            assert file_replay.strings() and file_replay.position == file_recording.instruction_count
            del file_replay

        # A trace recorded with other CPUID results is refused before replaying.
        ttd_format.replace_manifest(tampered, {**manifest, "cpuid": "0"})
        with ttd.Trace(tampered) as tampered_trace:
            try:
                ttd.Replay(tampered_trace, emulator).seek(1)
            except ttd.DivergenceError:
                raise AssertionError("A CPUID mismatch was reported as a divergence")
            except RuntimeError as error:
                assert "CPUID results 0" in str(error), error
            else:
                raise AssertionError("A trace with other CPUID results replayed")

        try:
            ttd.Replay(trace, sogen.windows.create_application(sample, **settings))
        except RuntimeError as error:
            assert "relative clock" in str(error)
        else:
            raise AssertionError("Replay accepted an emulator without the relative clock")

        # Host window events arrive whenever the desktop delivers them, so a TTD emulator's UI logs them while
        # recording and replays the logged ones; a plain live UI is refused.
        try:
            ttd.Replay(trace, sogen.windows.create_application(sample, backend=sogen.Backend.unicorn, use_relative_time=True,
                                                               **settings))
        except RuntimeError as error:
            assert "recordable or headless UI" in str(error), error
        else:
            raise AssertionError("Replay accepted an emulator with live window input")
        assert trace.manifest["ui"] == "recorded" and trace.ui_inputs == []
        del replay, emulator
        trace.close()

        # Window input: an injected WM_APP reaches the sample's window while recording, and replays deliver it again at
        # the same point. Without the recorded input the replay diverges where the input arrived.
        window = int(re.search(r"ttd-window ([0-9A-Fa-f]+)", recording).group(1), 16)
        ui_address = int(re.search(r"ttd-ui ([0-9A-Fa-f]+)", recording).group(1), 16)
        ui_trace = str(pathlib.Path(directory) / "ui.sogttd")
        ui_emulator = ttd.create_emulator(sample, headless=True, **settings)
        ttd.inject_ui_event(ui_emulator, window, WM_APP, UI_VALUE)
        with ttd.record(ui_emulator, ui_trace, checkpoint_interval=100000) as ui_recorded:
            inputs = ui_recorded.ui_inputs
            assert [(i.window, i.message, i.wparam) for i in inputs] == [(window, WM_APP, UI_VALUE)], inputs
            assert ui_recorded.manifest["ui"] == "recorded"
            ui_writes = ui_recorded.accesses(ui_address, 8, kinds=ttd.WRITE)
            assert ui_writes and ui_writes[-1].data == UI_VALUE.to_bytes(8, "little"), ui_writes
            ui_replay = ttd.Replay(ui_recorded, ttd.create_emulator(sample, headless=True, **settings))
            ui_replay.seek(ui_recorded.instruction_count)
            assert read_u64(ui_replay.emulator, ui_address) == UI_VALUE
            ui_replay.seek(ui_writes[-1].position - 1)
            assert read_u64(ui_replay.emulator, ui_address) == 0
            # run_to delivers the recorded input like a seek does, also from before the checkpoint after which the input
            # arrived.
            input_checkpoint = ui_recorded.checkpoints[inputs[0].checkpoint]
            ui_replay.seek(max(input_checkpoint - 1, 0))
            ui_replay.run_to(ui_writes[-1].position)
            assert read_u64(ui_replay.emulator, ui_address) == UI_VALUE
            assert ui_replay.strings()
            try:
                ttd.Replay(ui_recorded, sogen.windows.create_application(sample, backend=sogen.Backend.unicorn,
                                                                         use_relative_time=True, headless=True,
                                                                         **settings)).seek(ui_recorded.instruction_count)
            except RuntimeError as error:
                assert "recorded window input" in str(error), error
            else:
                raise AssertionError("A replay without a recordable UI accepted a trace with window input")
            del ui_replay
        verified = run("--ttd-replay", ui_trace, "--ttd-verify-checkpoints", *emulator_args, sample)
        assert " differs " not in verified and " not reached" not in verified, verified
        # The CLI's replay scans deliver the recorded window input too, and run on recorded forks.
        ui_buffers = pathlib.Path(directory) / "ui-buffers.tsv"
        assert "TTD buffer scan verified" in run("--ttd-replay", ui_trace, "--ttd-buffers", str(ui_buffers), *emulator_args, sample)
        assert "TTD replay verified" in run("--ttd-replay", ui_trace, "--ttd-scan-selfmod", *emulator_args, sample)
        fork_strings = pathlib.Path(directory) / "fork-strings.tsv"
        run("--ttd-replay", fork_trace, "--ttd-strings", str(fork_strings), *emulator_args, sample)
        assert fork_strings.exists()
        stripped =str(pathlib.Path(directory) / "stripped.sogttd")
        shutil.copyfile(ui_trace, stripped)
        ttd_format.drop_section(stripped, ttd_format.UI_INPUTS)
        with ttd.Trace(stripped) as stripped_trace:
            try:
                # From the start: a seek to the end would restore a checkpoint taken after the input arrived.
                ttd.Replay(stripped_trace, ttd.create_emulator(sample, headless=True, **settings)).strings()
            except ttd.DivergenceError:
                pass
            else:
                raise AssertionError("A replay without the recorded window input did not diverge")

        # A Python recording replays in the CLI, every checkpoint interval reaching the recorded state.
        python_trace = str(pathlib.Path(directory) / "python.sogttd")
        with ttd.record(ttd.create_emulator(sample, **settings), python_trace, checkpoint_interval=100000) as recorded:
            assert recorded.instruction_count == len(list(recorded.events(kinds=ttd.EXECUTE)))
            checkpoints = len(recorded.checkpoints) - 1
        verified = run("--ttd-replay", python_trace, "--ttd-verify-checkpoints", *emulator_args, sample)
        assert verified.count(" matches ") == checkpoints, verified
        gc.collect()


if __name__ == "__main__":
    main()
