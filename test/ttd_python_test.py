"""Check the sogen.ttd Python bindings against ttd-step-sample, across the CLI and Python.

Usage: ttd_python_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]. The sogen module is imported from the analyzer's
directory. SAMPLE is a host path (host mode), or a guest path when EMULATOR_ARGS is `-e ROOT`.
"""

import gc
import pathlib
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
        del replay, emulator
        trace.close()

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
