"""Check the sogen.ttd Python bindings against ttd-step-sample, across the CLI and Python.

Usage: ttd_python_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]. The sogen module is imported from the analyzer's
directory. SAMPLE is a host path (host mode), or a guest path when EMULATOR_ARGS is `-e ROOT`.
"""

import gc
import pathlib
import re
import subprocess
import sys
import tempfile

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
