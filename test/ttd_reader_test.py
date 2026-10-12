"""Check the reader-side queries (trace ids, calls_to, indirect_branches, exceptions, module machines) and the
cancellation of long operations, against cpu_at and against a reader-only build (ttd-inspect).

Usage: ttd_reader_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]. SAMPLE should raise hardware exceptions (test-sample
does); it is a host path (host mode), or a guest path when EMULATOR_ARGS is `-e ROOT`. The sogen module is imported
from the analyzer's directory.
"""

import gc
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import time


def main() -> None:
    analyzer = pathlib.Path(sys.argv[1]).resolve()
    sample = sys.argv[2]
    emulator_args = sys.argv[3:]
    sys.path.insert(0, str(analyzer.parent))
    import sogen  # noqa: E402
    from sogen import ttd  # noqa: E402

    registers = sogen.Register
    settings = {"registry_directory": str(analyzer.parent / "registry"), "disable_logging": True}
    if emulator_args[:1] == ["-e"]:
        settings["emulation_root"] = emulator_args[1]

    def run(executable: pathlib.Path, *args: str) -> str:
        result = subprocess.run([str(executable), *args], text=True, capture_output=True, cwd=analyzer.parent)
        if result.returncode != 0:
            raise AssertionError(f"{executable.name} {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
        return result.stdout

    random.seed(7)
    with tempfile.TemporaryDirectory() as directory:
        path = str(pathlib.Path(directory) / "reader.sogttd")
        run(analyzer, "--ttd-record", path, *emulator_args, sample)

        # Ids: random per recording, kept by copies, and a file's version is readable without opening it.
        trace = ttd.Trace(path)
        assert len(trace.id) == 32 and trace.manifest["trace_id"] == trace.id
        copy = str(pathlib.Path(directory) / "copy.sogttd")
        shutil.copy(path, copy)
        assert ttd.Trace(copy).id == trace.id
        assert ttd.trace_file_version(path) == trace.version == 8 and ttd.is_supported_trace_version(8)
        assert ttd.trace_file_version(str(analyzer)) is None and not ttd.is_supported_trace_version(6)

        # The reader-only inspector agrees.
        inspected = run(analyzer.parent / "ttd-inspect.exe", path)
        assert f"id            {trace.id}" in inspected, inspected

        # Module machines: x64 modules say so.
        ntdll = next(module for module in trace.modules if module.name.lower() == "ntdll.dll")
        assert ntdll.machine == 0x8664, hex(ntdll.machine)

        # calls_to: every entry calls() finds, the call before it, and the matching return; checked against cpu_at.
        name = "ntdll.dll!RtlAllocateHeap"
        target = next(m.base + e.rva for m, e in trace.find_exports(name) if e.forwarder is None)
        calls = trace.calls_to(target)
        assert [call.entry_position for call in calls] == [event.position for event in trace.calls(name)]
        returned = [call for call in calls if call.return_position is not None]
        assert returned and len(returned) == len([call for call in calls if call.is_call]), (len(returned), len(calls))
        for call in random.sample(returned, min(20, len(returned))):
            assert trace.cpu_at(call.position - 1).read_register(registers.rip) == call.site, call
            entered = trace.cpu_at(call.position)
            assert entered.read_register(registers.rip) == call.target, call
            left = trace.cpu_at(call.return_position)
            assert left.read_register(registers.rsp) == entered.read_register(registers.rsp) + 8, call
            assert 2 <= left.read_register(registers.rip) - call.site <= 7, call

        # indirect_branches: each edge's first execution lands on its target.
        branches = trace.indirect_branches([(module.base, module.size) for module in trace.modules], jumps=True)
        assert branches and any(branch.is_call for branch in branches) and any(not branch.is_call for branch in branches)
        for branch in random.sample(branches, min(30, len(branches))):
            assert trace.cpu_at(branch.first_position).read_register(registers.rip) == branch.target, branch

        # exceptions: test-sample's access violation, breakpoint, and single step, raised where the record says.
        exceptions = trace.exceptions()
        codes = {exception.code for exception in exceptions}
        assert {0xC0000005, 0x80000003, 0x80000004} <= codes, [hex(code) for code in codes]
        for exception in exceptions:
            assert exception.raise_position is not None, exception
            if exception.code == 0xC0000005:
                assert trace.cpu_at(exception.raise_position - 1).read_register(registers.rip) == exception.address, exception

        # Cancellation and progress of a long operation.
        reports = []
        trace = ttd.Trace(path)
        trace.prepare_seeks([ttd.create_emulator(sample, **settings) for _ in range(2)],
                            progress=lambda done, total: reports.append((done, total)))
        assert reports and reports[-1][0] == reports[-1][1] == trace.instruction_count - trace.start_position
        assert all(a[0] <= b[0] for a, b in zip(reports, reports[1:]))
        trace = ttd.Trace(path)
        start = time.perf_counter()
        try:
            trace.prepare_seeks([ttd.create_emulator(sample, **settings) for _ in range(2)],
                                interrupted=lambda: time.perf_counter() - start > 0.5)
            raise AssertionError("prepare_seeks was not cancelled")
        except ttd.OperationCancelled:
            pass
        replay = ttd.Replay(trace, ttd.create_emulator(sample, **settings))
        replay.seek(trace.instruction_count // 2)

        # The trace files stay open while anything references them.
        del replay, trace
        gc.collect()

    print("TTD reader test passed")


if __name__ == "__main__":
    main()
