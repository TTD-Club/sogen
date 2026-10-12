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

        # Thread stacks: one per thread that ran, from its TEB, and its first instruction runs on that stack.
        stacks = trace.thread_stacks
        assert stacks and [stack.thread_id for stack in stacks] == list(dict.fromkeys(
            switch.thread_id for switch in trace.thread_switches)), (stacks, trace.thread_switches)
        for stack in stacks:
            assert stack.teb and stack.teb % 0x1000 == 0 and 0 < stack.stack_limit < stack.stack_base, stack
            assert stack.teb32 == stack.stack32_base == stack.stack32_limit == 0, stack
            rsp = trace.cpu_at(stack.position).read_register(registers.rsp)
            assert stack.stack_limit <= rsp <= stack.stack_base, (stack, hex(rsp))
        # Memory regions: the map at a position is the replayed emulator's own (what NtQueryVirtualMemory shows).
        mem_commit, mem_image, top = 0x1000, 0x1000000, 0x7FFFFFFF0000
        permission = sogen.MemoryPermission
        page_protections = {permission.none: 0x01, permission.read: 0x02, permission.read_write: 0x04, permission.exec: 0x01,
                            permission.read_exec: 0x20, permission.write: 0x01, permission.write_exec: 0x01,
                            permission.all: 0x40}
        assert trace.memory_regions and any(region.position > trace.start_position for region in trace.memory_regions)
        image = next(region for region in trace.memory_regions_at(trace.start_position) if region.allocation_base == ntdll.base)
        assert image.type == mem_image and image.name_index == 0xFFFFFFFF, image
        for position in (trace.start_position, trace.instruction_count // 2, trace.instruction_count - 1):
            emulator = ttd.create_emulator(sample, **settings)
            ttd.Replay(trace, emulator).seek(position)
            regions = trace.memory_regions_at(position)
            for region in regions:
                info = emulator.memory.get_region_info(region.address)
                assert info.start <= region.address and region.address + region.size <= info.start + info.length, (region, position)
                assert info.allocation_base == region.allocation_base and info.is_committed == (region.state == mem_commit), (
                    region, position)
                assert info.kind.value == region.kind, (region, position)
                if region.state == mem_commit:
                    expected = page_protections[info.permissions] | (0x100 if info.is_guarded else 0)
                    assert region.protection == expected, (region, info.permissions, position)
            address, covered = 0x10000, 0
            while address < top:
                info = emulator.memory.get_region_info(address)
                if info.is_reserved:
                    assert any(r.address <= address < r.address + r.size for r in regions), (hex(address), position)
                    covered += 1
                address = info.start + info.length
            assert covered and covered <= len(regions), (covered, len(regions))
            listed = run(analyzer.parent / "ttd-inspect.exe", path, "regions", str(position))
            assert len(listed.splitlines()) == len(regions) + 1, listed

            # memory_at knows every byte of committed memory (from accesses, else from the checkpoint), as replayed. The
            # bottom of the first thread's stack is never touched: only the checkpoint shows it.
            assert trace.has_checkpoint_memory
            bottom = stacks[0].stack_limit
            assert not trace.accesses(bottom, 0x100), position
            assert bytes(trace.memory_at(position, bottom, 0x100)) == emulator.memory.read_memory(bottom, 0x100), position
            # A code page executed throughout the trace reads from the checkpoint and the writes since, as replayed.
            hot = next(m.base + e.rva for m, e in trace.find_exports("ntdll.dll!RtlAllocateHeap") if e.forwarder is None) & ~0xFFF
            assert bytes(trace.memory_at(position, hot, 0x1000)) == emulator.memory.read_memory(hot, 0x1000), position
            committed = [region for region in regions if region.state == mem_commit and region.kind != 5]
            for region in random.sample(committed, min(25, len(committed))):
                size = min(region.size, 0x2000)
                shown = trace.memory_at(position, region.address, size)
                assert None not in shown, (region, position, shown.count(None))
                assert bytes(shown) == emulator.memory.read_memory(region.address, size), (region, position)

        listed = run(analyzer.parent / "ttd-inspect.exe", path, "stacks")
        assert len(listed.splitlines()) == len(stacks) + 1 and f"0x{stacks[0].teb:016x}" in listed, listed

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
