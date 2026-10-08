"""Record ttd-step-sample and check the step definition from docs/ttd-poc.md against a real trace.

Usage: ttd_step_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]; SAMPLE is passed to the analyzer as given, so it is a
guest path such as c:/ttd-step-sample.exe when EMULATOR_ARGS selects a root with -e.
"""

import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import ttd_format  # noqa: E402

OLD_VALUE = 0x1111111111111111
NEW_VALUE = 0x2222222222222222


def main() -> None:
    analyzer = pathlib.Path(sys.argv[1]).resolve()
    sample = sys.argv[2]
    emulator_args = sys.argv[3:]

    def run(*args: str) -> str:
        result = subprocess.run([str(analyzer), *args], text=True, capture_output=True, cwd=analyzer.parent)
        if result.returncode != 0:
            raise AssertionError(f"analyzer {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
        return result.stdout

    with tempfile.TemporaryDirectory() as directory:
        trace = str(pathlib.Path(directory) / "step.sogttd")
        recording = run("--ttd-record", trace, "--ttd-checkpoint-interval", "100000", *emulator_args, sample)
        address = int(re.search(r"ttd-value ([0-9A-Fa-f]+)", recording).group(1), 16)
        assert "ttd-rdrand 0" in recording, "TTD recordings must not advertise RDRAND"

        def query(access: str, start: int, size: int) -> list[tuple[int, int]]:
            output = run("--ttd-query", trace, "--ttd-access", access, "--ttd-address", hex(start), "--ttd-size", str(size))
            return [(int(step, 16), int(ip, 16)) for step, ip in re.findall(r"^([0-9a-f]+):0 ip=([0-9a-f]+)", output, re.M)]

        writes = query("write", address, 8)
        reads = query("read", address, 8)
        assert len(writes) == 1, writes
        assert len(reads) == 1, reads
        write_step, write_ip = writes[0]
        read_step, read_ip = reads[0]
        assert write_step < read_step

        # An instruction's execute event and its memory accesses share one step.
        assert (write_step, write_ip) in query("execute", write_ip, 1)
        assert (read_step, read_ip) in query("execute", read_ip, 1)

        def seek(position: int) -> tuple[int, int]:
            output = run("--ttd-replay", trace, "--ttd-seek", hex(position), "--ttd-read", hex(address), *emulator_args,
                         sample)
            rip = int(re.search(r"TTD position [0-9a-f]+:0 RIP ([0-9a-f]+)", output).group(1), 16)
            value = int(re.search(r"TTD memory [0-9a-f]+ = ([0-9a-f]+)", output).group(1), 16)
            return rip, value

        # Position N is the state after instruction N: the store at step N is visible at N and not at N-1.
        assert seek(write_step - 1) == (write_ip, OLD_VALUE)
        rip, value = seek(write_step)
        assert rip != write_ip
        assert value == NEW_VALUE

        recorded = ttd_format.Trace(trace)
        checkpoint_count = len(recorded.checkpoints) - 1
        assert checkpoint_count > 0

        # Every position is one executed instruction: no counter values without an execute event.
        expected_step = 1
        for index in range(len(recorded.chunks)):
            steps, kinds = recorded.steps_and_kinds(index)
            for step, kind in zip(steps, kinds):
                if kind == ttd_format.EXECUTE:
                    assert step == expected_step, (step, expected_step)
                    expected_step += 1
        assert expected_step == recorded.instruction_count + 1

        # Replaying each checkpoint interval from the previous checkpoint must reach exactly the recorded state.
        verified = run("--ttd-replay", trace, "--ttd-verify-checkpoints", *emulator_args, sample)
        assert verified.count(" matches ") == checkpoint_count, verified

        store_chunk = next(index for index, (_, _, first, last, _, _) in enumerate(recorded.chunks) if first <= write_step <= last)
        chunk_events = recorded.chunk_events(store_chunk)
        store = next(event for event in chunk_events
                     if (event.step, event.address, event.kind) == (write_step, address, ttd_format.WRITE))
        assert store.data == NEW_VALUE.to_bytes(8, "little")

        def seek_tampered(field: str, value, failure: str) -> None:
            tampered = pathlib.Path(directory) / "tampered.sogttd"
            tampered.write_bytes(pathlib.Path(trace).read_bytes())
            original = getattr(store, field)
            setattr(store, field, value)
            ttd_format.replace_chunk(str(tampered), store_chunk, chunk_events)
            setattr(store, field, original)
            result = subprocess.run([str(analyzer), "--ttd-replay", str(tampered), "--ttd-seek", hex(write_step), *emulator_args,
                                     sample], text=True, capture_output=True, cwd=analyzer.parent)
            assert result.returncode != 0
            assert failure in result.stdout + result.stderr, result.stdout + result.stderr

        seek_tampered("address", address + 8, "TTD replay diverged from the recording")
        seek_tampered("data", (0x3333333333333333).to_bytes(8, "little"), "accessed different data")

        history = run("--ttd-history", trace, "--ttd-address", hex(address), "--ttd-size", "8").splitlines()
        assert f"{write_step:x}:0 ip={write_ip:x} kind=write address={address:x} size=8 data=2222222222222222 " \
               f"value=2222222222222222" in history, history
        assert any(line.startswith(f"{read_step:x}:0 ip={read_ip:x} kind=read") and line.endswith("value=2222222222222222")
                   for line in history), history

        # VirtualQuery's output is written by the emulated NtQueryVirtualMemory, not by a guest store.
        info = int(re.search(r"ttd-info ([0-9A-Fa-f]+)", recording).group(1), 16)
        output = run("--ttd-query", trace, "--ttd-address", hex(info), "--ttd-size", "48")
        host_writes = re.findall(r"^([0-9a-f]+):0 ip=[0-9a-f]+ address=[0-9a-f]+ size=\d+ kind=host-write data=[0-9a-f.]+$",
                                 output, re.M)
        assert host_writes, output
        host_step = int(host_writes[0], 16)
        assert host_step > read_step
        run("--ttd-replay", trace, "--ttd-seek", hex(host_step), *emulator_args, sample)

        # The generated function is the only code the sample writes before executing it.
        code = int(re.search(r"ttd-code ([0-9A-Fa-f]+)", recording).group(1), 16)
        offline = run("--ttd-first-selfmod", trace, "--ttd-address", hex(code), "--ttd-size", "0x1000")
        hit = re.fullmatch(r"address=([0-9a-f]+) size=5 write=([0-9a-f]+):0 write_ip=[0-9a-f]+ execute=([0-9a-f]+):0 "
                           r"execute_ip=([0-9a-f]+)\n", offline)
        assert hit, offline
        assert int(hit.group(1), 16) == code and int(hit.group(4), 16) == code
        assert host_step < int(hit.group(2), 16) < int(hit.group(3), 16)
        replayed = run("--ttd-replay", trace, "--ttd-scan-selfmod", *emulator_args, sample)
        assert f"address={code:x} size=5 write={hit.group(2)}:0" in replayed, replayed

        # The backend cannot decode ud2; its execute event still carries the real length and bytes.
        illegal = int(re.search(r"ttd-ud2 ([0-9A-Fa-f]+)", recording).group(1), 16)
        executes = run("--ttd-query", trace, "--ttd-access", "execute", "--ttd-address", hex(illegal), "--ttd-size", "2")
        assert re.fullmatch(rf"[0-9a-f]+:0 ip={illegal:x} address={illegal:x} size=2 kind=execute bytes=0f0b\n", executes), executes

        # The sample builds this string in writable memory and wipes it again; only the replay sees it.
        strings = pathlib.Path(directory) / "strings.tsv"
        run("--ttd-replay", trace, "--ttd-strings", str(strings), *emulator_args, sample)
        transient = [row.split("\t") for row in strings.read_text().splitlines()[1:]
                     if "SOGEN_TTD_TRANSIENT_STRING_FOR_RECOVERY" in row]
        assert any(int(step, 16) > 0 for _, step, _, _ in transient), transient

        buffers = pathlib.Path(directory) / "buffers.tsv"
        summary = run("--ttd-replay", trace, "--ttd-buffers", str(buffers), *emulator_args, sample)
        assert re.search(r"TTD buffer scan verified \d+ writes", summary), summary
        assert buffers.read_text().startswith("address\tsize\tfirst_step")


if __name__ == "__main__":
    main()
