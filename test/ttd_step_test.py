"""Record ttd-step-sample and check the step definition from docs/ttd-poc.md against a real trace.

Usage: ttd_step_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]; SAMPLE is passed to the analyzer as given, so it is a
guest path such as c:/ttd-step-sample.exe when EMULATOR_ARGS selects a root with -e.
"""

import pathlib
import re
import struct
import subprocess
import sys
import tempfile

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

        data = bytearray(pathlib.Path(trace).read_bytes())
        magic, snapshot_size, _, event_count, checkpoint_count = struct.unpack_from("<8s4Q", data)
        assert magic == b"SOGTTD5\0"
        assert checkpoint_count > 0

        # Replaying each checkpoint interval from the previous checkpoint must reach exactly the recorded state.
        verified = run("--ttd-replay", trace, "--ttd-verify-checkpoints", *emulator_args, sample)
        assert verified.count(" matches ") == checkpoint_count, verified
        start = 72 + snapshot_size
        for offset in range(start, start + event_count * 56, 56):
            step, _, event_address, _, kind = struct.unpack_from("<5Q", data, offset)
            if step == write_step and kind == 2 and event_address == address:
                struct.pack_into("<Q", data, offset + 16, address + 8)
                break
        else:
            raise AssertionError("recorded store not found in the event stream")
        tampered = pathlib.Path(directory) / "tampered.sogttd"
        tampered.write_bytes(data)
        result = subprocess.run([str(analyzer), "--ttd-replay", str(tampered), "--ttd-seek", hex(write_step), *emulator_args,
                                 sample], text=True, capture_output=True, cwd=analyzer.parent)
        assert result.returncode != 0
        assert "TTD replay diverged from the recording" in result.stdout + result.stderr

        # VirtualQuery's output is written by the emulated NtQueryVirtualMemory, not by a guest store.
        info = int(re.search(r"ttd-info ([0-9A-Fa-f]+)", recording).group(1), 16)
        output = run("--ttd-query", trace, "--ttd-address", hex(info), "--ttd-size", "48")
        host_writes = re.findall(r"^([0-9a-f]+):0 ip=[0-9a-f]+ address=[0-9a-f]+ size=\d+ kind=host-write$", output, re.M)
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
