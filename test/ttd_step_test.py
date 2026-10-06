"""Record ttd-step-sample and check the step definition from docs/ttd-poc.md against a real trace.

Usage: ttd_step_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]; SAMPLE is passed to the analyzer as given, so it is a
guest path such as c:/ttd-step-sample.exe when EMULATOR_ARGS selects a root with -e.
"""

import pathlib
import re
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


if __name__ == "__main__":
    main()
