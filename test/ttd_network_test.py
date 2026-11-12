"""Record test-sample with the network live and check that the recording replays without it.

The host network answers when and how it pleases (DNS answers, ports, how bytes arrive), so a replay that asked it again
would depend on it. A recording keeps its answers (the network inputs section), so every checkpoint interval must
replay to the recorded state with the network offline.

Usage: ttd_network_test.py ANALYZER SAMPLE [EMULATOR_ARGS...]; SAMPLE is passed to the analyzer as given (test-sample,
a guest path such as c:/test-sample.exe when EMULATOR_ARGS selects a root with -e). The sample's file tests need
--root-mode rw, which this test passes.
"""

import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import ttd_format  # noqa: E402

CREATE_SOCKET, RESOLVE_HOST = 1, 4


def main() -> None:
    analyzer = pathlib.Path(sys.argv[1]).resolve()
    sample = sys.argv[2]
    emulator_args = [*sys.argv[3:], "--root-mode", "rw"]

    def run(*args: str) -> str:
        result = subprocess.run([str(analyzer), *args], capture_output=True, cwd=analyzer.parent, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise AssertionError(f"analyzer {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
        return result.stdout

    with tempfile.TemporaryDirectory() as directory:
        trace_path = str(pathlib.Path(directory) / "network.sogttd")
        run("-s", "--ttd-record", trace_path, "--network", "live", *emulator_args, sample)

        first_position, inputs = ttd_format.Trace(trace_path).network_inputs
        calls = {network_input.call for network_input in inputs}
        assert CREATE_SOCKET in calls and RESOLVE_HOST in calls, f"no sockets or DNS lookups recorded: {sorted(calls)}"
        assert first_position == 0, first_position

        output = run("-s", "--ttd-replay", trace_path, "--ttd-verify-checkpoints", "--network", "offline", *emulator_args, sample)
        results = [line for line in output.splitlines() if line.startswith("TTD checkpoint ")]
        assert len(results) > 1, output
        differing = [line for line in results if " matches " not in line]
        assert not differing, "\n".join(differing)

    print(f"ttd_network_test: {len(inputs)} network inputs, {len(results)} intervals replayed offline")


if __name__ == "__main__":
    main()
