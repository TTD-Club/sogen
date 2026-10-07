"""Small v4 and v7 fixtures for instruction bytes and replay-derived taint flow."""

import pathlib
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import ttd_format  # noqa: E402


def main():
    analyzer = pathlib.Path(sys.argv[1])
    taint_tool = pathlib.Path(__file__).resolve().parents[1] / "tools/ttd_taint.py"
    with tempfile.TemporaryDirectory() as directory:
        trace = pathlib.Path(directory) / "taint.sogttd"
        load = bytes.fromhex("a00020000000000000")  # movabs al, byte ptr [0x2000]
        store = bytes.fromhex("a20030000000000000")  # movabs byte ptr [0x3000], al
        events = [
            (1, 0x1000, 0x1000, len(load), 4, load),
            (1, 0x1000, 0x2000, 1, 1, b""),
            (2, 0x1009, 0x1009, len(store), 4, store),
            (2, 0x1009, 0x3000, 1, 2, b""),
        ]
        end = 64 + 56 * len(events)
        postings = [(1, 0, 4), (1, 2, 4), (2, 1, 1), (3, 3, 2)]
        with trace.open("wb") as file:
            file.write(struct.pack("<8s7Q", b"SOGTTD4\0", 0, 2, len(events), 0, end, end, len(postings)))
            for step, ip, address, size, kind, code in events:
                file.write(struct.pack("<5Q16s", step, ip, address, size, kind, code))
            for posting in postings:
                file.write(struct.pack("<3Q", *posting))
        result = subprocess.run([str(analyzer), "--ttd-query", str(trace), "--ttd-access", "execute",
                                 "--ttd-address", "0x1000", "--ttd-size", "0x20"],
                                text=True, capture_output=True, check=True)
        assert "bytes=a00020000000000000" in result.stdout
        assert "bytes=a20030000000000000" in result.stdout
        result = subprocess.run([sys.executable, str(taint_tool), str(trace), "--taint", "input:0x2000:1",
                                 "--register", "rax"], text=True, capture_output=True, check=True)
        assert "taint=input step=2 ip=1009 memory=3000" in result.stdout
        assert "register=rax last_read=2:0 ip=1009" in result.stdout
        assert "register=rax last_write=1:0 ip=1000" in result.stdout
        late = subprocess.run([sys.executable, str(taint_tool), str(trace), "--taint", "input:0x2000:1:2"],
                              text=True, capture_output=True, check=True)
        assert "tainted_memory_writes=0" in late.stdout

        overwritten = pathlib.Path(directory) / "overwritten.sogttd"
        reload = bytes.fromhex("a00030000000000000")  # movabs al, byte ptr [0x3000]
        spill = bytes.fromhex("a20040000000000000")  # movabs byte ptr [0x4000], al
        events = [
            (1, 0x1000, 0x1000, len(load), 4, load),
            (1, 0x1000, 0x2000, 1, 1, b""),
            (2, 0x1009, 0x1009, len(store), 4, store),
            (2, 0x1009, 0x3000, 1, 2, b""),
            (2, 0x1009, 0x3000, 1, 8, b""),
            (3, 0x1012, 0x1012, len(reload), 4, reload),
            (3, 0x1012, 0x3000, 1, 1, b""),
            (4, 0x101b, 0x101b, len(spill), 4, spill),
            (4, 0x101b, 0x4000, 1, 2, b""),
        ]
        ttd_format.write_trace(str(overwritten), events, instruction_count=4)
        result = subprocess.run([sys.executable, str(taint_tool), str(overwritten), "--taint", "input:0x2000:1"],
                                text=True, capture_output=True, check=True)
        assert "memory=3000" in result.stdout
        assert "memory=4000" not in result.stdout
        assert "tainted_memory_writes=1" in result.stdout


if __name__ == "__main__":
    main()
