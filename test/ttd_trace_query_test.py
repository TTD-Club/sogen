"""Exercise the analyzer's persisted write index without a Windows root."""

import pathlib
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import ttd_format  # noqa: E402


def index_postings(events: list[tuple[int, int, int, int, int]]) -> list[tuple[int, int, int]]:
    """Build (page, event_number, kind) index entries in the recorder's (page, kind, event_number) order."""
    postings = {(page, number, kind)
                for number, (_, _, address, size, kind) in enumerate(events)
                for page in range(address // 4096, (address + size - 1) // 4096 + 1)}
    return sorted(postings, key=lambda posting: (posting[0], posting[2], posting[1]))


def main() -> None:
    analyzer = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as directory:
        trace = pathlib.Path(directory) / "fixture.sogttd"
        writes = [(1, 0x401000, 0x1FFE, 4), (3, 0x401004, 0x3000, 2), (5, 0x401008, 0x1FFF, 1)]
        # The first write straddles pages 1 and 2. Page index order deliberately
        # differs from event order; address queries must deduplicate and sort.
        index = sorted([(1, 0), (2, 0), (3, 1), (1, 2)])
        with trace.open("wb") as file:
            file.write(struct.pack("<8s5Q", b"SOGTTD1\0", 0, 5, len(writes), 48 + 32 * len(writes), len(index)))
            for write in writes:
                file.write(struct.pack("<4Q", *write))
            for entry in index:
                file.write(struct.pack("<2Q", *entry))

        def query(*args: str) -> list[str]:
            result = subprocess.run([str(analyzer), "--ttd-query", str(trace), *args],
                                    text=True, capture_output=True, check=True)
            return result.stdout.splitlines()

        assert query("--ttd-address", "8190", "--ttd-size", "4") == [
            "1:0 ip=401000 address=1ffe size=4", "5:0 ip=401008 address=1fff size=1"
        ]
        assert query("--ttd-address", "8190", "--ttd-size", "4", "--ttd-from", "2", "--ttd-to", "4") == []
        assert query("--ttd-address", "12288") == ["3:0 ip=401004 address=3000 size=2"]
        assert query("--ttd-address", "8190", "--ttd-size", "4", "--ttd-from", "1", "--ttd-next-write") == [
            "5:0 ip=401008 address=1fff size=1"
        ]
        assert query("--ttd-address", "8190", "--ttd-size", "4", "--ttd-from", "5", "--ttd-prev-write") == [
            "1:0 ip=401000 address=1ffe size=4"
        ]
        trace.write_bytes(trace.read_bytes()[:-1])
        invalid = subprocess.run([str(analyzer), "--ttd-query", str(trace)], text=True, capture_output=True)
        assert invalid.returncode != 0
        assert "Invalid TTD trace offsets" in invalid.stdout

        mixed = pathlib.Path(directory) / "mixed.sogttd"
        events = [
            (1, 0x401000, 0x401000, 3, 4),
            (2, 0x401003, 0x2FFE, 4, 1),
            (3, 0x401006, 0x3000, 2, 2),
            (4, 0x401008, 0x3000, 2, 1),
        ]
        # Entries are sorted by page, kind, then event number.
        postings = sorted([(0x401, 0, 4), (2, 1, 1), (3, 1, 1),
                           (3, 2, 2), (3, 3, 1)], key=lambda e: (e[0], e[2], e[1]))
        index_offset = 64 + 40 * len(events)
        with mixed.open("wb") as file:
            file.write(struct.pack("<8s7Q", b"SOGTTD3\0", 0, 4, len(events), 0,
                                   index_offset, index_offset, len(postings)))
            for event in events:
                file.write(struct.pack("<5Q", *event))
            for posting in postings:
                file.write(struct.pack("<3Q", *posting))

        def mixed_query(*args: str) -> list[str]:
            result = subprocess.run([str(analyzer), "--ttd-query", str(mixed), *args],
                                    text=True, capture_output=True, check=True)
            return result.stdout.splitlines()

        assert mixed_query("--ttd-access", "read", "--ttd-address", "0x3000") == [
            "2:0 ip=401003 address=2ffe size=4 kind=read",
            "4:0 ip=401008 address=3000 size=2 kind=read",
        ]
        assert mixed_query("--ttd-access", "write", "--ttd-address", "0x3000") == [
            "3:0 ip=401006 address=3000 size=2"
        ]
        assert mixed_query("--ttd-access", "execute", "--ttd-address", "0x401001") == [
            "1:0 ip=401000 address=401000 size=3 kind=execute"
        ]
        assert mixed_query("--ttd-access", "all", "--ttd-address", "0x3000",
                           "--ttd-from", "2", "--ttd-to", "3") == [
            "2:0 ip=401003 address=2ffe size=4 kind=read",
            "3:0 ip=401006 address=3000 size=2 kind=write",
        ]

        modified = pathlib.Path(directory) / "modified.sogttd"
        code_events = [
            (1, 0x7000, 0x5000, 3, 4),
            (2, 0x7001, 0x5001, 2, 2),
            (3, 0x5000, 0x5000, 3, 4),
            (4, 0x7002, 0x6000, 1, 2),
            (5, 0x6001, 0x6001, 1, 4),
            (6, 0x7003, 0x4000, 1, 2),
            (7, 0x4000, 0x4000, 1, 4),
        ]
        end = 64 + 40 * len(code_events)
        code_postings = index_postings(code_events)
        with modified.open("wb") as file:
            file.write(struct.pack("<8s7Q", b"SOGTTD3\0", 0, 7, len(code_events), 0, end, end, len(code_postings)))
            for event in code_events:
                file.write(struct.pack("<5Q", *event))
            for posting in code_postings:
                file.write(struct.pack("<3Q", *posting))
        found = subprocess.run([str(analyzer), "--ttd-selfmod", str(modified)],
                               text=True, capture_output=True, check=True).stdout.splitlines()
        assert found == [
            "address=4000 size=1 write=6:0 write_ip=7003 execute=7:0 execute_ip=4000 count=1",
            "address=5000 size=3 write=2:0 write_ip=7001 execute=3:0 execute_ip=5000 count=1",
        ]
        global_first = subprocess.run([str(analyzer), "--ttd-first-selfmod", str(modified)],
                                      text=True, capture_output=True, check=True).stdout.splitlines()
        assert global_first == ["address=5000 size=3 write=2:0 write_ip=7001 execute=3:0 execute_ip=5000"]
        first = subprocess.run([str(analyzer), "--ttd-first-selfmod", str(modified),
                                "--ttd-address", "0x4000", "--ttd-size", "0x2000"],
                               text=True, capture_output=True, check=True).stdout.splitlines()
        assert first == ["address=5000 size=3 write=2:0 write_ip=7001 execute=3:0 execute_ip=5000"]
        restricted = subprocess.run([str(analyzer), "--ttd-first-selfmod", str(modified),
                                     "--ttd-address", "0x4000"],
                                    text=True, capture_output=True, check=True).stdout.splitlines()
        assert restricted == ["address=4000 size=1 write=6:0 write_ip=7003 execute=7:0 execute_ip=4000"]

        heap_trace = pathlib.Path(directory) / "heap.sogttd"
        heap_events = [
            (1, 0x401000, 0x70000000, 4, 2),
            (2, 0x70000000, 0x70000000, 2, 4),
        ]
        heap_end = 64 + 40 * len(heap_events)
        heap_postings = index_postings(heap_events)
        with heap_trace.open("wb") as file:
            file.write(struct.pack("<8s7Q", b"SOGTTD3\0", 0, 2, len(heap_events), 0, heap_end, heap_end, len(heap_postings)))
            for event in heap_events:
                file.write(struct.pack("<5Q", *event))
            for posting in heap_postings:
                file.write(struct.pack("<3Q", *posting))
        heap_first = subprocess.run([str(analyzer), "--ttd-first-selfmod", str(heap_trace)],
                                    text=True, capture_output=True, check=True).stdout.splitlines()
        assert heap_first == ["address=70000000 size=2 write=1:0 write_ip=401000 execute=2:0 execute_ip=70000000"]

        # The recorder writes this header before the first event and only fills in the offsets when it finishes.
        interrupted = pathlib.Path(directory) / "interrupted.sogttd"
        with interrupted.open("wb") as file:
            file.write(struct.pack("<8s7Q", b"SOGTTD4\0", 0, 0, 0, 0, 0, 0, 0))
            file.write(struct.pack("<5Q16s", 1, 0x401000, 0x401000, 3, 4, b""))
        result = subprocess.run([str(analyzer), "--ttd-query", str(interrupted)], text=True, capture_output=True)
        assert result.returncode != 0
        assert "TTD trace was not finalized" in result.stdout

        # The bulk block filter must round-trip, including a rejected call whose displacement holds the start of a
        # converted `call [rip+disp32]`.
        filtered = pathlib.Path(directory) / "filtered.sogttd"
        contents = [
            bytes.fromhex("e848ff1513f8060090909090909090909090909090909090"),
            bytes.fromhex("e810000000e9f0ffffff4c8d0dfcffffffff2500010000cc"),
            bytes.fromhex("488b0500000080488905ffffff00909090909090e8000000"),
        ]
        joined = b"".join(contents)
        assert ttd_format.convert_displacements(joined, True) != joined
        host_writes = [(1, 0x401000, 0x10000 + 0x100 * i, len(data), ttd_format.HOST_WRITE, data)
                       for i, data in enumerate(contents)]
        ttd_format.write_trace(str(filtered), host_writes, instruction_count=1)
        assert [event.data for event in ttd_format.Trace(str(filtered)).events()] == contents


if __name__ == "__main__":
    main()
