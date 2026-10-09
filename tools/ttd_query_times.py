"""Times memory queries on a Sogen TTD trace of test-sample, mirroring tools/msttd_query_times.js.

Usage: ttd_query_times.py ARTIFACTS TRACE [--prepare N]. ARTIFACTS is the build's artifacts directory (sogen module,
test-sample.exe, registry). Targets are located from the main image's PE headers: its entry point, first IAT slot,
.data start, the most accessed qword of .data, and ntdll!RtlAllocateHeap.
"""

import argparse
import pathlib
import random
import sys
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts")
    parser.add_argument("trace")
    parser.add_argument("--prepare", type=int, default=0)
    parser.add_argument("--values", type=int, default=20)
    options = parser.parse_args()
    artifacts = pathlib.Path(options.artifacts)
    sys.path.insert(0, str(artifacts))
    from sogen import ttd  # noqa: E402

    settings = {"registry_directory": str(artifacts / "registry"), "disable_logging": True}
    sample = str(artifacts / "test-sample.exe")

    def timed(action):
        start = time.perf_counter()
        result = action()
        return (time.perf_counter() - start) * 1000, result

    trace = ttd.Trace(options.trace)
    emulator = ttd.create_emulator(sample, headless=True, **settings)
    replay = ttd.Replay(trace, emulator)
    end = trace.instruction_count
    if options.prepare:
        ms, _ = timed(lambda: trace.prepare_seeks([ttd.create_emulator(sample, headless=True, **settings)
                                                    for _ in range(options.prepare)]))
        print(f"PREPARE {options.prepare} emulators: {ms:.0f} ms")

    image = next(module for module in trace.modules if module.name.lower() == "test-sample.exe")
    replay.seek(end // 2)

    def read(address, size):
        return int.from_bytes(emulator.read_memory(address, size), "little")

    base = image.base
    header = base + read(base + 0x3C, 4)
    optional = header + 24
    sections = optional + read(header + 20, 2)
    entry = base + read(optional + 16, 4)
    iat = base + read(optional + 112 + 12 * 8, 4)
    data = data_size = 0
    for index in range(read(header + 6, 2)):
        section = sections + index * 40
        if bytes(emulator.read_memory(section, 5)) == b".data":
            data, data_size = base + read(section + 12, 4), read(section + 8, 4)

    ms, accesses = timed(lambda: trace.accesses(data, data_size, kinds=ttd.READ | ttd.WRITE))
    counts = {}
    for access in accesses:
        counts[access.address // 8 * 8] = counts.get(access.address // 8 * 8, 0) + 1
    hot = max(counts, key=counts.get)
    print(f"QUERY .data range ({data_size} bytes) rw: {len(accesses)} accesses in {ms:.0f} ms")
    module, export = trace.find_exports("ntdll!RtlAllocateHeap")[0]
    heap = module.base + export.rva
    print(f"TARGETS base {base:x} entry {entry:x} iat {iat:x} data {data:x} hot {hot:x} RtlAllocateHeap {heap:x}")

    kinds = {"r": ttd.READ, "w": ttd.WRITE, "e": ttd.EXECUTE}
    targets = [("entry", entry, "e"), ("RtlAllocateHeap", heap, "e"), ("iat", iat, "rw"), ("data", data, "rw"), ("hot", hot, "rw")]
    for label, address, watched in targets:
        ms, found = timed(lambda: trace.accesses(address, 8, kinds=ttd.READ | ttd.WRITE | ttd.EXECUTE))
        print(f"QUERY {label} rwe: {len(found)} accesses in {ms:.0f} ms")
        for kind in watched:
            size = 1 if kind == "e" else 8
            for direction, query in (("forward", lambda: trace.next_access(address, size, position=0, kinds=kinds[kind])),
                                     ("backward", lambda: trace.previous_access(address, size, position=end, kinds=kinds[kind]))):
                ms, hit = timed(query)
                seek_ms = timed(lambda: replay.seek(hit.position))[0] if hit else 0
                where = f"hit at {hit.position}" if hit else "no hit"
                print(f"WATCH {label} {kind} {direction}: {ms:.0f} ms + {seek_ms:.0f} ms seek to it, {where}")

    rng = random.Random(1)
    for label, address in (("iat", iat), ("data", data), ("hot", hot)):
        positions = [rng.randrange(1, end + 1) for _ in range(options.values)]
        seek_total = read_total = offline_total = 0.0
        for position in positions:
            seek_total += timed(lambda: replay.seek(position))[0]
            read_ms, value = timed(lambda: read(address, 8))
            read_total += read_ms
            offline_ms, history = timed(lambda: trace.history(address, 8, end=position))
            offline_total += offline_ms
            known = history[-1].value if history else []
            if all(byte is not None for byte in known) and len(known) == 8:
                assert int.from_bytes(bytes(known), "little") == value, (label, position)
        count = options.values
        print(f"VALUE {label}: seek {seek_total / count:.1f} ms + read {read_total / count:.1f} ms; "
              f"offline from history {offline_total / count:.1f} ms on average (n={count})")


if __name__ == "__main__":
    main()
