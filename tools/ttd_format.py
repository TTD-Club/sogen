"""Reader and writer for Sogen TTD traces, format v6 (see docs/ttd-poc.md). Requires the zstandard package."""

import itertools
import struct

import zstandard

HEADER = struct.Struct("<8s5Q")
SECTION = struct.Struct("<3Q")
CHUNK = struct.Struct("<6Q")
CHECKPOINT = struct.Struct("<4Q")
PAGE = struct.Struct("<QII")
CHUNK_HEADER = struct.Struct("<2Q")
MAGIC = b"SOGTTD6\0"
CHUNK_TABLE, CHECKPOINT_TABLE, PAGE_INDEX = 1, 2, 3
READ, WRITE, EXECUTE, HOST_WRITE = 1, 2, 4, 8
MASK64 = (1 << 64) - 1
INLINE_DATA_LIMIT = 16


class Event:
    __slots__ = ("number", "step", "ip", "address", "size", "kind", "payload", "data")

    def __init__(self, number, step, ip, address, size, kind, payload, data):
        self.number, self.step, self.ip, self.address = number, step, ip, address
        self.size, self.kind, self.payload, self.data = size, kind, payload, data

    @property
    def instruction(self):
        return self.payload[:self.size] if self.kind == EXECUTE and self.size < INLINE_DATA_LIMIT else b""


def decode_chunk(compressed, first_number=0):
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    count, blob_size = CHUNK_HEADER.unpack_from(raw)
    offset = CHUNK_HEADER.size

    def column(fmt):
        nonlocal offset
        values = struct.unpack_from(f"<{count}{fmt}", raw, offset)
        offset += struct.calcsize(f"<{count}{fmt}")
        return values

    steps, ips, addresses, sizes, kinds = column("Q"), column("Q"), column("Q"), column("Q"), column("B")
    payloads = [raw[offset + 16 * i:offset + 16 * (i + 1)] for i in range(count)]
    blob = raw[offset + 16 * count:]
    assert len(blob) == blob_size, "invalid chunk"
    step = ip = 0
    events = []
    for i in range(count):
        step = (step + steps[i]) & MASK64
        ip = (ip + ips[i]) & MASK64
        address = (ip + addresses[i]) & MASK64
        size, kind, payload = sizes[i], kinds[i], payloads[i]
        if kind == EXECUTE:
            data = b""
        elif size <= INLINE_DATA_LIMIT:
            data = payload[:size]
        else:
            start = struct.unpack_from("<Q", payload)[0]
            data = blob[start:start + size]
        events.append(Event(first_number + i, step, ip, address, size, kind, payload, data))
    return events


def encode_chunk(events):
    """events: (step, ip, address, size, kind, payload_or_data) tuples; data longer than 16 bytes goes to the blob."""
    blob = bytearray()
    payloads = []
    for step, ip, address, size, kind, content in events:
        if kind != EXECUTE and size > INLINE_DATA_LIMIT:
            payloads.append(struct.pack("<Q8x", len(blob)))
            blob += content
        else:
            payloads.append(bytes(content).ljust(INLINE_DATA_LIMIT, b"\0")[:INLINE_DATA_LIMIT])
    raw = bytearray(CHUNK_HEADER.pack(len(events), len(blob)))
    previous = 0
    for event in events:
        raw += struct.pack("<Q", (event[0] - previous) & MASK64)
        previous = event[0]
    previous = 0
    for event in events:
        raw += struct.pack("<Q", (event[1] - previous) & MASK64)
        previous = event[1]
    for event in events:
        raw += struct.pack("<Q", (event[2] - event[1]) & MASK64)
    for event in events:
        raw += struct.pack("<Q", event[3])
    for event in events:
        raw += struct.pack("<B", event[4])
    for payload in payloads:
        raw += payload
    raw += blob
    return zstandard.ZstdCompressor(level=3).compress(bytes(raw))


class Trace:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as file:
            self.bytes = file.read()
        magic, self.instruction_count, self.event_count, self.access_mask, count, table = HEADER.unpack_from(self.bytes)
        if magic != MAGIC:
            raise ValueError("not a v6 TTD trace")
        if not table:
            raise ValueError("TTD trace was not finalized")
        self.sections = {}
        for i in range(count):
            kind, offset, size = SECTION.unpack_from(self.bytes, table + i * SECTION.size)
            self.sections[kind] = (offset, size)
        offset, size = self.sections[CHUNK_TABLE]
        self.chunks = [CHUNK.unpack_from(self.bytes, offset + i * CHUNK.size) for i in range(size)]
        offset, size = self.sections[CHECKPOINT_TABLE]
        self.checkpoints = [CHECKPOINT.unpack_from(self.bytes, offset + i * CHECKPOINT.size) for i in range(size)]

    def chunk_events(self, index):
        first, _, _, _, offset, size = self.chunks[index]
        return decode_chunk(self.bytes[offset:offset + size], first)

    def steps_and_kinds(self, index):
        """Fast path over one chunk's step and kind columns, without decoding whole events."""
        _, _, _, _, offset, size = self.chunks[index]
        raw = zstandard.ZstdDecompressor().decompress(self.bytes[offset:offset + size])
        count, _ = CHUNK_HEADER.unpack_from(raw)
        deltas = struct.unpack_from(f"<{count}Q", raw, CHUNK_HEADER.size)
        kinds = raw[CHUNK_HEADER.size + 32 * count:CHUNK_HEADER.size + 33 * count]
        return list(itertools.accumulate(deltas)), kinds

    def events(self):
        for index in range(len(self.chunks)):
            yield from self.chunk_events(index)


def write_trace(path, events, instruction_count, access_mask=READ | WRITE | EXECUTE | HOST_WRITE):
    """Write a minimal single-chunk trace without checkpoints, for tools that only read events."""
    chunk = encode_chunk(events)
    body = bytearray(HEADER.size)
    chunk_offset = len(body)
    body += chunk
    kinds_by_page = {}
    for _, _, address, size, kind, _ in events:
        for page in range(address // 4096, (address + max(size, 1) - 1) // 4096 + 1):
            kinds_by_page[page] = kinds_by_page.get(page, 0) | kind
    chunk_table = len(body)
    body += CHUNK.pack(0, len(events), events[0][0], events[-1][0], chunk_offset, len(chunk))
    checkpoint_table = len(body)
    page_index = len(body)
    for page in sorted(kinds_by_page):
        body += PAGE.pack(page, 0, kinds_by_page[page])
    section_table = len(body)
    body += SECTION.pack(CHUNK_TABLE, chunk_table, 1)
    body += SECTION.pack(CHECKPOINT_TABLE, checkpoint_table, 0)
    body += SECTION.pack(PAGE_INDEX, page_index, len(kinds_by_page))
    body[:HEADER.size] = HEADER.pack(MAGIC, instruction_count, len(events), access_mask, 3, section_table)
    with open(path, "wb") as file:
        file.write(body)


def replace_chunk(path, index, events):
    """Re-encode chunk `index` with `events` (Event objects), appending it and repointing the chunk table."""
    trace = Trace(path)
    encoded = encode_chunk([(e.step, e.ip, e.address, e.size, e.kind, e.payload if e.kind == EXECUTE else e.data)
                            for e in events])
    data = bytearray(trace.bytes)
    offset = len(data)
    data += encoded
    first, count, first_step, last_step, _, _ = trace.chunks[index]
    table_offset = trace.sections[CHUNK_TABLE][0] + index * CHUNK.size
    data[table_offset:table_offset + CHUNK.size] = CHUNK.pack(first, count, first_step, last_step, offset, len(encoded))
    with open(path, "wb") as file:
        file.write(data)
