"""Reader and writer for Sogen TTD traces, format v7 (see docs/ttd-poc.md). Requires the zstandard package."""

import struct

import zstandard

HEADER = struct.Struct("<8s5Q")
SECTION = struct.Struct("<3Q")
CHUNK = struct.Struct("<6Q")
CHECKPOINT = struct.Struct("<4Q")
PAGE_BLOCK = struct.Struct("<4Q")
PAGE_BLOCK_ENTRIES = 4096
CODE = struct.Struct("<2Q16s")
CHUNK_HEADER = struct.Struct("<8Q")
MAGIC = b"SOGTTD7\0"
CHUNK_TABLE, CHECKPOINT_TABLE, PAGE_INDEX, CODE_TABLE = 1, 2, 3, 4
READ, WRITE, EXECUTE, HOST_WRITE = 1, 2, 4, 8
MASK64 = (1 << 64) - 1
INLINE_DATA_LIMIT = 16
TAG_KIND, TAG_IRREGULAR_STEP, TAG_EXTRA = 0x0F, 0x10, 0x20
STREAMS = 7
TAGS, STEPS, IPS, CODES, ADDRESSES, SIZES, DATA = range(STREAMS)


class Event:
    __slots__ = ("number", "step", "ip", "address", "size", "kind", "payload", "data")

    def __init__(self, number, step, ip, address, size, kind, payload, data):
        self.number, self.step, self.ip, self.address = number, step, ip, address
        self.size, self.kind, self.payload, self.data = size, kind, payload, data

    @property
    def instruction(self):
        return self.payload[:self.size] if self.kind == EXECUTE and self.size < INLINE_DATA_LIMIT else b""


class CodeTable:
    """Distinct executed instructions as (address, size, 16 payload bytes), in order of first execution."""

    def __init__(self, entries=()):
        self.entries = list(entries)
        self.ids = {entry: index for index, entry in enumerate(self.entries)}

    def id_of(self, address, size, payload):
        key = (address, size, bytes(payload).ljust(INLINE_DATA_LIMIT, b"\0")[:INLINE_DATA_LIMIT])
        if key not in self.ids:
            self.ids[key] = len(self.entries)
            self.entries.append(key)
        return self.ids[key]

    def encode(self):
        return zstandard.ZstdCompressor(level=9).compress(b"".join(CODE.pack(*entry) for entry in self.entries))

    @staticmethod
    def decode(compressed):
        raw = zstandard.ZstdDecompressor().decompress(compressed)
        assert len(raw) % CODE.size == 0, "invalid code table"
        return CodeTable(CODE.unpack_from(raw, offset) for offset in range(0, len(raw), CODE.size))


def _zigzag(delta):
    delta &= MASK64
    return ((delta << 1) ^ (MASK64 if delta >> 63 else 0)) & MASK64


def _unzigzag(value):
    return ((value >> 1) ^ (MASK64 if value & 1 else 0)) & MASK64


def _put_varint(output, value):
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)


class _Stream:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def varint(self):
        value = shift = 0
        while True:
            byte = self.data[self.offset]
            self.offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7

    def bytes(self, count):
        assert self.offset + count <= len(self.data), "truncated chunk stream"
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result


class _Predictor:
    """Mirror of the predictor in src/windows-analyzer/ttd_chunk.cpp; encoder and decoder update it identically."""

    def __init__(self):
        self.step = self.ip = self.next_ip = self.next_code = 0
        self.code_at, self.last_address_at, self.last_address_of_kind, self.memory = {}, {}, {}, {}

    def address_base(self, ip, kind):
        return self.last_address_at.get(((ip << 4) | kind) & MASK64, self.last_address_of_kind.get(kind, 0))

    def known(self, address, size):
        values = [self.memory.get((address + i) & MASK64) for i in range(size)]
        return None if None in values else bytes(values)

    def remember_access(self, ip, kind, address, data):
        self.last_address_at[((ip << 4) | kind) & MASK64] = address
        self.last_address_of_kind[kind] = address
        for i, value in enumerate(data):
            self.memory[(address + i) & MASK64] = value


def _split_streams(compressed):
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    count, *sizes = CHUNK_HEADER.unpack_from(raw)
    offset = CHUNK_HEADER.size
    streams = []
    for size in sizes:
        streams.append(raw[offset:offset + size])
        offset += size
    assert offset == len(raw) and len(streams[TAGS]) == count, "invalid chunk"
    return streams


def decode_chunk(compressed, code, first_number=0):
    streams = _split_streams(compressed)
    tags = streams[TAGS]
    readers = [_Stream(stream) for stream in streams]
    state = _Predictor()
    events = []
    for number, tag in enumerate(tags, first_number):
        kind = tag & TAG_KIND
        step = (state.step + (readers[STEPS].varint() if tag & TAG_IRREGULAR_STEP else int(kind == EXECUTE))) & MASK64
        state.step = step
        if kind == EXECUTE:
            ip = (state.next_ip + _unzigzag(readers[IPS].varint())) & MASK64
            address = (ip + _unzigzag(readers[ADDRESSES].varint())) & MASK64
            if tag & TAG_EXTRA:
                index = (state.next_code + _unzigzag(readers[CODES].varint())) & MASK64
                state.code_at[address] = index
                state.next_code = index + 1
            else:
                index = state.code_at[address]
            entry_address, size, payload = code.entries[index]
            assert entry_address == address, "invalid code entry reference"
            data = b""
            state.next_ip = (ip + size) & MASK64
        else:
            ip = (state.ip + _unzigzag(readers[IPS].varint())) & MASK64
            address = (state.address_base(ip, kind) + _unzigzag(readers[ADDRESSES].varint())) & MASK64
            size = readers[SIZES].varint()
            if tag & TAG_EXTRA:
                data = state.known(address, size)
                assert kind == READ and data is not None, "invalid known-value read"
            else:
                offset = readers[DATA].offset
                data = readers[DATA].bytes(size)
            payload = data.ljust(INLINE_DATA_LIMIT, b"\0") if size <= INLINE_DATA_LIMIT else struct.pack("<Q8x", offset)
            state.remember_access(ip, kind, address, data)
        state.ip = ip
        events.append(Event(number, step, ip, address, size, kind, payload, data))
    return events


def encode_chunk(events, code):
    """events: (step, ip, address, size, kind, payload_or_data) tuples; code: the trace's CodeTable, extended as needed."""
    streams = [bytearray() for _ in range(STREAMS)]
    state = _Predictor()
    for step, ip, address, size, kind, content in events:
        tag = kind
        delta = (step - state.step) & MASK64
        if delta != int(kind == EXECUTE):
            tag |= TAG_IRREGULAR_STEP
            _put_varint(streams[STEPS], delta)
        state.step = step
        if kind == EXECUTE:
            _put_varint(streams[IPS], _zigzag(ip - state.next_ip))
            _put_varint(streams[ADDRESSES], _zigzag(address - ip))
            index = code.id_of(address, size, content if size < INLINE_DATA_LIMIT else b"")
            if state.code_at.get(address) != index:
                tag |= TAG_EXTRA
                _put_varint(streams[CODES], _zigzag(index - state.next_code))
                state.code_at[address] = index
                state.next_code = index + 1
            state.next_ip = (ip + size) & MASK64
        else:
            _put_varint(streams[IPS], _zigzag(ip - state.ip))
            _put_varint(streams[ADDRESSES], _zigzag(address - state.address_base(ip, kind)))
            _put_varint(streams[SIZES], size)
            data = bytes(content).ljust(size, b"\0")[:size]
            if kind == READ and size <= INLINE_DATA_LIMIT and state.known(address, size) == data:
                tag |= TAG_EXTRA
            else:
                streams[DATA] += data
            state.remember_access(ip, kind, address, data)
        state.ip = ip
        streams[TAGS].append(tag)
    raw = CHUNK_HEADER.pack(len(events), *(len(stream) for stream in streams)) + b"".join(streams)
    return zstandard.ZstdCompressor(level=6).compress(raw)


class Trace:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as file:
            self.bytes = file.read()
        magic, self.instruction_count, self.event_count, self.access_mask, count, table = HEADER.unpack_from(self.bytes)
        if magic != MAGIC:
            raise ValueError("not a v7 TTD trace")
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
        offset, size = self.sections.get(CODE_TABLE, (0, 0))
        self.code = CodeTable.decode(self.bytes[offset:offset + size]) if size else CodeTable()

    def chunk_events(self, index):
        first, _, _, _, offset, size = self.chunks[index]
        return decode_chunk(self.bytes[offset:offset + size], self.code, first)

    def steps_and_kinds(self, index):
        """Fast path over one chunk's tag and step streams, without decoding whole events."""
        _, _, _, _, offset, size = self.chunks[index]
        streams = _split_streams(self.bytes[offset:offset + size])
        irregular = _Stream(streams[STEPS])
        steps, kinds, step = [], [], 0
        for tag in streams[TAGS]:
            kind = tag & TAG_KIND
            step += irregular.varint() if tag & TAG_IRREGULAR_STEP else int(kind == EXECUTE)
            steps.append(step & MASK64)
            kinds.append(kind)
        return steps, kinds

    def events(self):
        for index in range(len(self.chunks)):
            yield from self.chunk_events(index)


def _pages(events):
    kinds_by_page = {}
    for _, _, address, size, kind, _ in events:
        for page in range(address // 4096, (address + max(size, 1) - 1) // 4096 + 1):
            kinds_by_page[page] = kinds_by_page.get(page, 0) | kind
    return kinds_by_page


def encode_page_block(entries):
    """entries: sorted (page, chunk, kinds) tuples, at most PAGE_BLOCK_ENTRIES."""
    streams = [bytearray() for _ in range(3)]
    page, chunk = entries[0][0], 0
    for entry_page, entry_chunk, kinds in entries:
        _put_varint(streams[0], entry_page - page)
        _put_varint(streams[1], entry_chunk - chunk if entry_page == page else entry_chunk)
        streams[2].append(kinds)
        page, chunk = entry_page, entry_chunk
    raw = struct.pack("<3Q", *(len(stream) for stream in streams)) + b"".join(streams)
    return zstandard.ZstdCompressor(level=6).compress(raw)


def _write_page_index(body, entries):
    blocks = []
    for first in range(0, len(entries), PAGE_BLOCK_ENTRIES):
        block = entries[first:first + PAGE_BLOCK_ENTRIES]
        encoded = encode_page_block(block)
        blocks.append(PAGE_BLOCK.pack(block[0][0], len(block), len(body), len(encoded)))
        body += encoded
    directory = len(body)
    for block in blocks:
        body += block
    return directory, len(blocks)


def write_trace(path, events, instruction_count, access_mask=READ | WRITE | EXECUTE | HOST_WRITE):
    """Write a minimal single-chunk trace without checkpoints, for tools that only read events."""
    code = CodeTable()
    chunk = encode_chunk(events, code)
    body = bytearray(HEADER.size)
    chunk_offset = len(body)
    body += chunk
    kinds_by_page = _pages(events)
    chunk_table = len(body)
    body += CHUNK.pack(0, len(events), events[0][0], events[-1][0], chunk_offset, len(chunk))
    checkpoint_table = len(body)
    page_index, page_blocks = _write_page_index(body, [(page, 0, kinds_by_page[page]) for page in sorted(kinds_by_page)])
    code_table = len(body)
    encoded_code = code.encode()
    body += encoded_code
    section_table = len(body)
    body += SECTION.pack(CHUNK_TABLE, chunk_table, 1)
    body += SECTION.pack(CHECKPOINT_TABLE, checkpoint_table, 0)
    body += SECTION.pack(PAGE_INDEX, page_index, page_blocks)
    body += SECTION.pack(CODE_TABLE, code_table, len(encoded_code))
    body[:HEADER.size] = HEADER.pack(MAGIC, instruction_count, len(events), access_mask, 4, section_table)
    with open(path, "wb") as file:
        file.write(body)


def replace_chunk(path, index, events):
    """Re-encode chunk `index` with `events` (Event objects), appending it, the code table, and a new section table."""
    trace = Trace(path)
    code = CodeTable(trace.code.entries)
    encoded = encode_chunk([(e.step, e.ip, e.address, e.size, e.kind, e.payload if e.kind == EXECUTE else e.data)
                            for e in events], code)
    data = bytearray(trace.bytes)
    offset = len(data)
    data += encoded
    first, count, first_step, last_step, _, _ = trace.chunks[index]
    table_offset = trace.sections[CHUNK_TABLE][0] + index * CHUNK.size
    data[table_offset:table_offset + CHUNK.size] = CHUNK.pack(first, count, first_step, last_step, offset, len(encoded))
    encoded_code = code.encode()
    sections = dict(trace.sections)
    sections[CODE_TABLE] = (len(data), len(encoded_code))
    data += encoded_code
    section_table = len(data)
    for kind, (section_offset, size) in sections.items():
        data += SECTION.pack(kind, section_offset, size)
    data[:HEADER.size] = HEADER.pack(MAGIC, trace.instruction_count, trace.event_count, trace.access_mask, len(sections),
                                     section_table)
    with open(path, "wb") as file:
        file.write(data)
