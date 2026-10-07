"""Reader and writer for Sogen TTD traces, format v8 (reads v7 too; see docs/ttd-poc.md). Requires the zstandard
package."""

import struct

import zstandard

HEADER = struct.Struct("<8s5Q")
SECTION = struct.Struct("<3Q")
CHUNK = struct.Struct("<6Q")
CHECKPOINT = struct.Struct("<4Q")
PAGE_BLOCK = struct.Struct("<4Q")
PAGE_BLOCK_ENTRIES = 4096
CODE = struct.Struct("<2Q16s")
CHUNK_HEADER = struct.Struct("<9Q")
BULK = struct.Struct("<2Q")
BULK_REFERENCE = struct.Struct("<2Q")
MAGIC = b"SOGTTD8\0"
MAGIC_V7 = b"SOGTTD7\0"
CHUNK_TABLE, CHECKPOINT_TABLE, PAGE_INDEX, CODE_TABLE, BULK_TABLE, MANIFEST, UI_INPUTS, SYSCALLS = 1, 2, 3, 4, 5, 6, 7, 8
MODULES, THREADS = 9, 10
SYSCALL_HEADER = struct.Struct("<8Q")
# checkpoint, event_number, step, window, message, reserved, wparam, lparam
UI_INPUT = struct.Struct("<4QII2Q")
MANIFEST_SIZES = struct.Struct("<2I")
READ, WRITE, EXECUTE, HOST_WRITE = 1, 2, 4, 8
MASK64 = (1 << 64) - 1
INLINE_DATA_LIMIT = 16
TAG_KIND, TAG_IRREGULAR_STEP, TAG_EXTRA = 0x0F, 0x10, 0x20
STREAMS = 8
TAGS, STEPS, IPS, CODES, ADDRESSES, SIZES, DATA, BULK_REFS = range(STREAMS)


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


def _displacement_at(data, i):
    op = data[i]
    if op in (0xE8, 0xE9):
        return i + 1
    if op == 0xFF and data[i + 1] in (0x15, 0x25):
        return i + 2
    if op in (0x48, 0x4C) and data[i + 1] in (0x89, 0x8B, 0x8D) and data[i + 2] & 0xC7 == 0x05:
        return i + 3
    return None


def convert_displacements(data, encode):
    """Mirror of the bulk block x86-64 filter in src/windows-ttd/ttd_chunk.cpp."""
    data = bytearray(data)
    i = 0
    while i + 8 < len(data):
        field = _displacement_at(data, i)
        if field is None:
            i += 1
            continue
        if data[field + 3] not in (0x00, 0xFF):
            i = field + 3
            continue
        value = int.from_bytes(data[field:field + 4], "little")
        value = (value + field if encode else value - field) & 0x1FFFFFF
        if value & 0x1000000:
            value |= 0xFE000000
        data[field:field + 4] = value.to_bytes(4, "little")
        i = field + 4
    return bytes(data)


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
    """Mirror of the predictor in src/windows-ttd/ttd_chunk.cpp; encoder and decoder update it identically."""

    def __init__(self):
        self.step = self.ip = self.next_ip = self.next_code = self.bulk_block = self.bulk_next = 0
        self.code_at, self.last_address_at, self.last_address_of_kind, self.memory = {}, {}, {}, {}

    def bulk_offset_base(self, block):
        return self.bulk_next if block == self.bulk_block else 0

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


def decode_chunk(compressed, code, bulk, first_number=0):
    """bulk(index) returns the bytes of bulk block `index`."""
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
            if size > INLINE_DATA_LIMIT:
                assert not tag & TAG_EXTRA, "invalid known-value read"
                block = (state.bulk_block + _unzigzag(readers[BULK_REFS].varint())) & MASK64
                offset = (state.bulk_offset_base(block) + _unzigzag(readers[BULK_REFS].varint())) & MASK64
                data = bytes(bulk(block)[offset:offset + size])
                assert len(data) == size, "invalid bulk data reference"
                state.bulk_block, state.bulk_next = block, offset + size
                payload = BULK_REFERENCE.pack(offset, block)
            else:
                if tag & TAG_EXTRA:
                    data = state.known(address, size)
                    assert kind == READ and data is not None, "invalid known-value read"
                else:
                    data = readers[DATA].bytes(size)
                payload = data.ljust(INLINE_DATA_LIMIT, b"\0")
            state.remember_access(ip, kind, address, data)
        state.ip = ip
        events.append(Event(number, step, ip, address, size, kind, payload, data))
    return events


def encode_chunk(events, code, bulk=None):
    """events: (step, ip, address, size, kind, content) tuples. content is the instruction bytes of an execute, the
    data of an access up to 16 bytes, and the (block, offset) bulk reference of a larger access, whose bytes bulk(block)
    returns. code: the trace's CodeTable, extended as needed."""
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
            if size > INLINE_DATA_LIMIT:
                block, offset = content
                data = bytes(bulk(block)[offset:offset + size])
                _put_varint(streams[BULK_REFS], _zigzag(block - state.bulk_block))
                _put_varint(streams[BULK_REFS], _zigzag(offset - state.bulk_offset_base(block)))
                state.bulk_block, state.bulk_next = block, offset + size
            else:
                data = bytes(content).ljust(size, b"\0")[:size]
                if kind == READ and state.known(address, size) == data:
                    tag |= TAG_EXTRA
                else:
                    streams[DATA] += data
            state.remember_access(ip, kind, address, data)
        state.ip = ip
        streams[TAGS].append(tag)
    raw = CHUNK_HEADER.pack(len(events), *(len(stream) for stream in streams)) + b"".join(streams)
    return zstandard.ZstdCompressor(level=6).compress(raw)


def decode_manifest(data):
    manifest, offset = {}, 0
    while offset < len(data):
        key_size, value_size = MANIFEST_SIZES.unpack_from(data, offset)
        offset += MANIFEST_SIZES.size
        key = data[offset:offset + key_size].decode()
        offset += key_size
        manifest[key] = data[offset:offset + value_size].decode()
        offset += value_size
        if offset > len(data):
            raise ValueError("invalid TTD manifest")
    return manifest


class Syscall:
    __slots__ = ("step", "event_number", "event_count", "result", "id", "name")

    def __init__(self, step, event_number, event_count, result, id, name):
        self.step, self.event_number, self.event_count = step, event_number, event_count
        self.result, self.id, self.name = result, id, name


def decode_syscalls(compressed):
    """Mirror of decode_syscalls in src/windows-ttd/ttd_chunk.cpp."""
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    count, name_count, *sizes = SYSCALL_HEADER.unpack_from(raw)
    offset = SYSCALL_HEADER.size
    readers = []
    for size in sizes:
        readers.append(_Stream(raw[offset:offset + size]))
        offset += size
    assert offset == len(raw), "invalid syscalls"
    steps, gaps, ids, event_counts, results, names = readers
    entries, step, next_event = [], 0, 0
    for _ in range(count):
        step += steps.varint()
        event_number = next_event + gaps.varint()
        id, event_count = ids.varint(), event_counts.varint()
        result = int.from_bytes(results.bytes(8), "little")
        entries.append(Syscall(step, event_number, event_count, result, id, None))
        next_event = event_number + event_count
    known = {}
    for _ in range(name_count):
        id, length = names.varint(), names.varint()
        known[id] = names.bytes(length).decode()
    for entry in entries:
        entry.name = known.get(entry.id)
    return entries


def _text(stream):
    return stream.bytes(stream.varint()).decode()


def decode_modules(compressed):
    """Mirror of decode_modules in src/windows-ttd/ttd_chunk.cpp: dicts with base, size, load_step, load_event_number,
    unload_step and unload_event_number (None while loaded at the end), name, and path."""
    stream = _Stream(zstandard.ZstdDecompressor().decompress(compressed))
    modules = []
    for _ in range(stream.varint()):
        base, size, load_step, load_event, unload, unload_event = (stream.varint() for _ in range(6))
        modules.append({"base": base, "size": size, "load_step": load_step, "load_event_number": load_event,
                        "unload_step": unload - 1 if unload else None,
                        "unload_event_number": unload_event if unload else None,
                        "name": _text(stream), "path": _text(stream)})
    assert stream.offset == len(stream.data), "invalid modules"
    return modules


def decode_threads(compressed):
    """Mirror of decode_threads in src/windows-ttd/ttd_chunk.cpp: (step, event_number, thread_id) switches and the
    names by thread id."""
    stream = _Stream(zstandard.ZstdDecompressor().decompress(compressed))
    switches, step, event_number = [], 0, 0
    for _ in range(stream.varint()):
        step += stream.varint()
        event_number += stream.varint()
        switches.append((step, event_number, stream.varint()))
    names = {}
    for _ in range(stream.varint()):
        thread_id = stream.varint()
        names[thread_id] = _text(stream)
    assert stream.offset == len(stream.data), "invalid threads"
    return switches, names


class Trace:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as file:
            self.bytes = file.read()
        magic, self.instruction_count, self.event_count, self.access_mask, count, table = HEADER.unpack_from(self.bytes)
        if magic not in (MAGIC, MAGIC_V7):
            raise ValueError("not a v7 or v8 TTD trace")
        self.magic = magic
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
        offset, size = self.sections.get(BULK_TABLE, (0, 0))
        self.bulk_table = [BULK.unpack_from(self.bytes, offset + i * BULK.size) for i in range(size)]
        offset, size = self.sections.get(MANIFEST, (0, 0))
        self.manifest = decode_manifest(self.bytes[offset:offset + size])
        offset, size = self.sections.get(UI_INPUTS, (0, 0))
        self.ui_inputs = [UI_INPUT.unpack_from(self.bytes, offset + i * UI_INPUT.size) for i in range(size)]
        offset, size = self.sections.get(SYSCALLS, (0, 0))
        self.syscalls = decode_syscalls(self.bytes[offset:offset + size]) if SYSCALLS in self.sections else None
        offset, size = self.sections.get(MODULES, (0, 0))
        self.modules = decode_modules(self.bytes[offset:offset + size]) if MODULES in self.sections else []
        offset, size = self.sections.get(THREADS, (0, 0))
        self.thread_switches, self.thread_names = (decode_threads(self.bytes[offset:offset + size])
                                                   if THREADS in self.sections else ([], {}))
        self._bulk_cache = {}

    def bulk(self, index):
        if index not in self._bulk_cache:
            offset, size = self.bulk_table[index]
            block = zstandard.ZstdDecompressor().decompress(self.bytes[offset:offset + size]) if size else b""
            self._bulk_cache = {index: convert_displacements(block, False) if self.magic == MAGIC else block}
        return self._bulk_cache[index]

    def chunk_events(self, index):
        first, _, _, _, offset, size = self.chunks[index]
        return decode_chunk(self.bytes[offset:offset + size], self.code, self.bulk, first)

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
    """Write a minimal single-chunk trace without checkpoints, for tools that only read events. Accesses larger than 16
    bytes give their data as content and go to bulk block 0."""
    code = CodeTable()
    bulk = bytearray()
    referenced = []
    for step, ip, address, size, kind, content in events:
        if kind != EXECUTE and size > INLINE_DATA_LIMIT:
            referenced.append((step, ip, address, size, kind, (0, len(bulk))))
            bulk += bytes(content).ljust(size, b"\0")[:size]
        else:
            referenced.append((step, ip, address, size, kind, content))
    chunk = encode_chunk(referenced, code, lambda _: bulk)
    body = bytearray(HEADER.size)
    chunk_offset = len(body)
    body += chunk
    bulk_offset = len(body)
    encoded_bulk = zstandard.ZstdCompressor(level=6).compress(convert_displacements(bulk, True)) if bulk else b""
    body += encoded_bulk
    kinds_by_page = _pages(events)
    chunk_table = len(body)
    body += CHUNK.pack(0, len(events), events[0][0], events[-1][0], chunk_offset, len(chunk))
    checkpoint_table = len(body)
    page_index, page_blocks = _write_page_index(body, [(page, 0, kinds_by_page[page]) for page in sorted(kinds_by_page)])
    code_table = len(body)
    encoded_code = code.encode()
    body += encoded_code
    bulk_table = len(body)
    body += BULK.pack(bulk_offset if encoded_bulk else 0, len(encoded_bulk))
    section_table = len(body)
    body += SECTION.pack(CHUNK_TABLE, chunk_table, 1)
    body += SECTION.pack(CHECKPOINT_TABLE, checkpoint_table, 0)
    body += SECTION.pack(PAGE_INDEX, page_index, page_blocks)
    body += SECTION.pack(CODE_TABLE, code_table, len(encoded_code))
    body += SECTION.pack(BULK_TABLE, bulk_table, 1)
    body[:HEADER.size] = HEADER.pack(MAGIC, instruction_count, len(events), access_mask, 5, section_table)
    with open(path, "wb") as file:
        file.write(body)


def replace_chunk(path, index, events):
    """Re-encode chunk `index` with `events` (Event objects), appending it, the code table, and a new section table.
    Accesses larger than 16 bytes keep their bulk references."""
    trace = Trace(path)
    code = CodeTable(trace.code.entries)

    def content(e):
        if e.kind == EXECUTE:
            return e.payload
        if e.size > INLINE_DATA_LIMIT:
            offset, block = BULK_REFERENCE.unpack(e.payload)
            return block, offset
        return e.data

    encoded = encode_chunk([(e.step, e.ip, e.address, e.size, e.kind, content(e)) for e in events], code, trace.bulk)
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
    data[:HEADER.size] = HEADER.pack(trace.magic, trace.instruction_count, trace.event_count, trace.access_mask, len(sections),
                                     section_table)
    with open(path, "wb") as file:
        file.write(data)


def encode_manifest(manifest):
    data = bytearray()
    for key, value in manifest.items():
        key, value = key.encode(), value.encode()
        data += MANIFEST_SIZES.pack(len(key), len(value)) + key + value
    return bytes(data)


def drop_section(path, kind):
    """Append a section table without section `kind`."""
    trace = Trace(path)
    data = bytearray(trace.bytes)
    sections = {k: v for k, v in trace.sections.items() if k != kind}
    section_table = len(data)
    for section_kind, (section_offset, size) in sections.items():
        data += SECTION.pack(section_kind, section_offset, size)
    data[:HEADER.size] = HEADER.pack(trace.magic, trace.instruction_count, trace.event_count, trace.access_mask, len(sections),
                                     section_table)
    with open(path, "wb") as file:
        file.write(data)


def replace_manifest(path, manifest):
    """Append `manifest` (a dict of str) and a new section table pointing to it."""
    trace = Trace(path)
    data = bytearray(trace.bytes)
    encoded = encode_manifest(manifest)
    sections = dict(trace.sections)
    sections[MANIFEST] = (len(data), len(encoded))
    data += encoded
    section_table = len(data)
    for kind, (section_offset, size) in sections.items():
        data += SECTION.pack(kind, section_offset, size)
    data[:HEADER.size] = HEADER.pack(trace.magic, trace.instruction_count, trace.event_count, trace.access_mask, len(sections),
                                     section_table)
    with open(path, "wb") as file:
        file.write(data)
