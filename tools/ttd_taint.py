#!/usr/bin/env python3
"""Experimental byte-taint propagation over a Sogen v4 or v5 access trace.

Requires capstone 5. This is a bounded x64 data-flow prototype: unsupported
instructions are reported as gaps when they consume tainted data.
"""

import argparse
import collections
import functools
import mmap
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

HEADER = struct.Struct("<8s7Q")
HEADER_SIZES = {b"SOGTTD4\0": HEADER.size, b"SOGTTD5\0": HEADER.size + 8}
EVENT = struct.Struct("<5Q16s")
HOST_WRITE = 8
GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp")


def reg_slice(name):
    for base in GPRS:
        stem = base[1:]
        if name == base:
            return base, 0, 8
        if name == "e" + stem:
            return base, 0, 4
        if name == stem:
            return base, 0, 2
        if name == stem[0] + "l" and base in ("rax", "rbx", "rcx", "rdx"):
            return base, 0, 1
        if name == stem[0] + "h" and base in ("rax", "rbx", "rcx", "rdx"):
            return base, 1, 1
        if name == stem + "l" and base in ("rsi", "rdi", "rbp", "rsp"):
            return base, 0, 1
    for n in range(8, 16):
        base = f"r{n}"
        for suffix, width in (("", 8), ("d", 4), ("w", 2), ("b", 1)):
            if name == base + suffix:
                return base, 0, width
    if name.startswith("xmm") and name[3:].isdigit():
        return name, 0, 16
    return None


class TaintReplay:
    def __init__(self, sources, max_hits):
        self.memory = {}
        self.registers = collections.defaultdict(lambda: [0] * 16)
        self.last_read = {}
        self.last_write = {}
        self.sources = sources
        self.max_hits = max_hits
        self.hits = 0
        self.gaps = 0
        self.pending_sources = []
        for index, (name, address, size, step) in enumerate(sources):
            if index >= 63:
                raise ValueError("at most 63 taints are supported")
            self.pending_sources.append((step, index, address, size))
        self.pending_sources.sort()
        self.apply_sources(0)

    def apply_sources(self, step):
        while self.pending_sources and self.pending_sources[0][0] <= step:
            _, index, address, size = self.pending_sources.pop(0)
            for address_byte in range(address, address + size):
                self.memory[address_byte] = self.memory.get(address_byte, 0) | (1 << index)

    def read_reg(self, name):
        location = reg_slice(name)
        if location is None:
            return []
        base, offset, size = location
        return self.registers[base][offset:offset + size]

    def write_reg(self, name, taints):
        location = reg_slice(name)
        if location is None:
            return
        base, offset, size = location
        values = (taints + [0] * size)[:size]
        self.registers[base][offset:offset + size] = values
        if size == 4 and offset == 0 and base.startswith("r"):
            self.registers[base][4:8] = [0] * 4  # x64 zero extension

    def read_mem(self, event):
        return [self.memory.get(event[2] + i, 0) for i in range(min(event[3], 64))]

    def write_mem(self, event, taints, step, ip):
        address, size = event[2:4]
        for i in range(size):
            taint = taints[i] if i < len(taints) else 0
            if taint:
                self.memory[address + i] = taint
                if self.hits < self.max_hits:
                    names = ",".join(source[0] for bit, source in enumerate(self.sources) if taint & (1 << bit))
                    print(f"taint={names} step={step:x} ip={ip:x} memory={address + i:x}")
                self.hits += 1
            else:
                self.memory.pop(address + i, None)

    def process(self, execute, accesses, decoder):
        step, ip, _, size, _, code = execute
        self.apply_sources(step)
        instructions = list(decoder.disasm(code[:size], ip, count=1))
        if len(instructions) != 1 or instructions[0].size != size:
            self.gaps += 1
            return
        insn = instructions[0]
        read_events = [event for event in accesses if event[4] == 1]
        write_events = [event for event in accesses if event[4] == 2]
        try:
            reads, writes = insn.regs_access()
        except Exception:
            reads, writes = (), ()
        for reg in reads:
            location = reg_slice(insn.reg_name(reg))
            if location:
                self.last_read[location[0]] = (step, ip)
        for reg in writes:
            location = reg_slice(insn.reg_name(reg))
            if location:
                self.last_write[location[0]] = (step, ip)

        mnemonic = insn.mnemonic
        operands = insn.operands
        if mnemonic.startswith("movs") and read_events and write_events:
            for read, write in zip(read_events, write_events):
                self.write_mem(write, self.read_mem(read), step, ip)
            return
        if mnemonic == "push" and operands and write_events:
            source = self.operand_taints(insn, operands[0], read_events)
            self.write_mem(write_events[-1], source, step, ip)
            return
        if mnemonic == "pop" and operands and read_events:
            self.store_operand(insn, operands[0], self.read_mem(read_events[0]), write_events, step, ip)
            return
        if len(operands) >= 2 and mnemonic in ("mov", "movabs", "movzx", "movsx", "movsxd", "lea",
                                                 "add", "sub", "xor", "or", "and", "imul"):
            destination, source = operands[:2]
            width = destination.size
            source_taints = self.operand_taints(insn, source, read_events)
            if mnemonic == "lea":
                source_taints = self.address_taints(insn, source)
            if mnemonic in ("add", "sub", "xor", "or", "and", "imul"):
                prior = self.operand_taints(insn, destination, read_events)
                if mnemonic == "xor" and destination.type == source.type == X86_OP_REG and destination.reg == source.reg:
                    source_taints = [0] * width
                else:
                    merged = 0
                    for taint in prior + source_taints:
                        merged |= taint
                    source_taints = [merged] * width
            self.store_operand(insn, destination, source_taints, write_events, step, ip)
            return

        if (read_events or any(self.read_reg(insn.reg_name(reg)) for reg in reads)) and write_events:
            if any(any(self.read_mem(event)) for event in read_events) or any(any(self.read_reg(insn.reg_name(reg))) for reg in reads):
                self.gaps += 1
        elif any(any(self.read_reg(insn.reg_name(reg))) for reg in reads):
            self.gaps += 1
        for reg in writes:
            self.write_reg(insn.reg_name(reg), [])
        for event in write_events:
            self.write_mem(event, [], step, ip)

    def address_taints(self, insn, operand):
        if operand.type != X86_OP_MEM:
            return []
        result = 0
        for reg in (operand.mem.base, operand.mem.index):
            if reg:
                for taint in self.read_reg(insn.reg_name(reg)):
                    result |= taint
        return [result] * operand.size

    def operand_taints(self, insn, operand, read_events):
        if operand.type == X86_OP_REG:
            return self.read_reg(insn.reg_name(operand.reg))
        if operand.type == X86_OP_MEM and read_events:
            return self.read_mem(read_events[-1])
        if operand.type == X86_OP_IMM:
            return [0] * operand.size
        return []

    def store_operand(self, insn, operand, taints, write_events, step, ip):
        if operand.type == X86_OP_REG:
            self.write_reg(insn.reg_name(operand.reg), taints)
        elif operand.type == X86_OP_MEM and write_events:
            self.write_mem(write_events[-1], taints, step, ip)


def events(path):
    with open(path, "rb") as file:
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            magic, snapshot_size, _, count, _, _, _, _ = HEADER.unpack_from(data)
            if magic not in HEADER_SIZES:
                raise ValueError("taint replay requires a v4 or v5 trace with instruction bytes")
            start = HEADER_SIZES[magic] + snapshot_size
            if start + count * EVENT.size > len(data):
                raise ValueError("truncated event stream")
            for offset in range(start, start + count * EVENT.size, EVENT.size):
                yield EVENT.unpack_from(data, offset)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace")
    parser.add_argument("--taint", action="append", required=True, metavar="NAME:ADDRESS:SIZE[:STEP]")
    parser.add_argument("--register", help="report the last replay-derived read and write of this register")
    parser.add_argument("--through-step", type=lambda value: int(value, 0))
    parser.add_argument("--max-hits", type=int, default=32)
    args = parser.parse_args()
    sources = []
    for specification in args.taint:
        parts = specification.split(":")
        if len(parts) not in (3, 4):
            parser.error("--taint needs NAME:ADDRESS:SIZE[:STEP]")
        name, address, size = parts[:3]
        sources.append((name, int(address, 0), int(size, 0), int(parts[3], 0) if len(parts) == 4 else 0))
    replay = TaintReplay(sources, args.max_hits)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    current = None
    accesses = []

    def flush():
        if current:
            replay.process(current, accesses, decoder)
        for access in accesses:
            if access[4] == HOST_WRITE:
                replay.write_mem(access, [], access[0], access[1])

    for event in events(args.trace):
        if args.through_step is not None and event[0] > args.through_step:
            break
        if event[4] == 4:
            flush()
            current, accesses = event, []
        else:
            accesses.append(event)
    flush()
    print(f"tainted_memory_writes={replay.hits} unsupported_tainted_flows={replay.gaps}")
    if args.register:
        location = reg_slice(args.register)
        if location is None:
            parser.error("unsupported register")
        base = location[0]
        for operation, index in (("last_read", replay.last_read), ("last_write", replay.last_write)):
            value = index.get(base)
            print(f"register={base} {operation}=" + (f"{value[0]:x}:0 ip={value[1]:x}" if value else "none"))
        print(f"register={base} taint_mask={functools.reduce(int.__or__, replay.registers[base], 0):x}")


if __name__ == "__main__":
    main()
