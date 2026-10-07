# Checkpointed TTD proof of concept

This is an experimental trace in `windows-analyzer`, based on Sogen's own
serialized snapshots, instruction counter, and Unicorn write hooks. It is not a Microsoft
TTD `.run` file and is not yet a Binary Ninja debug adapter.

## Recording and querying

Use an ordinary Sogen Windows emulation root and a Windows PE:

```sh
analyzer --ttd-record sample.sogttd --ttd-checkpoint-interval 500000 -e root c:/sample.exe
analyzer --ttd-record writes-only.sogttd --ttd-no-read-trace --ttd-no-execute-trace -e root c:/sample.exe
analyzer --ttd-replay writes-only.sogttd --ttd-scan-selfmod -e root c:/sample.exe
analyzer --ttd-query sample.sogttd --ttd-address 0x401000 --ttd-size 0x100
analyzer --ttd-query sample.sogttd --ttd-access read --ttd-address 0x401000 --ttd-size 0x100
analyzer --ttd-query sample.sogttd --ttd-access execute --ttd-address 0x401000 --ttd-size 0x100
analyzer --ttd-query sample.sogttd --ttd-address 0x401000 --ttd-size 0x100 --ttd-from 1000 --ttd-to 2000
analyzer --ttd-query sample.sogttd --ttd-access all --ttd-address 0x401000 --ttd-from 1000 --ttd-next-access
analyzer --ttd-replay sample.sogttd --ttd-seek 1000 --ttd-read 0x401000 -e root c:/sample.exe
analyzer --ttd-selfmod sample.sogttd
analyzer --ttd-record packed.sogttd --ttd-max-instructions 12000000 --ttd-no-read-trace -e root c:/sample.exe
analyzer --ttd-first-selfmod packed.sogttd
analyzer --ttd-first-selfmod packed.sogttd --ttd-address 0x140001000 --ttd-size 0x11000
analyzer --ttd-replay packed.sogttd --ttd-seek 9343590 --ttd-dump-image unpacked.mem -e root c:/sample.exe
analyzer --ttd-replay dll.sogttd --ttd-seek 8493589 --ttd-dump-image unpacked-dll.mem --ttd-dump-address 0x104a70000 --ttd-dump-size 0x4c000 -e root c:/loader.exe
analyzer --ttd-replay sample.sogttd --ttd-strings strings.tsv -e root c:/sample.exe
python3 tools/ttd_taint.py sample.sogttd --taint input:0x140002000:35 --register rax
```

The application and root for replay must match the recording. `--ttd-seek N`
restores the nearest checkpoint at or before `N` and executes the remaining
instructions. While it does, every access of a recorded kind is compared with
the trace (kind, step, instruction pointer, address, size, and instruction
bytes for executes); a mismatch, or a recorded event at or before `N` that
never occurs, fails the seek with the first differing event. Only event
metadata is compared, not written values, so a replay that writes different
data to the same places still verifies. Running
the same command with `N-1` implements reverse instruction step. The CLI
prints the resulting instruction pointer. Positions are represented as
`N:0`, corresponding to Binary Ninja's `(sequence, step)` pair.
`--ttd-read` prints an eight-byte guest memory value at that position.

Recording and replay force Unicorn, one vCPU, instruction precision, and
Sogen's relative-time clock. External file/network responses and UI input
must also be identical for deterministic replay; this POC does not capture
them. Recording is suitable for an isolated, self-contained sample.

`--ttd-no-checkpoints` keeps just the initial snapshot for comparison. The
default interval is 500,000 instructions. Checkpoints are taken only between
instruction-budgeted `start()` calls, when emulator state is quiescent.
`--ttd-max-instructions` bounds recording and finalizes the trace at the limit.
A guest failure before the limit can also leave a finalized trace.

`--ttd-replay T --ttd-verify-checkpoints` checks replay determinism, including
written values: for every checkpoint it restores the previous checkpoint (or
the initial snapshot), replays the interval with event verification, and
compares the complete serialized emulator state with the recorded checkpoint,
printing `matches` or the first differing state offset. All checkpoints of
`ttd-step-sample` match. A 40M-instruction write-only recording of
`test-sample` matched in 74 of 78 intervals; the other four differed in a few
guest bytes last written from live inputs (DNS lookups over ALPC, socket
`NtDeviceIoControlFile` results, and values derived from them).

`--ttd-access` accepts `read`, `write` (the default), `host-write`, `execute`,
or `all`. The directional query flags also use that access filter.

Host writes are guest-memory writes made by Sogen itself rather than by a guest
instruction: syscall output buffers, loader and section mappings, exception and
APC frames. They are recorded whenever write tracing is on, with the step and
RIP at the time of the write (for a syscall, the instruction after `syscall`),
and `write` queries list them with `kind=host-write`. Only their range is
recorded, not their bytes. Writes through host-mapped guest memory and MMIO
regions are not reported. The self-modifying-code analyses consider guest
writes only, so code mapped by the loader is not reported as written code.

## Post-recording analyses

`--ttd-selfmod` streams the access events in order and reports an instruction
range when any of its bytes were written earlier in the same trace. Hits are
grouped by executed address, with the first matching writer and execution
positions plus an execution count. This is a write-before-execute finding;
loader relocations or legitimate generated code can also produce hits. It does
not determine whether the bytes differ from the original image.

`--ttd-first-selfmod` selects the earliest hit by execution step across the
entire recorded address space by default, including allocated regions outside
the original image. `--ttd-address` and `--ttd-size` optionally restrict the
reported instruction start address. The earliest hit can still be a packer
stub or legitimate generated code rather than an unpacked payload entry.
Replay to one step before the selected execution and use `--ttd-dump-image`
with `--ttd-dump-address` and `--ttd-dump-size` to capture the relevant guest
region. The output is raw mapped memory, with unmapped pages zero-filled; it
is not a reconstructed on-disk PE with repaired imports or sections. The dump
still needs the original application and emulation root used for recording.

For a trace with write events, `--ttd-scan-selfmod` starts a fresh emulation and
compares each observed write with its recorded position, instruction
pointer, address, and size, and checks the byte range of each executed
instruction against earlier writes. It prints the first overlap only after
the complete replay verifies. A replay divergence is an error, not evidence
that no written code executed. Execute-address queries and instruction-byte
analysis still require execute recording; this scan does not build a
persistent execute index.

Add `--ttd-dump-image first-hit.mem` to capture the original image at the
first write-before-execute hit. `--ttd-dump-address` and `--ttd-dump-size`
select a different range, such as an allocated code region. This capture is
taken before the matched instruction executes and saved only after the full
replay verifies. The scan capture limit is 64 MiB.

The scan starts a fresh emulation of the recorded application rather than
restoring the initial snapshot. Give it a fresh, writable copy of the same
emulation root and guest files used for recording. Guest file creation can
change a branch: replaying a trace recorded with a writable root against a
read-only root diverged at `NtCreateFile` in one packed sample. A separate
sample diverged after restoring the initial snapshot even though its
serialized bytes round-tripped unchanged; fresh setup verified its full
340,386,267-instruction run. Snapshot-based seeks still need independent
determinism validation before relying on them for long traces.

`--ttd-strings` restores the initial snapshot and deterministically replays
the application up to the recorded instruction count, verifying every recorded
event as a seek does. It scans committed memory at the initial position and scans
around each guest write after its instruction completes. It emits a TSV with
address, observed instruction position, encoding, and value. The
heuristics currently recognize NUL-terminated printable ASCII and ASCII-range
UTF-16LE strings of 6 to 4096 characters. `--ttd-min-string-length` changes
the lower bound. Growing prefixes at one address are coalesced into the
longest observed value; distinct replacements at that address are retained.
The replay needs the same application and root as the recording. This scan
costs a full replay and cannot recover bytes that were never present at an
instruction boundary, writes made outside the hooked guest CPU, nonprintable
encodings, or strings outside the heuristic length and termination rules.

`--ttd-buffers OUT.tsv` replays a trace with write events from a fresh
setup, verifying every guest write as `--ttd-scan-selfmod` does, and groups
guest writes into regions: writes within 16 bytes and 250,000 instructions of
a region extend it. A region is classified when it is overwritten, unmapped,
evicted, or the replay ends, and each contiguous run of at least 16 written
bytes is reported with the first kind that applies: a file signature
(`pe_image`, `elf_image`, `png_image`, `jpeg_image`, `gif_image`, `bmp_image`,
`pdf_document`, `zip_archive`, `gzip_stream`, `sqlite_database`,
`pem_private_key`, `pem_public_key`), `contains_executed_code`, `ascii_text`
(at least 32 bytes, 90% printable), `utf16le_text`, `high_entropy_buffer`
(at least 256 bytes and 7.5 bits per byte), or `buffer` (at least 512 bytes).
Printable runs inside a region are also reported as `ascii_string` (16+
characters) and `utf16le_string` (12+ characters), and signatures found inside
a region as their own rows. The TSV has `address, size, first_step, last_step,
writer_ip, writes, kind, preview, artifact`; region bytes are saved under
`OUT.tsv.buffers/`. Limits: 256 KiB per region, 16,384 active regions, 20,000
results, and 64 MiB of retained bytes (`skipped` in the summary line counts
bytes that could not be read back).

`test/ttd_dynamic_sample.c` constructs `SOGEN_TRANSIENT_BUFFER` in ASCII and
UTF-16LE and then erases both buffers. It also writes a six-byte function into
allocated executable memory, calls it, patches it, and calls it again. The
sample exited successfully; string recovery found both transient buffers,
and the self-modifying-code scan reported two executed instruction ranges.
The same scan returned no hits for `test/ttd_large_sample.c`. On the local
Apple Silicon test, string recovery took 4.88 seconds and the self-modifying
scan took 0.46 seconds for the dynamic sample. String recovery on the larger
200,000-iteration sample took 7.58 seconds, including a full deterministic
replay and initial memory scan.

`tools/ttd_taint.py` is an experimental post-recording taint pass (requires
Python Capstone 5). `--taint NAME:ADDRESS:SIZE[:STEP]` labels bytes at the
initial position or just before the specified instruction position; the
option can be repeated for independent taints. The pass walks
the event stream, disassembles the recorded bytes of each executed x64
instruction, and derives the last read and write position for each supported
general-purpose or XMM register. It propagates byte taints through MOV,
MOVZX/MOVSX, LEA, basic arithmetic/bitwise operations, PUSH/POP, and MOVS.
It prints tainted memory writes, a bounded count of unsupported tainted
flows, and an optional register's last read/write. `--through-step` limits
analysis to a position. Read, write, and execute recording must all be on.
Host writes in a v5 trace clear taint from the bytes they overwrite; they are
not yet taint sources.
For `test/ttd_xor_string_sample.c`, tainting the 35 encoded bytes at
`0x140002000` produced 34 tainted output-byte writes beginning at
`0x140005000`, with zero reported unsupported tainted flows through position
`0x219680`. The pass took 26.30 seconds on the local Apple Silicon Mac over
about 2.2 million instructions. Its v4 trace was 234 MiB (241 MiB allocated).
This is a prototype: flags, implicit dependencies, other instruction families,
thread-specific register state, MMIO, and data from the initial snapshot other
than selected source ranges are not fully modeled. A gap means the reported
taint flow may be incomplete.

## Format v5

All fields are little-endian. The 72-byte header is `SOGTTD5\0` plus eight
`uint64_t` values: initial snapshot size, instruction count, access-event count,
checkpoint count, checkpoint-table offset, index offset, index count, and the
recorded access kinds (a nonzero mask of the kind values below). Version 4 is
identical except for its 64-byte `SOGTTD4\0` header without the mask; readers
infer a v3/v4 trace's kinds by scanning its events. An index offset of zero
marks a recording that was never finalized.
The header is followed by the initial Sogen `SNAP` snapshot, 56-byte access events
(`step, ip, address, size, kind, instruction_bytes[16]`), checkpoint snapshots, 24-byte checkpoint
table entries (`step, offset, size`), and 24-byte index entries
(`page, event_number, kind`). Kind is 1 for read, 2 for write, 4 for
execute, and 8 for a host write (v5 only). Execute events contain the instruction bytes as they existed just
before execution, using `size` bytes up to the x86 maximum of 15. Other
events have zeroed instruction-byte fields. Versions 1 and 2 remain readable
as write-only traces; version 3 remains readable without instruction bytes;
version 4 remains readable.
On the UPX-packed test PE, a v4 query at the unpacked entry
`0x140001000` returned `bytes=55` (`push rbp`) at position `0x244b89`;
the self-modifying-code pass linked it to the UPX stub write at position
`0x219cb4`.
The index is sorted by 4 KiB page, access kind, and event number. It includes
every page touched by an access. The hot hooks append only events; index
construction scans the event stream after emulation completes. Readers
validate offsets and event numbers before using them. The event stream and
index may grow large; index construction sorts bounded chunks on disk and
merges them into the trace. Address queries binary-search the index on disk:
each (page, kind) group is bounded by event number (event numbers grow with
step), and next/previous queries stop at the first overlapping event, so a
query reads only the entries in its page and step range. The index must be
sorted, as every recorder version writes it. Compressed checkpoint snapshots
are spooled to `<trace>.checkpoints` as they are taken and copied into the
trace when recording finishes, so recorder memory does not grow with the
number of checkpoints.

### Positions and steps

An event's `step` is Sogen's instruction counter while the access happens:
the 1-based number of the instruction performing it. Its execute event and its
memory reads and writes therefore share one step, even though Unicorn reports
the execute event before the instruction runs (Sogen's counting hook is
registered before the recorder's). Position `N` is the state after instruction
`N`: a write with step `N` is visible when seeking to `N` and not at `N-1`, and
seeking to `N-1` reports RIP at the writing instruction.
`test/ttd_step_test.py` checks this on a recording of
`src/samples/ttd-step-sample`.

The counter can advance without an instruction completing. When a thread's
time slice ends (every `0x20000` of its instructions), Sogen's counting hook
stops the CPU, which skips the recorder's hook and the instruction itself; the
instruction is counted again when the thread resumes. A faulting instruction
also has an execute event without completing. Such positions are still
deterministic for seek, but `instruction_count` is not the number of execute
events. A recording of `ttd-step-sample` had 3,660,773 instructions and 27
positions without an execute event (`0x20000`, `0x40096`, `0x60096`, ...);
seeking to `0x1ffff` and `0x20000` reported the same RIP, so the state does
not change at such a position. The header's access-event count covers
all kinds, not only writes (the C++ field was renamed from `write_count` to
`event_count`; the layout is unchanged).

## Larger-program check

`test/ttd_large_sample.c` performs 200,000 loop iterations with repeated
writes to a 256-element array and writes a final 64-bit checksum. Built with
MinGW for x64 and run against the Sogen root image, it executed 3,416,772
guest instructions. The 250,000-instruction interval produced 13 checkpoints
and a 310.2 MiB v3 trace with 4,457,306 access events. A query for the checksum
address found its write at instruction `0x33efba`. Seeking there returned
`0x4f29837f20`, matching the expected arithmetic checksum and the result
from a trace recorded with `--ttd-no-checkpoints`.

On an Apple Silicon Mac using the Unicorn backend, the earlier write-only
v2 trace gave a 0.56-second late seek with checkpoints versus 2.25 seconds
from the initial snapshot. The v3 trace recorded in 19.37 seconds, including
the post-run index build. These are single-run wall-clock measurements, not
a general performance claim.

## Binary Ninja TTD adapter comparison

The current `DbgEngTTDAdapter` exposes reverse go/step into/step over/step
return; position get/set; memory access queries by address and time range;
next/previous memory access; next/previous register write; call queries; and
timeline events. This POC implements seek, reverse instruction stepping by
seek, read/write/execute queries by address and time range, and next/previous
access queries in the trace library. Register-write, call, and timeline-event
indexes and a Binary Ninja adapter remain future work.

Read, write, and execute hooks can each be disabled at recording time with
`--ttd-no-read-trace`, `--ttd-no-write-trace`, and
`--ttd-no-execute-trace`. All three are enabled by default. Disabling a kind
omits its events and page index entries; queries for that kind return no
results. On `test/ttd_xor_string_sample.c`, a write-only recording completed
2,214,469 instructions and contained 289,135 write events, zero read events,
and zero execute events. Write and execute events are both needed for the
self-modifying-code query on a stored trace. A write-only trace can instead
use `--ttd-scan-selfmod` if deterministic replay succeeds. Replay scans
(`--ttd-scan-selfmod`, `--ttd-buffers`) need recorded writes and skip any
read and execute events in the trace.
The same PE with only write tracing disabled produced 550,117 reads,
2,214,453 executes, and zero writes.

Each access event records its instruction position and guest instruction
pointer (`ip`) alongside address, width, and access kind. Execute events also
record the actual instruction bytes, so self-modified code can be decoded
without reading the final memory image. Register reads and writes are derived
by the taint pass from each decoded instruction; they are not stored in the
trace. Guest register values are still replay-only state.

To do: record all call instructions and their targets, then resolve exported
API calls and optional symbols during indexing. Decode selected API arguments
and returns after symbols and calling conventions are known. This is separate
from the current memory access trace.

The initial snapshot skips PE/process/OS setup. A seek from a periodic
checkpoint reexecutes at most one checkpoint interval, assuming the run reaches
each interval boundary. Reaching a checkpoint still requires its compressed
snapshot to be read and deserialized.

## String and packed-code cross-checks

FLOSS (FLARE Obfuscated String Solver) 3.1.1 was run on two x64 PE fixtures:

- FLOSS's `test-decode-from-global64.exe` fixture (SHA-256
  `b9b60720984894c2376a3dea442c566ed7e41095e745283f5a45ac19fcffdfdf`)
  produced two `decoded_strings` entries for `hello world`. Sogen completed
  emulation with status 0 and recovered `hello world` at guest addresses
  `0x408030` and `0x1018ce8a0` during trace replay.
- `test/ttd_xor_string_sample.c` compiled with MinGW (SHA-256
  `4b81b2748535d94e16311a57b143982fa3b9e18a84a9cf06a816c0f0f5019a3d`)
  constructs and then clears `XOR_DECODED_TRANSIENT_SECRET_12345`. Sogen
  recovered it at address `0x140005000`, trace position `0x21967b`. FLOSS
  found no decoded string in this optimized, inlined fixture. The scanners
  have different execution and heuristic coverage.

UPX 5.2.1 packed `test/ttd_dynamic_sample.c` into a x64 PE (SHA-256
`5e4d76e3302a0a1806e8c16b7bab16183b037f6a2e4224f8e275d2925f7030cc`).
Sogen completed the packed program with status 0. `--ttd-selfmod` reported
84 address ranges, including writes by the UPX stub at `0x140008338` to
`0x140001000` before execution of `0x140001000`, plus the fixture's own
generated code at `0x104920000`. This verifies the write-before-execute
query on a real packer, but the program itself is a benign test fixture.

A public ZIP named for SHA-256
`1d4322dbad293847de14eca09bee5056eaede7ce178490e101642bf1f5875e37`
was inspected statically. Its extracted payload matched that hash and was a
32-bit .NET PE, so it was not used for a Sogen x64 runtime claim.

## Packed sample pilot

Seven x64 PE files from a user-provided Malpedia sample archive passed
`upx -t`. Five were executables; two were DLLs loaded by a benign x64
`LoadLibraryA` harness. They were emulated in separate, network-disabled
Docker runs with bounded instruction counts, one vCPU, and read tracing
disabled. The archive's family labels were not independently verified. The
raw binaries, roots, traces, and dumps were kept outside the Git repository.

| Archive family | Input SHA-256 | First write-to-execute address | Write step | Execute step | Dump SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `win.brbbot` | `a7e036dc7ca28573d34f34b200b1b13343f017ce13d9bb5a6cce4395f39c92bb` | `0x140003f94` | `0x749937` | `0x8e9267` | `bbef309c1cda9d3c13df1d55fe68fe64a553b50d3433b048cd8fa4d4e8c1082c` |
| `win.reynolds` | `6bd8a0291b268d32422139387864f15924e1db05dbef8cc75a6677f8263fa11d` | `0x1400094fc` | `0x96e658` | `0xd680e8` | `3b381e4ca1ae18d7005a1fa101e0a56f075d4dfb54140ea6c2ec282b89bb4a91` |
| `win.valley_rat` | `fc97ad46767a45f4e59923f96d15ec5b680a33f580af7cc4e320fb9963933f26` | `0x1400235f8` | `0xac190b` | `0x204a084` | `eff91e554544d9f12ea4c227f00ecc8e20bf3b0aefeb947581eacb58971268a2` |
| `win.blackbyte` | `796531b6bc24d389750d5db0dc3596456b7f050d3bac280f31563ae362e9f120` | `0x14003f1b8` | `0x19dba96` | `0x3c15c1a` | `47d94dbe0ac78be2b7abbd3c2f7983c2a7b47dc25ac815431b2f116fec4ef32d` |
| `win.catb` DLL | `3661ff2a050ad47fdc451aed18b88444646bb3eb6387b07f4e47d0306aac6642` | `0x104a71784` | `0x471325` | `0x819a16` | `7f505a8802164862b19517929b7a48442df16299c6fb45058d80a3d2669516ee` |
| `win.kimsuky` DLL | `0a4f2cff4d4613c08b39c9f18253af0fd356697368eecddf7c0fa560386377e6` | `0x104a99948` | `0x6bc76c` | `0xe3d20f` | `88120c251dbcc4a3a5383fdc0a912dc0888e2e3c5513d837e7e3cd937594ac35` |

For all six hits, replay to `execute step - 1` reported RIP at the detected
address and dumped the mapped image without missing pages. Offline `upx -d`
produced a reference executable or DLL for each sample: its entry-point RVA
equaled the detected RVA, and its first 16 instruction bytes matched the
memory dump. The input `UPX0` sections have zero raw bytes, while the dumps
contain restored code. DLLs were mapped at `0x104a70000`, not their preferred
base of `0x180000000`, and were dumped using the explicit range options.

The seventh sample, `win.waterminer`
(`db4f825732f27f1163367226c7d565714455f3f51c1cdbd858ed4a0b2335515b`),
stopped at 4,515,906 instructions before its packed entry point. Its loader
searched for `cpu_tromp_SSE2.dll` and reached `NtRaiseHardError`; this is an
emulation coverage limit, not an unpacking result. These tests cover one
packer family only. None of the raw dumps was rebuilt and verified as a
runnable PE, and no payload completion is claimed.
