"use strict";

// Times memory queries on a Microsoft TTD trace of test-sample inside cdb (see tools/msttd_cdb.ps1): access queries,
// RWX watchpoints run forward from the start and backward from the end, and the value of a qword at random positions.
// Targets are located from the main image's PE headers in the trace: its entry point, first IAT slot, and .data start.
//   tools\msttd_cdb.ps1 -Trace build\msttd\test-sample.run -Commands '.scriptload tools\msttd_query_times.js; dx @$scriptContents.queryTimes(20)'

function queryTimes(valueQueries) {
    const control = host.namespace.Debugger.Utility.Control;
    const log = (text) => host.diagnostics.debugLog(text + "\n");
    const run = (command) => {
        const lines = [];
        for (const line of control.ExecuteCommand(command)) {
            lines.push(line);
        }
        return lines;
    };
    const timed = (action) => {
        const start = Date.now();
        const result = action();
        return [Date.now() - start, result];
    };
    const position = () => host.currentThread.TTD.Position.toString();
    const read = (address, size) => host.memory.readMemoryValues(host.Int64(address), 1, size)[0];

    run("!tt 50");
    let image = null;
    for (const module of host.currentProcess.Modules) {
        if (module.Name.toLowerCase().indexOf("test-sample") >= 0) {
            image = module;
        }
    }
    const base = image.BaseAddress.asNumber();
    const header = base + read(base + 0x3c, 4);
    const optional = header + 24;
    const sections = optional + read(header + 20, 2);
    const entry = base + read(optional + 16, 4);
    const iat = base + read(optional + 112 + 12 * 8, 4);
    let data = 0;
    let dataSize = 0;
    for (let i = 0; i < read(header + 6, 2); ++i) {
        const section = sections + i * 40;
        const name = String.fromCharCode(...[0, 1, 2, 3, 4].map((offset) => read(section + offset, 1)));
        if (name === ".data") {
            data = base + read(section + 12, 4);
            dataSize = read(section + 8, 4);
        }
    }

    // The most accessed qword of .data, found with a query over the whole section.
    const [rangeMs, counts] = timed(() => {
        const perQword = new Map();
        for (const access of host.currentSession.TTD.Memory(host.Int64(data), host.Int64(data + dataSize), "rw")) {
            const qword = Math.floor(access.Address.asNumber() / 8) * 8;
            perQword.set(qword, (perQword.get(qword) || 0) + 1);
        }
        return perQword;
    });
    let hot = data;
    let total = 0;
    for (const [qword, count] of counts) {
        total += count;
        if (count > (counts.get(hot) || 0)) {
            hot = qword;
        }
    }
    log(`QUERY .data range (${dataSize} bytes) rw: ${total} accesses in ${rangeMs} ms`);
    const heap = host.getModuleSymbolAddress("ntdll", "RtlAllocateHeap").asNumber();
    log(`TARGETS base ${base.toString(16)} entry ${entry.toString(16)} iat ${iat.toString(16)} data ${data.toString(16)} hot ${hot.toString(16)} RtlAllocateHeap ${heap.toString(16)}`);

    const targets = [["entry", entry, ["e"]], ["RtlAllocateHeap", heap, ["e"]], ["iat", iat, ["r", "w"]], ["data", data, ["r", "w"]],
                     ["hot", hot, ["r", "w"]]];
    for (const [label, address, kinds] of targets) {
        const [queryMs, count] = timed(() => {
            let accesses = 0;
            for (const access of host.currentSession.TTD.Memory(host.Int64(address), host.Int64(address + 8), "rwe")) {
                ++accesses;
            }
            return accesses;
        });
        log(`QUERY ${label} rwe: ${count} accesses in ${queryMs} ms`);
        for (const kind of kinds) {
            const size = kind === "e" ? 1 : 8;
            for (const [direction, from, command] of [["forward", "0", "g"], ["backward", "100", "g-"]]) {
                run("bc *");
                run(`!tt ${from}`);
                run(`ba ${kind}${size} 0x${address.toString(16)}`);
                // The replay also stops at every exception the trace recorded (test-sample raises some on purpose);
                // a watchpoint answer is the first stop that is the breakpoint, or the trace's end.
                const [ms, stops] = timed(() => {
                    for (let stop = 1; stop <= 100; ++stop) {
                        const before = position();
                        run(command);
                        if (run(".lastevent").join(" ").indexOf("Hit breakpoint") >= 0 || position() === before) {
                            return stop;
                        }
                    }
                    return 100;
                });
                const hit = run(".lastevent").join(" ").indexOf("Hit breakpoint") >= 0;
                log(`WATCH ${label} ${kind} ${direction}: ${ms} ms, ${hit ? "hit" : "no hit"} at ${position()} after ${stops} stops`);
            }
        }
        run("bc *");
    }

    let seed = 1;
    const random = () => {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        return seed / 2147483648;
    };
    for (const [label, address] of [["iat", iat], ["data", data], ["hot", hot]]) {
        let seekTotal = 0;
        let readTotal = 0;
        for (let i = 0; i < valueQueries; ++i) {
            seekTotal += timed(() => run(`!tt ${(random() * 100).toFixed(4)}`))[0];
            readTotal += timed(() => read(address, 8))[0];
        }
        log(`VALUE ${label}: seek ${(seekTotal / valueQueries).toFixed(1)} ms + read ${(readTotal / valueQueries).toFixed(1)} ms on average (n=${valueQueries})`);
    }
}
