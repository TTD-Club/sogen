"use strict";

// Times !tt seeks to random positions (percent of the trace) inside cdb.
function seekBench(count) {
    const control = host.namespace.Debugger.Utility.Control;
    let seed = 1;
    const random = () => {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        return seed / 2147483648;
    };
    const time = (command) => {
        const start = Date.now();
        for (const line of control.ExecuteCommand(command)) { }
        return Date.now() - start;
    };
    const times = [];
    const first = time("!tt 37");
    for (let i = 0; i < count; ++i) {
        times.push(time("!tt " + (random() * 100).toFixed(4)));
    }
    times.sort((a, b) => a - b);
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const middle = time("!tt 50");
    const end = time("!tt 100");
    host.diagnostics.debugLog(`SEEKS first ${first} ms, random mean ${mean.toFixed(1)} median ${times[times.length >> 1]} p90 ${times[Math.floor(times.length * 0.9)]} max ${times[times.length - 1]} (n=${count}), middle ${middle}, end ${end}\n`);
}
