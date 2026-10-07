"use strict";

// Counts the instructions in a Microsoft TTD trace. Positions are sequence:step and each step is one instruction, so a
// sequence whose last valid step is k holds k + 1 instructions (the last one moves its thread to its next sequence).
// A seek to an invalid s:k lands somewhere else, so the last valid step is found by exponential and binary search.
function number(value)
{
    return typeof value === "number" ? value : value.asNumber();
}

function countInstructions()
{
    const control = host.namespace.Debugger.Utility.Control;
    const lifetime = host.currentProcess.TTD.Lifetime;
    const first = number(lifetime.MinPosition.Sequence);
    const last = number(lifetime.MaxPosition.Sequence);
    let seeks = 0;
    const lands = (s, k) => {
        ++seeks;
        control.ExecuteCommand("!tt " + s.toString(16) + ":" + k.toString(16));
        const position = host.currentThread.TTD.Position;
        return number(position.Sequence) === s && number(position.Steps) === k;
    };
    let total = 0;
    let sequences = 0;
    for (let s = first; s <= last; s++)
    {
        if (!lands(s, 0))
        {
            continue;
        }
        let low = 0;
        let high = 1;
        while (lands(s, high))
        {
            low = high;
            high *= 2;
        }
        while (high - low > 1)
        {
            const middle = Math.floor((low + high) / 2);
            if (lands(s, middle))
            {
                low = middle;
            }
            else
            {
                high = middle;
            }
        }
        total += low + 1;
        ++sequences;
    }
    return { Instructions: total, Sequences: sequences, First: first, Last: last, Seeks: seeks };
}
