#!/usr/bin/env python3
"""Generate a deterministic baseline/new demo pair (<= 32 KiB each).

new = tail(88) + block0 + 256 inserted bytes + block1

so the demo exercises a block move, a short-tail reuse and an insertion.
"""

import sys

BLOCK = 256


def lcg(seed, n):
    out = bytearray(n)
    state = seed & 0xFFFFFFFF
    for i in range(n):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        out[i] = (state >> 8) & 0xFF
    return bytes(out)


def main():
    baseline_path, new_path = sys.argv[1], sys.argv[2]
    b0 = lcg(101, BLOCK)
    b1 = lcg(202, BLOCK)
    tail = lcg(303, 88)
    inserted = bytes((i * 31 + 7) & 0xFF for i in range(BLOCK))

    baseline = b0 + b1 + tail
    new = tail + b0 + inserted + b1
    assert len(baseline) <= 32 * 1024 and len(new) <= 32 * 1024

    with open(baseline_path, "wb") as fh:
        fh.write(baseline)
    with open(new_path, "wb") as fh:
        fh.write(new)


if __name__ == "__main__":
    main()
