#!/usr/bin/env python3
"""Block-based binary delta tool (rsync-style), no external diff libraries.

Commands:
    signature <baseline> <out.sig>
    delta     <in.sig>  <newfile> <out.patch>
    apply     <baseline> <in.patch> <target>

Constraints:
  * Every payload file is at most MAX_PAYLOAD (32 KiB).
  * Baseline is split into fixed BLOCK (256) byte blocks; a trailing short
    block is kept and can be matched as well.
  * Weak checksum = rsync Adler-32 variant with O(1) window slide updates;
    a weak hit must be confirmed with the strong SHA-256 digest.
  * delta reads only the signature and the new file; it never opens the
    baseline.  apply reads only the baseline and the patch; it never opens
    the new file.
  * apply builds the whole result in a temp file and only replaces the
    target after the final digest checks out.
"""

import argparse
import hashlib
import os
import struct
import sys
import tempfile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PAYLOAD = 32 * 1024            # 32 KiB
BLOCK = 256
WEAK_MOD = 1 << 16
WEAK_MASK = WEAK_MOD - 1

# Signature format (version 1), all integers little-endian:
#   magic "RDSG", u16 version, u32 block_len, u64 baseline_len,
#   u8[32] baseline_sha256, u32 count
#   per block, repeated count times:
#     u64 src_offset, u64 length, u32 weak, u8[32] strong
SIG_MAGIC = b"RDSG"
SIG_VERSION = 1
SIG_HEADER = struct.Struct("<4sH I Q 32s I")
SIG_RECORD = struct.Struct("<QQI32s")

# Patch format (version 1), all integers little-endian:
#   magic "BDPF", u16 version, u8[32] baseline_sha256,
#   u64 target_len, u8[32] target_sha256, u32 op_count
#   operations, repeated op_count times:
#     OP_COPY    = 0x43 ("C"): u8 tag, u64 src_offset, u64 length
#     OP_LITERAL = 0x4C ("L"): u8 tag, u64 length, u8[length] data
PATCH_MAGIC = b"BDPF"
PATCH_VERSION = 1
PATCH_HEADER = struct.Struct("<4sH32sQ32sI")
OP_COPY = 0x43
OP_LITERAL = 0x4C
COPY_OP = struct.Struct("<BQQ")
LITERAL_HEADER = struct.Struct("<BQ")

# Patch files hold literals from a 32 KiB new file, so allow a little more
# than the payload limit for the framing overhead.
MAX_PATCH = MAX_PAYLOAD + 64 * 1024


class DeltaError(Exception):
    """Any structural / semantic failure in signature or patch handling."""


# ---------------------------------------------------------------------------
# Weak rolling checksum (rsync Adler-32 family)
#
#   s1 = (sum of bytes)                                mod 65536
#   s2 = (sum of bytes * reversed position, n ... 1)    mod 65536
#        s2 = sum( x[i] * (n - i) ), i = 0 .. n-1
#   weak = s1 | (s2 << 16)
#
# Sliding the window by one byte (old byte leaves, new byte enters at the
# end, window length n):
#   s1' = s1 - old + new
#   s2' = s2 - n * old + s1'
# which makes the per-position cost constant.
# ---------------------------------------------------------------------------

def weak_checksum(data):
    n = len(data)
    s1 = s2 = 0
    for i, b in enumerate(data):
        s1 += b
        s2 += b * (n - i)
    s1 &= WEAK_MASK
    s2 &= WEAK_MASK
    return s1 | (s2 << 16)


class RollingWeak:
    """Weak checksum kept alive over a fixed-size sliding window."""

    __slots__ = ("n", "s1", "s2")

    def __init__(self, n, s1=0, s2=0):
        self.n = n
        self.s1 = s1 & WEAK_MASK
        self.s2 = s2 & WEAK_MASK

    @classmethod
    def seed(cls, data):
        n = len(data)
        s1 = s2 = 0
        for i, b in enumerate(data):
            s1 += b
            s2 += b * (n - i)
        return cls(n, s1, s2)

    def slide(self, old, new):
        # s1' = s1 - old + new ; s2' = s2 - n*old + s1'
        self.s1 = (self.s1 - old + new) & WEAK_MASK
        self.s2 = (self.s2 - self.n * old + self.s1) & WEAK_MASK

    def value(self):
        return self.s1 | (self.s2 << 16)


def sha256(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Block helpers
# ---------------------------------------------------------------------------

def iter_blocks(data):
    """Yield (offset, length) of fixed blocks, keeping a trailing short one."""
    pos = 0
    n = len(data)
    while pos < n:
        length = min(BLOCK, n - pos)
        yield pos, length
        pos += BLOCK


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

def build_signature(baseline):
    records = []
    for offset, length in iter_blocks(baseline):
        chunk = baseline[offset:offset + length]
        records.append((offset, length, weak_checksum(chunk), sha256(chunk)))

    out = bytearray()
    out += SIG_HEADER.pack(
        SIG_MAGIC, SIG_VERSION, BLOCK, len(baseline),
        sha256(baseline), len(records),
    )
    for offset, length, weak, strong in records:
        out += SIG_RECORD.pack(offset, length, weak, strong)
    return bytes(out)


def parse_signature(blob):
    """Return (block_len, baseline_len, baseline_digest, records).

    records: list of (src_offset, length, weak, strong)
    """
    if len(blob) < SIG_HEADER.size:
        raise DeltaError("signature truncated")
    magic, version, block_len, baseline_len, baseline_digest, count = \
        SIG_HEADER.unpack(blob[:SIG_HEADER.size])
    if magic != SIG_MAGIC:
        raise DeltaError("bad signature magic")
    if version != SIG_VERSION:
        raise DeltaError("unsupported signature version")
    if block_len != BLOCK or baseline_len > MAX_PAYLOAD:
        raise DeltaError("incompatible signature parameters")

    need = SIG_HEADER.size + count * SIG_RECORD.size
    if len(blob) != need:
        raise DeltaError("signature length mismatch (truncated or trailing data)")

    records = []
    pos = SIG_HEADER.size
    expected_offset = 0
    for _ in range(count):
        offset, length, weak, strong = SIG_RECORD.unpack(
            blob[pos:pos + SIG_RECORD.size])
        pos += SIG_RECORD.size
        if length == 0 or length > block_len:
            raise DeltaError("signature block length out of range")
        if offset != expected_offset:
            raise DeltaError("signature blocks must cover baseline contiguously")
        records.append((offset, length, weak, strong))
        expected_offset = offset + length
    if expected_offset != baseline_len:
        raise DeltaError("signature blocks do not cover whole baseline")
    return block_len, baseline_len, baseline_digest, records


# ---------------------------------------------------------------------------
# Delta
# ---------------------------------------------------------------------------

def build_delta(signature_blob, new_data):
    if len(new_data) > MAX_PAYLOAD:
        raise DeltaError("new file exceeds 32 KiB")

    block_len, _base_len, baseline_digest, records = parse_signature(signature_blob)

    # Index candidates by (weak, length). Two lists: full-size blocks and
    # possible trailing short block. Each list is ordered by ascending
    # source offset (records are produced in order), which implements the
    # "smallest source offset" tie-break.
    full = {}
    tails = {}
    for offset, length, weak, strong in records:
        table = tails if length < block_len else full
        table.setdefault((weak, length), []).append((offset, strong))

    n = len(new_data)
    ops = []
    pos = 0
    lit_start = 0

    def flush_literals(upto):
        if upto > lit_start:
            ops.append((OP_LITERAL, new_data[lit_start:upto]))

    tail_lengths = {length for _o, length, _w, _s in records
                    if length < block_len}

    # One rolling window per block length present in the signature.
    rollers = {}
    for length in {block_len} | tail_lengths:
        if length <= n:
            rollers[length] = RollingWeak.seed(new_data[pos:pos + length])

    while pos < n:
        best_offset = None
        best_length = 0

        # Prefer longest possible match: try the full block size first,
        # then the (unique) trailing short size.
        candidates_order = ((block_len, full),) + tuple(
            (l, tails) for l in sorted(rollers) if l < block_len)
        for length, table in candidates_order:
            if length > n - pos:
                continue
            roller = rollers.get(length)
            if roller is None:
                continue
            candidates = table.get((roller.value(), length))
            if not candidates:
                continue
            strong = sha256(new_data[pos:pos + length])
            for src_offset, cand_strong in candidates:  # ascending offset
                if cand_strong == strong:
                    best_offset = src_offset
                    best_length = length
                    break
            if best_length:
                break  # full size beats any short tail

        if best_length:
            flush_literals(pos)
            ops.append((OP_COPY, best_offset, best_length))
            pos += best_length
            # Re-seed every live window after a jump of best_length bytes.
            rollers = {}
            for length in {block_len} | tail_lengths:
                if length <= n - pos:
                    rollers[length] = RollingWeak.seed(new_data[pos:pos + length])
            lit_start = pos
        else:
            # Slide every window one byte forward.  Windows that fit at
            # the current position but not at the next one (near the end)
            # are used for matching above, then dropped by the filter after
            # pos advances.  Each length slides using the byte at its own
            # window boundary.
            for length, roller in rollers.items():
                end = pos + length
                if end < n:
                    roller.slide(new_data[pos], new_data[end])
            pos += 1
            rollers = {length: r for length, r in rollers.items()
                       if length <= n - pos}

    flush_literals(n)

    # Merge adjacent literal ops (single-pass emission above already does,
    # but make the guarantee explicit and structural).
    merged = []
    for op in ops:
        if op[0] == OP_LITERAL and merged and merged[-1][0] == OP_LITERAL:
            merged[-1] = (OP_LITERAL, merged[-1][1] + op[1])
        else:
            merged.append(op)
    return encode_patch(baseline_digest, new_data, merged)


# ---------------------------------------------------------------------------
# Patch encoding / parsing
# ---------------------------------------------------------------------------

def encode_patch(baseline_digest, target_data, ops):
    out = bytearray()
    out += PATCH_HEADER.pack(
        PATCH_MAGIC, PATCH_VERSION, baseline_digest,
        len(target_data), sha256(target_data), len(ops),
    )
    for op in ops:
        if op[0] == OP_COPY:
            _, src_offset, length = op
            if length == 0:
                raise DeltaError("empty COPY op")
            out += COPY_OP.pack(OP_COPY, src_offset, length)
        elif op[0] == OP_LITERAL:
            data = op[1]
            if not data:
                raise DeltaError("empty LITERAL op")
            out += LITERAL_HEADER.pack(OP_LITERAL, len(data))
            out += data
        else:
            raise DeltaError("unknown op")
    return bytes(out)


def parse_patch(blob):
    """Parse and strictly validate the patch framing.

    Returns (baseline_digest, target_len, target_digest, ops).
    ops contain only COPY (offset, length) and LITERAL (data).
    """
    if len(blob) > MAX_PATCH:
        raise DeltaError("patch too large")
    if len(blob) < PATCH_HEADER.size:
        raise DeltaError("patch truncated")
    magic, version, baseline_digest, target_len, target_digest, op_count = \
        PATCH_HEADER.unpack(blob[:PATCH_HEADER.size])
    if magic != PATCH_MAGIC:
        raise DeltaError("bad patch magic")
    if version != PATCH_VERSION:
        raise DeltaError("unsupported patch version")
    if target_len > MAX_PAYLOAD:
        raise DeltaError("target length exceeds 32 KiB")

    pos = PATCH_HEADER.size
    ops = []
    total = 0
    for _ in range(op_count):
        if pos + 1 > len(blob):
            raise DeltaError("truncated op tag")
        tag = blob[pos]
        pos += 1
        if tag == OP_COPY:
            if pos + COPY_OP.size - 1 > len(blob):
                raise DeltaError("truncated COPY op")
            _tag, src_offset, length = COPY_OP.unpack(
                blob[pos - 1:pos - 1 + COPY_OP.size])
            pos += COPY_OP.size - 1
            if length == 0:
                raise DeltaError("zero-length COPY op")
            ops.append((OP_COPY, src_offset, length))
            total += length
        elif tag == OP_LITERAL:
            if pos + 8 > len(blob):
                raise DeltaError("truncated LITERAL header")
            _tag, length = LITERAL_HEADER.unpack(
                blob[pos - 1:pos - 1 + LITERAL_HEADER.size])
            pos += LITERAL_HEADER.size - 1
            if length == 0:
                raise DeltaError("zero-length LITERAL op")
            if pos + length > len(blob):
                raise DeltaError("truncated LITERAL body")
            ops.append((OP_LITERAL, blob[pos:pos + length]))
            pos += length
            total += length
        else:
            raise DeltaError("unknown op tag 0x%02x" % tag)
        if total > target_len:
            raise DeltaError("ops exceed declared target length")

    if pos != len(blob):
        raise DeltaError("trailing bytes after last op")
    if total != target_len:
        raise DeltaError("op stream length does not match target length")
    return baseline_digest, target_len, target_digest, ops


def apply_bytes(baseline, patch_blob):
    """Pure application: validate everything, return target bytes or raise.

    The baseline is "frozen" here: the bytes object is read once and all
    COPY ops index into this same immutable snapshot. Growing output is
    never a COPY source.
    """
    if len(baseline) > MAX_PAYLOAD:
        raise DeltaError("baseline exceeds 32 KiB")
    expected_digest = sha256(baseline)
    baseline_digest, target_len, target_digest, ops = parse_patch(patch_blob)
    if baseline_digest != expected_digest:
        raise DeltaError("baseline digest mismatch")

    base_len = len(baseline)
    out = bytearray()
    for op in ops:
        if op[0] == OP_COPY:
            _, src_offset, length = op
            if src_offset > base_len or length > base_len - src_offset:
                raise DeltaError("COPY references bytes outside baseline")
            out += baseline[src_offset:src_offset + length]
        else:
            out += op[1]

    if len(out) != target_len:
        raise DeltaError("reconstructed length mismatch")
    if sha256(out) != target_digest:
        raise DeltaError("reconstructed target digest mismatch")
    return bytes(out)


# ---------------------------------------------------------------------------
# File IO
# ---------------------------------------------------------------------------

def read_payload(path, limit=MAX_PAYLOAD, what="file"):
    size = os.path.getsize(path)
    if size > limit:
        raise DeltaError("%s too large (%d bytes)" % (what, size))
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise DeltaError("%s too large" % what)
    return data


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".rdiff-tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        fsync_dir(directory)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Commands / CLI
# ---------------------------------------------------------------------------

def cmd_signature(args):
    baseline = read_payload(args.baseline, what="baseline")
    atomic_write(args.out_sig, build_signature(baseline))
    return 0


def cmd_delta(args):
    sig = read_payload(args.signature, limit=MAX_PATCH, what="signature")
    new = read_payload(args.new_file, what="new file")
    atomic_write(args.out_patch, build_delta(sig, new))
    return 0


def cmd_apply(args):
    # Freeze the baseline once; every COPY must reference this snapshot.
    baseline = read_payload(args.baseline, what="baseline")
    patch = read_payload(args.patch, limit=MAX_PATCH, what="patch")

    target_path = args.target
    result = apply_bytes(baseline, patch)  # raises on any defect
    # Only now do we touch the target: full candidate lands in a temp file
    # and is atomically renamed over the target.
    atomic_write(target_path, result)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="rdiff",
        description="Signature / delta / apply for files up to 32 KiB.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("signature", help="build baseline signature")
    p.add_argument("baseline")
    p.add_argument("out_sig")
    p.set_defaults(func=cmd_signature)

    p = sub.add_parser("delta", help="build patch from signature + new file")
    p.add_argument("signature")
    p.add_argument("new_file")
    p.add_argument("out_patch")
    p.set_defaults(func=cmd_delta)

    p = sub.add_parser("apply", help="apply patch using baseline")
    p.add_argument("baseline")
    p.add_argument("patch")
    p.add_argument("target")
    p.set_defaults(func=cmd_apply)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (DeltaError, OSError) as exc:
        sys.stderr.write("rdiff: %s: %s\n" % (args.command, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
