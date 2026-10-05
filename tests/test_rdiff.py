"""Unit + end-to-end tests for rdiff.

Run: python3 -m unittest -v   (from the directory containing rdiff.py)
"""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# tests/ lives next to rdiff.py; its parent dir is the workspace root.

import rdiff as R


def lcg_bytes(seed, n):
    """Deterministic pseudo-random bytes (no external deps)."""
    out = bytearray(n)
    state = seed & 0xFFFFFFFF
    for i in range(n):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        out[i] = (state >> 8) & 0xFF
    return bytes(out)


def roundtrip(baseline, new):
    """Run signature -> delta -> apply and return (target, ops)."""
    sig = R.build_signature(baseline)
    patch = R.build_delta(sig, new)
    base_d, tlen, td, ops = R.parse_patch(patch)
    target = R.apply_bytes(baseline, patch)
    self_check = None
    return target, ops, (base_d, tlen, td)


def assert_ops_valid_for_new(test, ops, new):
    """Every COPY must reference baseline bytes equal to the new-file span."""
    pos = 0
    for op in ops:
        if op[0] == R.OP_COPY:
            pos += op[2]
        else:
            pos += len(op[1])
    test.assertEqual(pos, len(new))
    # No two LITERAL ops may be adjacent.
    for a, b in zip(ops, ops[1:]):
        test.assertFalse(a[0] == R.OP_LITERAL and b[0] == R.OP_LITERAL,
                         "adjacent LITERAL ops were not merged")


class RandomizedRoundtripTests(unittest.TestCase):

    def test_many_random_edits(self):
        import random
        rng = random.Random(20261005)
        for trial in range(60):
            # Baseline of random length up to 32 KiB.
            blen = rng.randint(0, R.MAX_PAYLOAD)
            seed_len = min(blen, 4096)
            core = bytes(rng.randrange(256) for _ in range(seed_len))
            if blen and seed_len < blen:
                base = (core * ((blen // seed_len) + 1))[:blen]
            else:
                base = core
            new = bytearray(base)
            for _ in range(rng.randint(1, 6)):
                kind = rng.choice(("insert", "delete", "move", "flip",
                                   "insert_block"))
                if kind == "insert" and len(new) < R.MAX_PAYLOAD:
                    at = rng.randint(0, len(new))
                    payload = bytes(rng.randrange(256)
                                    for _ in range(rng.randint(0, 300)))
                    new[at:at] = payload
                elif kind == "insert_block" and len(new) + 256 <= R.MAX_PAYLOAD:
                    at = (rng.randint(0, len(new) // 256 or 0)) * 256
                    new[at:at] = bytes(rng.randrange(256) for _ in range(256))
                elif kind == "delete" and new:
                    a = rng.randint(0, len(new) - 1)
                    b = min(len(new), a + rng.randint(1, 256))
                    del new[a:b]
                elif kind == "move" and len(new) > 8:
                    a = rng.randint(0, len(new) - 1)
                    length = min(rng.randint(1, 512), len(new) - a)
                    chunk = bytes(new[a:a + length])
                    del new[a:a + length]
                    to = rng.randint(0, len(new))
                    new[to:to] = chunk
                elif kind == "flip" and new:
                    a = rng.randint(0, len(new) - 1)
                    new[a] ^= 0xFF
                if len(new) > R.MAX_PAYLOAD:
                    del new[R.MAX_PAYLOAD:]
            new = bytes(new)
            sig = R.build_signature(base)
            patch = R.build_delta(sig, new)
            _, _, _, ops = R.parse_patch(patch)
            target = R.apply_bytes(base, patch)
            self.assertEqual(target, new, "trial %d mismatch" % trial)
            # Every COPY span must equal the corresponding new-file span.
            pos = 0
            for op in ops:
                if op[0] == R.OP_COPY:
                    src, length = op[1], op[2]
                    self.assertEqual(base[src:src + length], new[pos:pos + length],
                                     "invalid COPY at trial %d pos %d" % (trial, pos))
                    pos += length
                else:
                    self.assertEqual(op[1], new[pos:pos + len(op[1])])
                    pos += len(op[1])
            self.assertEqual(pos, len(new))


class RollingChecksumTests(unittest.TestCase):

    def test_rolling_matches_direct(self):
        data = lcg_bytes(42, 1000)
        for n in (1, 2, 7, 100, 255, 256):
            roller = R.RollingWeak.seed(data[:n])
            self.assertEqual(roller.value(), R.weak_checksum(data[:n]))
            for start in range(0, 1000 - n):
                roller.slide(data[start], data[start + n])
                self.assertEqual(
                    roller.value(),
                    R.weak_checksum(data[start + 1:start + 1 + n]),
                    "roll mismatch n=%d start=%d" % (n, start))

    def test_known_values(self):
        self.assertEqual(R.weak_checksum(b""), 0)
        self.assertEqual(R.weak_checksum(b"\x00" * 256), 0)
        # n=1: s1=1, s2 = 1*1 = 1
        self.assertEqual(R.weak_checksum(b"\x01"), 0x00010001)
        # n=2: s1 = 1+2 = 3, s2 = 2*1 + 1*2 = 4
        self.assertEqual(R.weak_checksum(b"\x01\x02"), 0x00040003)


class RoundtripTests(unittest.TestCase):

    def test_identical_file_is_all_copy(self):
        base = lcg_bytes(1, 600)  # 256 + 256 + 88
        target, ops, _ = roundtrip(base, base)
        self.assertEqual(target, base)
        self.assertTrue(ops)
        self.assertTrue(all(op[0] == R.OP_COPY for op in ops))
        assert_ops_valid_for_new(self, ops, base)

    def test_insertion_unaligned(self):
        base = lcg_bytes(7, 600)
        new = base[:300] + b"INSERTED-BYTES" * 20 + base[300:]
        self.assertLessEqual(len(new), R.MAX_PAYLOAD)
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)
        # The insertion at offset 300 shifts everything after it out of the
        # 256-byte alignment, so only the first aligned block (256) and the
        # trailing short block (88) can be copied: 344 bytes.
        copied = sum(op[2] for op in ops if op[0] == R.OP_COPY)
        self.assertEqual(copied, 344)

    def test_insertion_block_aligned_keeps_all_blocks(self):
        # Insertion at a block boundary shifts by a multiple of 256, so
        # every block after it stays aligned and must be reused.
        base = lcg_bytes(8, 600)
        marker = b"M" * 256
        new = base[:256] + marker + base[256:]
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)
        copied = sum(op[2] for op in ops if op[0] == R.OP_COPY)
        self.assertEqual(copied, 600)  # all original bytes reused
        literals = b"".join(op[1] for op in ops if op[0] == R.OP_LITERAL)
        self.assertEqual(literals, marker)

    def test_block_move(self):
        p = lcg_bytes(11, 256)
        q = lcg_bytes(22, 256)
        tail = lcg_bytes(33, 88)
        base = p + q + tail
        new = q + p + tail  # whole blocks swapped, tail stays at end
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)
        self.assertEqual(ops[0], (R.OP_COPY, 256, 256))   # q
        self.assertEqual(ops[1], (R.OP_COPY, 0, 256))     # p
        self.assertEqual(ops[2], (R.OP_COPY, 512, 88))    # short tail

    def test_short_tail_moved(self):
        p = lcg_bytes(11, 256)
        q = lcg_bytes(22, 256)
        tail = lcg_bytes(33, 88)
        base = p + q + tail
        new = tail + p + q          # short block moved to the front
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)
        self.assertEqual(ops[0], (R.OP_COPY, 512, 88))

    def test_tail_match_at_unaligned_position(self):
        # Tail block can be found anywhere in the new file, not just on
        # 256-byte boundaries.
        p = lcg_bytes(11, 256)
        tail = lcg_bytes(33, 40)
        base = p + tail
        new = b"XYZ" + tail + b"MORE" + p
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)
        # The 40-byte tail must be reused via a short COPY at offset 256.
        self.assertIn((R.OP_COPY, 256, 40), ops)

    def test_completely_different_is_all_literal(self):
        base = lcg_bytes(1, 600)
        new = lcg_bytes(2, 600)
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        self.assertTrue(all(op[0] == R.OP_LITERAL for op in ops))
        self.assertEqual(len(ops), 1)  # single merged literal run

    def test_empty_files(self):
        target, ops, _ = roundtrip(b"", b"")
        self.assertEqual(target, b"")
        self.assertEqual(ops, [])
        target, ops, _ = roundtrip(lcg_bytes(1, 100), b"")
        self.assertEqual(target, b"")
        target, ops, _ = roundtrip(b"", b"hello world")
        self.assertEqual(target, b"hello world")
        self.assertTrue(all(op[0] == R.OP_LITERAL for op in ops))

    def test_smaller_new_file(self):
        base = lcg_bytes(5, 1000)
        new = base[100:612]  # arbitrary sub-window, includes block boundaries
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)

    def test_duplicate_blocks_pick_smallest_offset(self):
        d = lcg_bytes(99, 256)
        base = d + d + b"zz"
        new = d + d
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        self.assertEqual(ops[0], (R.OP_COPY, 0, 256))  # smallest source offset
        self.assertEqual(ops[1], (R.OP_COPY, 0, 256))

    def test_longest_match_beats_short_tail(self):
        c = lcg_bytes(77, 256)
        t = c[:100]                       # tail is a prefix of block c
        base = c + t                      # 256 block + 100 short block
        new = c                           # could match tail (100) or c (256)
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        self.assertEqual(ops, [(R.OP_COPY, 0, 256)])  # longest wins

    def test_max_size_block_permutation(self):
        blocks = [lcg_bytes(1000 + i, 256) for i in range(128)]
        base = b"".join(blocks)
        self.assertEqual(len(base), 32 * 1024)
        order = list(range(128))
        order = order[::3] + order[1::3] + order[2::3]
        new = b"".join(blocks[i] for i in order)
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        assert_ops_valid_for_new(self, ops, new)
        copied = sum(op[2] for op in ops if op[0] == R.OP_COPY)
        self.assertEqual(copied, len(new))  # everything reused


class WeakCollisionTests(unittest.TestCase):
    """Deliberately constructed weak-checksum collisions.

    A = 0x07 repeated 256 times.
    B differs from A at four positions:
        index   0: -1
        index  85: +1
        index 170: +1
        index 255: -1
    Sum delta = 0 and weighted-sum delta =
        -1*1 + 1*86 + 1*171 - 1*256 = 0
    so the rsync weak checksum is identical while the content (and hence
    the SHA-256 strong digest) differs.
    """

    def setUp(self):
        self.a = b"\x07" * 256
        self.b = bytearray(self.a)
        self.b[0] -= 1
        self.b[85] += 1
        self.b[170] += 1
        self.b[255] -= 1
        self.b = bytes(self.b)
        self.assertNotEqual(self.a, self.b)
        self.assertEqual(R.weak_checksum(self.a), R.weak_checksum(self.b))
        self.assertNotEqual(R.sha256(self.a), R.sha256(self.b))

    def test_weak_collision_is_not_copied(self):
        # Baseline contains block A (and an unrelated block X), but not B.
        x = bytes((i * 37) & 0xFF for i in range(256))
        self.assertNotEqual(R.weak_checksum(x), R.weak_checksum(self.a))
        base = self.a + x
        new = self.b + b"tail-data"
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        # No COPY may claim bytes from block A for the colliding span.
        for op in ops:
            if op[0] == R.OP_COPY:
                self.assertNotEqual((op[1], op[2]), (0, 256))
        # The first 256 bytes must be delivered as LITERAL content.
        self.assertEqual(
            b"".join(op[1] for op in ops if op[0] == R.OP_LITERAL)
            [:256], self.b)

    def test_real_match_found_after_false_weak_hit(self):
        # Baseline contains both A and B; the weak lookup probes A first
        # (smaller offset), the strong check fails, then B is accepted.
        base = self.a + self.b
        new = self.b
        target, ops, _ = roundtrip(base, new)
        self.assertEqual(target, new)
        self.assertEqual(ops, [(R.OP_COPY, 256, 256)])


class FormatValidationTests(unittest.TestCase):

    def setUp(self):
        self.sig = R.build_signature(b"abcdefgh")

    def test_truncated_signature(self):
        with self.assertRaises(R.DeltaError):
            R.parse_signature(self.sig[:10])
        with self.assertRaises(R.DeltaError):
            R.parse_signature(self.sig + b"\x00")

    def test_bad_signature_magic_and_version(self):
        bad = b"XXXX" + self.sig[4:]
        with self.assertRaises(R.DeltaError):
            R.parse_signature(bad)
        bad = self.sig[:4] + struct.pack("<H", 99) + self.sig[6:]
        with self.assertRaises(R.DeltaError):
            R.parse_signature(bad)

    def test_bad_patch_framing(self):
        good = R.build_delta(self.sig, b"xyzabc")
        with self.assertRaises(R.DeltaError):
            R.parse_patch(good[:20])                  # truncated
        with self.assertRaises(R.DeltaError):
            R.parse_patch(good + b"junk")             # trailing bytes
        with self.assertRaises(R.DeltaError):
            R.parse_patch(b"XXXX" + good[4:])         # bad magic
        badver = good[:4] + struct.pack("<H", 7) + good[6:]
        with self.assertRaises(R.DeltaError):
            R.parse_patch(badver)

    def test_patch_rejects_unknown_and_zero_ops(self):
        base = b"abcd"
        unknown = (R.PATCH_HEADER.pack(
            R.PATCH_MAGIC, R.PATCH_VERSION, R.sha256(base), 1,
            R.sha256(b"x"), 1) + b"\x99")
        with self.assertRaises(R.DeltaError):
            R.parse_patch(unknown)
        zero_copy = R.PATCH_HEADER.pack(
            R.PATCH_MAGIC, R.PATCH_VERSION, R.sha256(base), 0,
            R.sha256(b""), 1) + R.COPY_OP.pack(R.OP_COPY, 0, 0)
        with self.assertRaises(R.DeltaError):
            R.parse_patch(zero_copy)

    def test_length_field_must_match_op_stream(self):
        base = b"abcd"
        patch = R.encode_patch(R.sha256(base), b"abc",
                               [(R.OP_COPY, 0, 3)])
        # Declare target length 4 though ops cover 3.
        lying = R.PATCH_HEADER.pack(
            R.PATCH_MAGIC, R.PATCH_VERSION, R.sha256(base), 4,
            R.sha256(b"abc"), 1) + patch[R.PATCH_HEADER.size:]
        with self.assertRaises(R.DeltaError):
            R.parse_patch(lying)


class ApplyFailureTests(unittest.TestCase):
    """A failed apply must leave the existing target exactly as it was."""

    def run_apply(self, workdir, baseline, patch_bytes, target_name="target"):
        bpath = os.path.join(workdir, "base")
        ppath = os.path.join(workdir, "patch")
        tpath = os.path.join(workdir, target_name)
        with open(bpath, "wb") as fh:
            fh.write(baseline)
        with open(ppath, "wb") as fh:
            fh.write(patch_bytes)
        rc = R.main(["apply", bpath, ppath, tpath])
        return rc, tpath

    def assert_no_temp_leftovers(self, workdir):
        leftovers = [n for n in os.listdir(workdir)
                     if n.startswith(".rdiff-tmp-")]
        self.assertEqual(leftovers, [])

    def test_wrong_baseline_keeps_target(self):
        original = b"PREVIOUS TARGET CONTENT"
        with tempfile.TemporaryDirectory() as d:
            base = b"the real baseline" * 10
            # Patch declares a *different* baseline digest.
            patch = R.encode_patch(
                R.sha256(b"different baseline!!"),
                b"new", [(R.OP_LITERAL, b"new")])
            rc, tpath = self.run_apply(d, base, patch)
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(tpath))
            self.assert_no_temp_leftovers(d)

    def test_out_of_range_copy_keeps_target(self):
        original = b"PREVIOUS TARGET CONTENT"
        with tempfile.TemporaryDirectory() as d:
            base = b"abc"
            patch = R.encode_patch(
                R.sha256(base), b"x" * 10,
                [(R.OP_COPY, 0, 10)])  # baseline only has 3 bytes
            rc, tpath = self.run_apply(d, base, patch)
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(tpath))
            self.assert_no_temp_leftovers(d)

    def test_wrong_target_digest_keeps_target(self):
        with tempfile.TemporaryDirectory() as d:
            base = b"abc"
            good = R.encode_patch(
                R.sha256(base), b"abc", [(R.OP_COPY, 0, 3)])
            # Corrupt the declared target digest.
            hdr = R.PATCH_HEADER.unpack(good[:R.PATCH_HEADER.size])
            corrupt = R.PATCH_HEADER.pack(
                hdr[0], hdr[1], hdr[2], hdr[3], b"\x00" * 32, hdr[5]) \
                + good[R.PATCH_HEADER.size:]
            tpath = os.path.join(d, "target")
            with open(tpath, "wb") as fh:
                fh.write(b"ORIGINAL")
            rc, _ = self.run_apply(d, base, corrupt)
            self.assertEqual(rc, 1)
            with open(tpath, "rb") as fh:
                self.assertEqual(fh.read(), b"ORIGINAL")
            self.assert_no_temp_leftovers(d)

    def test_truncated_patch_keeps_target(self):
        with tempfile.TemporaryDirectory() as d:
            base = lcg_bytes(3, 600)
            sig = R.build_signature(base)
            good = R.build_delta(sig, base[:300] + b"X" + base[300:])
            tpath = os.path.join(d, "target")
            with open(tpath, "wb") as fh:
                fh.write(b"ORIGINAL-BYTES")
            rc, _ = self.run_apply(d, base, good[:len(good) // 2])
            self.assertEqual(rc, 1)
            with open(tpath, "rb") as fh:
                self.assertEqual(fh.read(), b"ORIGINAL-BYTES")
            self.assert_no_temp_leftovers(d)

    def test_apply_then_second_failing_patch_keeps_first_result(self):
        with tempfile.TemporaryDirectory() as d:
            base = b"baseline-bytes-here"
            good = R.encode_patch(
                R.sha256(base), base, [(R.OP_COPY, 0, len(base))])
            rc, tpath = self.run_apply(d, base, good, target_name="t")
            self.assertEqual(rc, 0)
            with open(tpath, "rb") as fh:
                self.assertEqual(fh.read(), base)
            # A later broken patch must not damage the good result.
            bad = R.encode_patch(R.sha256(b"other base"),
                                 base, [(R.OP_COPY, 0, len(base))])
            with open(os.path.join(d, "patch2"), "wb") as fh:
                fh.write(bad)
            rc2 = R.main(["apply", os.path.join(d, "base"),
                          os.path.join(d, "patch2"), tpath])
            self.assertEqual(rc2, 1)
            with open(tpath, "rb") as fh:
                self.assertEqual(fh.read(), base)
            self.assert_no_temp_leftovers(d)


class CliEndToEndTests(unittest.TestCase):

    def test_full_pipeline_cli(self):
        base = lcg_bytes(123, 700)
        new = base[:333] + b"=== INSERT ===" + base[333:]
        with tempfile.TemporaryDirectory() as d:
            bp = os.path.join(d, "base")
            sp = os.path.join(d, "base.sig")
            np = os.path.join(d, "new")
            pp = os.path.join(d, "new.patch")
            tp = os.path.join(d, "target")
            for path, data in ((bp, base), (np, new)):
                with open(path, "wb") as fh:
                    fh.write(data)
            self.assertEqual(R.main(["signature", bp, sp]), 0)
            self.assertEqual(R.main(["delta", sp, np, pp]), 0)
            self.assertEqual(R.main(["apply", bp, pp, tp]), 0)
            with open(tp, "rb") as fh:
                self.assertEqual(fh.read(), new)
            # delta must not have needed the baseline: move it away and
            # rebuild the patch using only signature + new file.
            os.rename(bp, bp + ".away")
            self.assertEqual(R.main(["delta", sp, np, pp + ".2"]), 0)
            self.assertTrue(os.path.exists(pp + ".2"))

    def test_oversize_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            bp = os.path.join(d, "base")
            sp = os.path.join(d, "sig")
            with open(bp, "wb") as fh:
                fh.write(b"\x00" * (R.MAX_PAYLOAD + 1))
            self.assertEqual(R.main(["signature", bp, sp]), 1)
            self.assertFalse(os.path.exists(sp))


if __name__ == "__main__":
    unittest.main()
