"""端到端与单元测试：插入、块搬移、短尾块、弱校验碰撞、失败原子性。

直接运行：
    python3 -m unittest discover -s tests -t . -v
"""

import glob
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdiff import BLOCK_SIZE, MAX_FILE_SIZE
from rdiff.apply import ApplyError, build_target
from rdiff.delta import make_delta
from rdiff.patch import (OP_COPY, OP_LITERAL, Patch, parse_patch,
                         serialize_patch, op_copy, op_literal)
from rdiff.signature import (make_signature, parse_signature, serialize_sig)
from rdiff.weak import Roller, weak_checksum
from rdiff.wire import FormatError


# ---------- 工具函数 ----------

def block(seed: int, length: int = BLOCK_SIZE) -> bytes:
    return bytes((seed * 31 + i * 7 + (i * i) // 5) & 0xFF for i in range(length))


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "rdiff", *args],
        cwd=ROOT, capture_output=True, text=True)


class Workdir:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="rdiff-test-")

    def path(self, name):
        return os.path.join(self.tmp, name)

    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)

    def read(self, name):
        with open(self.path(name), "rb") as f:
            return f.read()

    def exists(self, name):
        return os.path.exists(self.path(name))

    def leftovers(self):
        return [p for p in glob.glob(os.path.join(self.tmp, ".rdiff-apply-*"))]


def pipeline(wd, baseline, new, out_name="target.bin"):
    wd.write("baseline", baseline)
    wd.write("new", new)
    r1 = run_cli("signature", wd.path("baseline"), wd.path("sig"))
    r2 = run_cli("delta", wd.path("sig"), wd.path("new"), wd.path("patch"))
    r3 = run_cli("apply", wd.path("baseline"), wd.path("patch"), wd.path(out_name))
    return r1, r2, r3, wd.read(out_name)


def ops_for(baseline, new):
    sig = make_signature(baseline)
    patch = make_delta(sig, new)
    return patch.ops


def assert_roundtrip(testcase, baseline, new):
    wd = Workdir()
    r1, r2, r3, out = pipeline(wd, baseline, new)
    testcase.assertEqual((r1.returncode, r2.returncode, r3.returncode), (0, 0, 0),
                         msg=f"{r1.stderr}{r2.stderr}{r3.stderr}")
    testcase.assertEqual(out, new)
    return wd


def assert_ops_well_formed(testcase, ops, new_len):
    # 相邻 LITERAL 必须合并；COPY 长度不超过 256
    prev = None
    total = 0
    for op in ops:
        if op.kind == OP_LITERAL:
            testcase.assertIsNot(prev, OP_LITERAL)
            testcase.assertTrue(len(op.data) > 0)
            total += len(op.data)
        else:
            testcase.assertEqual(op.kind, OP_COPY)
            testcase.assertTrue(1 <= op.data <= BLOCK_SIZE)
            total += op.data
        prev = op.kind
    testcase.assertEqual(total, new_len)


# ---------- 滚动弱校验 ----------

class RollingTest(unittest.TestCase):
    def test_slide_matches_full_computation(self):
        import random
        rng = random.Random(42)
        data = bytes(rng.randrange(256) for _ in range(1000))
        for length in (1, 2, 7, 255, 256):
            roller = Roller(data[:length])
            self.assertEqual(roller.value, weak_checksum(data[:length]))
            for pos in range(1, len(data) - length + 1):
                roller.slide(data[pos - 1], data[pos + length - 1])
                self.assertEqual(
                    roller.value, weak_checksum(data[pos:pos + length]),
                    msg=f"length={length} pos={pos}")

    def test_adversarial_collision_exists(self):
        # 构造弱校验相同、强摘要不同的两个 256 字节块：
        # i=0,255 处 +1（权重 256 与 1），i=1,254 处 -1（权重 255 与 2），
        # 字节和与加权和的变化量均为 0，但 SHA-256 必然不同。
        a = bytearray(block(9))
        b = bytearray(a)
        b[0] = (b[0] + 1) & 0xFF
        b[255] = (b[255] + 1) & 0xFF
        b[1] = (b[1] - 1) & 0xFF
        b[254] = (b[254] - 1) & 0xFF
        self.assertEqual(weak_checksum(bytes(a)), weak_checksum(bytes(b)))
        self.assertNotEqual(hashlib.sha256(bytes(a)).digest(),
                            hashlib.sha256(bytes(b)).digest())

    def test_signature_roundtrip(self):
        data = block(1) + block(2) + b"\x01\x02\x03"
        sig = serialize_sig(make_signature(data))
        parsed = parse_signature(sig)
        self.assertEqual(parsed.base_length, len(data))
        self.assertEqual(len(parsed.blocks), 3)
        self.assertEqual(parsed.blocks[-1].length, 3)
        self.assertEqual(parsed.blocks[-1].offset, 512)

    def test_signature_rejects_garbage(self):
        with self.assertRaises(FormatError):
            parse_signature(b"XXXX" + b"\x00" * 40)
        good = serialize_sig(make_signature(block(3)))
        with self.assertRaises(FormatError):
            parse_signature(good + b"\x00")


# ---------- 逐字节还原：各类编辑场景 ----------

class RoundtripTest(unittest.TestCase):
    def test_identical_file(self):
        baseline = block(1) + block(2) + block(3)
        ops = ops_for(baseline, baseline)
        self.assertTrue(all(op.kind == OP_COPY for op in ops))
        assert_ops_well_formed(self, ops, len(baseline))
        assert_roundtrip(self, baseline, baseline)

    def test_insertion_at_start_middle_end(self):
        baseline = block(1) + block(2) + block(3) + block(4)
        insert = bytes(range(256))
        for new in (insert + baseline,
                    baseline[:512] + insert + baseline[512:],
                    baseline + insert):
            ops = ops_for(baseline, new)
            self.assertTrue(any(op.kind == OP_COPY for op in ops))
            self.assertTrue(any(op.kind == OP_LITERAL for op in ops))
            assert_ops_well_formed(self, ops, len(new))
            assert_roundtrip(self, baseline, new)

    def test_block_move(self):
        x, y, z = block(1), block(2), block(3)
        baseline = x + y + z
        new = z + y + x  # 块搬移：内容一致，顺序颠倒
        ops = ops_for(baseline, new)
        self.assertEqual([op.kind for op in ops],
                         [OP_COPY, OP_COPY, OP_COPY])
        # 按新文件顺序引用源偏移 512, 256, 0
        self.assertEqual([op.a for op in ops], [512, 256, 0])
        assert_ops_well_formed(self, ops, len(new))
        assert_roundtrip(self, baseline, new)

    def test_short_tail_block(self):
        x, y = block(1), block(2)
        for tail_len in (1, 88, 255):
            tail = block(5, tail_len)
            baseline = x + y + tail
            # 短尾块搬到最前面，delta 必须能直接 COPY 这个短块
            new = tail + x + y
            ops = ops_for(baseline, new)
            self.assertEqual(ops[0].kind, OP_COPY)
            self.assertEqual((ops[0].a, ops[0].data), (512, tail_len))
            assert_ops_well_formed(self, ops, len(new))
            assert_roundtrip(self, baseline, new)

    def test_tail_only_baseline(self):
        # 基线本身不足 256 字节：只有一个短块
        baseline = bytes(range(200))
        new = b"HEAD" + baseline
        ops = ops_for(baseline, new)
        self.assertEqual(ops[0].kind, OP_LITERAL)
        self.assertEqual(ops[1:], [op_copy(0, 200)])
        assert_roundtrip(self, baseline, new)

    def test_empty_inputs(self):
        assert_roundtrip(self, b"", b"")
        assert_roundtrip(self, block(1) + block(2), b"")
        assert_roundtrip(self, b"", block(7))

    def test_32kib_boundaries(self):
        for length in (32767, 32768):
            baseline = bytes((i * 131 + 17) & 0xFF for i in range(length))
            new = b"q" * 137 + baseline[:-137]
            assert_roundtrip(self, baseline, new)

    def test_oversized_rejected(self):
        wd = Workdir()
        wd.write("big", b"\x00" * (MAX_FILE_SIZE + 1))
        r = run_cli("signature", wd.path("big"), wd.path("sig"))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(wd.exists("sig"))

    def test_duplicate_block_prefers_smallest_offset(self):
        x = block(4)
        baseline = x + x  # 偏移 0 与 256 完全相同
        ops = ops_for(baseline, x)
        self.assertEqual(ops, [op_copy(0, 256)])
        # 前面插一个字节后，仍应命中最小偏移 0
        ops = ops_for(baseline, b"z" + x)
        self.assertEqual(ops[0], op_literal(b"z"))
        self.assertEqual(ops[1], op_copy(0, 256))

    def test_random_data_roundtrips(self):
        import random
        rng = random.Random(7)
        baseline = bytes(rng.randrange(256) for _ in range(3000))
        # 随机替换一段 + 末尾追加
        new = bytearray(baseline)
        new[1000:1200] = bytes(rng.randrange(256) for _ in range(200))
        new += bytes(rng.randrange(256) for _ in range(37))
        assert_roundtrip(self, baseline, bytes(new))


# ---------- 弱校验碰撞：强摘要是最后防线 ----------

class CollisionTest(unittest.TestCase):
    def make_pair(self):
        a = bytearray(block(9))
        b = bytearray(a)
        b[0] = (b[0] + 1) & 0xFF
        b[255] = (b[255] + 1) & 0xFF
        b[1] = (b[1] - 1) & 0xFF
        b[254] = (b[254] - 1) & 0xFF
        return bytes(a), bytes(b)

    def test_weak_collision_rejected_by_strong_hash(self):
        a, b = self.make_pair()
        c = block(3)
        baseline = a + c
        new = b + c
        ops = ops_for(baseline, new)
        # 第一个块弱校验命中但强摘要不符：开头必须是字面量，不能 COPY 偏移 0
        self.assertEqual(ops[0].kind, OP_LITERAL)
        self.assertGreaterEqual(len(ops[0].data), BLOCK_SIZE)
        self.assertFalse(any(op.kind == OP_COPY and op.a == 0 and op.data == 256
                             for op in ops))
        # 未受影响的第二个块仍应通过 COPY 复用
        self.assertIn(op_copy(256, 256), ops)
        # 最终仍可逐字节还原
        wd = Workdir()
        _, _, r3, out = pipeline(wd, baseline, new)
        self.assertEqual(r3.returncode, 0, msg=r3.stderr)
        self.assertEqual(out, new)

    def test_build_target_collision_bytes(self):
        a, b = self.make_pair()
        # 直接用 API 验证：补丁结果字节精确等于 b
        baseline = a
        patch = make_delta(make_signature(baseline), b)
        rebuilt = build_target(baseline, serialize_patch(patch))
        self.assertEqual(rebuilt, b)


# ---------- 失败补丁：原子性与保留原目标 ----------

class FailureAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.wd = Workdir()
        self.baseline = block(1) + block(2) + b"\xaa\xbb"
        self.new = b"INSERTED" + self.baseline[8:] + b"TAIL"
        self.wd.write("baseline", self.baseline)
        self.wd.write("new", self.new)
        r = run_cli("signature", self.wd.path("baseline"), self.wd.path("sig"))
        self.assertEqual(r.returncode, 0)
        r = run_cli("delta", self.wd.path("sig"), self.wd.path("new"),
                    self.wd.path("patch"))
        self.assertEqual(r.returncode, 0)
        self.good_patch = self.wd.read("patch")
        self.sentinel = b"ORIGINAL TARGET CONTENT - must survive failure"

    def apply_bad_patch(self, patch_bytes, precreate=True):
        self.wd.write("bad", patch_bytes)
        out = self.wd.path("target")
        if precreate:
            self.wd.write("target", self.sentinel)
        r = run_cli("apply", self.wd.path("baseline"), self.wd.path("bad"), out)
        self.assertNotEqual(r.returncode, 0)
        if precreate:
            self.assertEqual(self.wd.read("target"), self.sentinel)
        else:
            self.assertFalse(self.wd.exists("target"))
        self.assertEqual(self.wd.leftovers(), [],
                         msg="失败后临时候选文件残留")

    def test_corrupt_literal_payload(self):
        bad = bytearray(self.good_patch)
        # 篡改补丁中部一个字节（在 END 之前）
        bad[len(bad) // 2] ^= 0xFF
        self.apply_bad_patch(bytes(bad))

    def test_truncated_patch_various_points(self):
        for cut in (0, 5, 40, 70, len(self.good_patch) - 1,
                    len(self.good_patch) - 2):
            self.apply_bad_patch(self.good_patch[:cut])

    def test_garbage_after_end(self):
        self.apply_bad_patch(self.good_patch + b"\x00")

    def test_bad_magic_and_version(self):
        self.apply_bad_patch(b"XXXXX" + self.good_patch[5:])
        bad = bytearray(self.good_patch)
        bad[5] = 99
        self.apply_bad_patch(self.good_patch[:5])
        self.apply_bad_patch(bytes(bad))

    def test_out_of_bounds_copy(self):
        # 手工构造：基线上报正确摘要，但 COPY 指向基线之外
        patch = Patch(
            target_length=256,
            base_digest=hashlib.sha256(self.baseline).digest(),
            target_digest=hashlib.sha256(b"x" * 256).digest(),
            ops=[op_copy(len(self.baseline) - 10, 256)],  # 越过基线尾
        )
        self.apply_bad_patch(serialize_patch(patch))

    def test_copy_at_exact_boundary_rejected(self):
        # offset == 基线长度、length 非零 -> 越界
        patch = Patch(
            target_length=1,
            base_digest=hashlib.sha256(self.baseline).digest(),
            target_digest=hashlib.sha256(b"\x00").digest(),
            ops=[op_copy(len(self.baseline), 1)],
        )
        self.apply_bad_patch(serialize_patch(patch))

    def test_wrong_baseline_digest(self):
        patch = Patch(
            target_length=4,
            base_digest=hashlib.sha256(b"not the baseline").digest(),
            target_digest=hashlib.sha256(b"abcd").digest(),
            ops=[op_literal(b"abcd")],
        )
        self.apply_bad_patch(serialize_patch(patch))

    def test_target_length_lying(self):
        # 指令总长与 target_length 不符：解析阶段即拒绝
        raw = bytearray(self.good_patch)
        raw[5:9] = (len(self.new) + 500).to_bytes(4, "big")
        with self.assertRaises(FormatError):
            parse_patch(bytes(raw))
        self.apply_bad_patch(bytes(raw))

    def test_missing_target_dir_fails_cleanly(self):
        out = self.wd.path("nonexistent-dir/target")
        r = run_cli("apply", self.wd.path("baseline"),
                    self.wd.path("patch"), out)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(out))
        self.assertEqual(self.wd.leftovers(), [])

    def test_corrupt_baseline_file(self):
        # 补丁声明的基线与实际提供的基线不符（apply 不读新文件也应发现）
        self.wd.write("other_baseline", self.baseline + b"different")
        out = self.wd.path("target2")
        r = run_cli("apply", self.wd.path("other_baseline"),
                    self.wd.path("patch"), out)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.wd.exists("target2"))
        self.assertEqual(self.wd.leftovers(), [])

    def test_build_target_pure_api_failures(self):
        good = parse_patch(self.good_patch)
        rebuilt = build_target(self.baseline, self.good_patch)
        self.assertEqual(rebuilt, self.new)
        with self.assertRaises(ApplyError):
            build_target(self.baseline + b"x", self.good_patch)
        # 补丁声称的目标摘要错误
        lying = Patch(good.target_length, good.base_digest,
                      b"\x00" * 32, good.ops)
        with self.assertRaises(ApplyError):
            build_target(self.baseline, serialize_patch(lying))


if __name__ == "__main__":
    unittest.main()
