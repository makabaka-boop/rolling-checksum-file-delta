"""依据签名与新文件生成补丁。

delta 只读：签名 + 新文件，绝不读取基线正文。

匹配过程：
  * 按弱校验和把签名分块建桶；
  * 在新文件的每个位置，为所有可行窗口长度（256，以及末尾短块长度）维护
    Roller，窗口推进使用 O(1) 滚动更新（不重新整窗计算）；
  * 弱校验命中候选块后，必须对窗口计算 SHA-256 强摘要核对；
  * 多个命中时：先选最长块，长度相同选最小源偏移；
  * 未命中的相邻字节合并为一个 LITERAL。
"""

import hashlib

from .patch import (OP_COPY, OP_LITERAL, Patch, op_copy, op_literal)
from .weak import Roller


def make_delta(signature, new: bytes) -> Patch:
    # 弱校验 -> 候选块列表
    buckets: dict[int, list] = {}
    for blk in signature.blocks:
        buckets.setdefault(blk.weak, []).append(blk)

    # 去重的窗口长度（通常是 256，加上可能存在的末尾短块）
    lengths = sorted({b.length for b in signature.blocks}, reverse=True)

    ops = []
    literal = bytearray()

    def flush_literal() -> None:
        if literal:
            ops.append(op_literal(bytes(literal)))
            literal.clear()

    n = len(new)
    pos = 0
    # rollers[L] 是起点恰为 pos、长度 L 的窗口滚动计算器
    rollers: dict[int, Roller] = {}

    def reset_rollers(at: int) -> None:
        rollers.clear()
        for length in lengths:
            if at + length <= n:
                rollers[length] = Roller(new[at:at + length])

    reset_rollers(0)

    while pos < n:
        best = None  # 类型：BlockSig
        # 弱命中 + 强摘要核对；最长块优先，其次最小源偏移
        for length in lengths:
            roller = rollers.get(length)
            if roller is None:
                continue
            for cand in buckets.get(roller.value, ()):
                if cand.length != length:
                    continue
                window = new[pos:pos + length]
                if hashlib.sha256(window).digest() != cand.strong:
                    continue  # 弱校验碰撞：强摘要否决
                if (best is None
                        or length > best.length
                        or (length == best.length and cand.offset < best.offset)):
                    best = cand

        if best is not None:
            flush_literal()
            ops.append(op_copy(best.offset, best.length))
            pos += best.length
            reset_rollers(pos)  # 匹配后从新位置重新开窗
            continue

        # 未命中：该字节走 LITERAL，所有存活窗口 O(1) 滑动一格
        literal.append(new[pos])
        for length in lengths:
            roller = rollers.get(length)
            if roller is None:
                continue
            if pos + 1 + length <= n:
                roller.slide(new[pos], new[pos + length])
            else:
                del rollers[length]
        pos += 1

    flush_literal()

    return Patch(
        target_length=len(new),
        base_digest=signature.base_digest,
        target_digest=hashlib.sha256(new).digest(),
        ops=ops,
    )
