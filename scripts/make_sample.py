#!/usr/bin/env python3
"""生成示例基线与新文件（含块搬移、插入与末尾短块），供 compose 流水线演示。"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def block(seed, n=256):
    return bytes((seed * 31 + i * 7 + (i * i) // 5) & 0xFF for i in range(n))


def main():
    b1, b2, b3, b4 = block(1), block(2), block(3), block(4)
    tail = bytes(range(100))  # 末尾短块（< 256）

    baseline = b1 + b2 + b3 + b4 + tail

    # 新文件：短尾块搬到开头 + 插入一段 + 块搬移（b3 在 b2 之前）+ 短尾
    new = tail + b"*** INSERTED PREFIX ***" + b3 + b1 + b4 + b2 + b"TAIL!!"

    os.makedirs(os.path.join(ROOT, "data/in"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "data/new"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "data/out"), exist_ok=True)
    for d in ("work/sig", "work/patch"):
        os.makedirs(os.path.join(ROOT, d), exist_ok=True)

    with open(os.path.join(ROOT, "data/in/baseline.bin"), "wb") as f:
        f.write(baseline)
    with open(os.path.join(ROOT, "data/new/new.bin"), "wb") as f:
        f.write(new)

    print(f"baseline = {len(baseline)} bytes, new = {len(new)} bytes")


if __name__ == "__main__":
    main()
