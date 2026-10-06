"""32 位滚动弱校验和（自定义实现，非 rsync 库）。

形式参考经典滚动校验（可做 O(1) 窗口滑动），但完全自行实现：

    a = (sum bytes + n) mod 2^16
    b = (sum (n - i) * byte_i + n) mod 2^16        # i 从 0 起
    weak = a + 2^16 * b

滑动时（移出 out，移入 in，窗口长度 n 固定）：
    a' = a - out + in
    b' = b - n * out + a'
全部在 mod 2^16 下运算。
"""

MASK = 0xFFFF
HIGH = 1 << 16


def weak_checksum(data: bytes) -> int:
    """整块计算弱校验和（32 位：低 16 位为 a，高 16 位为 b）。"""
    n = len(data)
    a = n
    b = n
    # byte_i 的权重为 (n - i)，最左端权重最高
    weight = n
    for byte in data:
        a += byte
        b += weight * byte
        weight -= 1
    a &= MASK
    b &= MASK
    return a | (b << 16)


def weak_lo(weak: int) -> int:
    return weak & MASK


def weak_hi(weak: int) -> int:
    return (weak >> 16) & MASK


class Roller:
    """固定长度窗口的滚动弱校验计算器，支持 O(1) 推进。

    初始化代价 O(n)（仅在窗口首次形成时）；之后每次 slide 为 O(1)。
    """

    __slots__ = ("n", "a", "b")

    def __init__(self, window: bytes):
        self.n = len(window)
        w = weak_checksum(window)
        self.a = weak_lo(w)
        self.b = weak_hi(w)

    @property
    def value(self) -> int:
        return self.a | (self.b << 16)

    def slide(self, outgoing: int, incoming: int) -> int:
        """窗口右移一字节：移出 outgoing，移入 incoming。"""
        # 因 a、b 各含 +n 常数项：
        # a' = a - out + in ；b' = b - n*out + a' - n
        a = (self.a - outgoing + incoming) & MASK
        self.b = (self.b - self.n * outgoing + a - self.n) & MASK
        self.a = a
        return self.value
