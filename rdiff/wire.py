"""二进制解析的轻量游标。"""


class FormatError(ValueError):
    """签名 / 补丁格式非法（截断、未知版本、垃圾尾巴等）。"""


class Cursor:
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> memoryview:
        if n < 0 or self.pos + n > len(self.data):
            raise FormatError("输入被截断")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return int(self.take(1)[0])

    def u16(self) -> int:
        b = self.take(2)
        return (int(b[0]) << 8) | int(b[1])

    def u32(self) -> int:
        b = self.take(4)
        return (int(b[0]) << 24) | (int(b[1]) << 16) | (int(b[2]) << 8) | int(b[3])

    def end(self) -> None:
        if self.pos != len(self.data):
            raise FormatError("末尾存在多余字节")
