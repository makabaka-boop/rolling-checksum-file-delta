"""补丁二进制格式（版本 1，大端整数），仅含 COPY 与 LITERAL 两种指令。

    magic   5 字节  "RDPAT"
    version 1 字节  = 1
    target_len   4 字节  重建后的目标长度
    base_digest 32 字节  基线整体 SHA-256（apply 时先冻结核对）
    target_sha  32 字节  重建结果应有的 SHA-256
    指令流（0 条或多条）：
        COPY    op=1  offset:4 length:2        从冻结基线 [offset, offset+length) 复制
        LITERAL op=2  length:4 payload:length  直接写出 payload
    END  op=0                     显式结束（其后不允许任何字节）

COPY 的 length 不超过 256，任何 offset/length 组合都必须完全落在基线内；
COPY 只能引用冻结的基线，绝不引用正在增长的输出。
"""

from dataclasses import dataclass
import hashlib

from . import VERSION
from .wire import Cursor, FormatError

MAGIC = b"RDPAT"
OP_END = 0
OP_COPY = 1
OP_LITERAL = 2


@dataclass(frozen=True)
class Op:
    kind: int            # OP_COPY / OP_LITERAL
    a: int = 0           # COPY: 基线偏移；LITERAL: 未使用
    data: bytes = b""    # LITERAL: 负载；COPY: 长度

    @property
    def length(self) -> int:
        return self.data if self.kind == OP_COPY else len(self.data)


@dataclass(frozen=True)
class Patch:
    target_length: int
    base_digest: bytes
    target_digest: bytes
    ops: list  # list[Op]


def op_copy(offset: int, length: int) -> Op:
    return Op(OP_COPY, offset, length)


def op_literal(payload: bytes) -> Op:
    return Op(OP_LITERAL, 0, bytes(payload))


def serialize_patch(patch: Patch) -> bytes:
    out = bytearray()
    out += MAGIC
    out.append(VERSION)
    out += patch.target_length.to_bytes(4, "big")
    out += patch.base_digest
    out += patch.target_digest
    for op in patch.ops:
        if op.kind == OP_COPY:
            if not (1 <= op.data <= 0xFFFF):
                raise FormatError("COPY 长度非法")
            if op.a < 0 or op.a > 0xFFFFFFFF:
                raise FormatError("COPY 偏移非法")
            out.append(OP_COPY)
            out += op.a.to_bytes(4, "big")
            out += int(op.data).to_bytes(2, "big")
        elif op.kind == OP_LITERAL:
            if not op.data:
                raise FormatError("空 LITERAL 非法")
            if len(op.data) > 0xFFFFFFFF:
                raise FormatError("LITERAL 过长")
            out.append(OP_LITERAL)
            out += len(op.data).to_bytes(4, "big")
            out += op.data
        else:
            raise FormatError(f"未知指令类型: {op.kind}")
    out.append(OP_END)
    return bytes(out)


def parse_patch(data: bytes) -> Patch:
    cur = Cursor(data)
    if bytes(cur.take(len(MAGIC))) != MAGIC:
        raise FormatError("补丁 magic 不匹配")
    version = cur.u8()
    if version != VERSION:
        raise FormatError(f"不支持的补丁版本: {version}")
    target_length = cur.u32()
    base_digest = bytes(cur.take(32))
    target_digest = bytes(cur.take(32))
    ops = []
    while True:
        kind = cur.u8()
        if kind == OP_END:
            break
        if kind == OP_COPY:
            offset = cur.u32()
            length = cur.u16()
            if length == 0:
                raise FormatError("COPY 长度为 0")
            ops.append(Op(OP_COPY, offset, length))
        elif kind == OP_LITERAL:
            length = cur.u32()
            if length == 0:
                raise FormatError("LITERAL 长度为 0")
            payload = bytes(cur.take(length))
            ops.append(Op(OP_LITERAL, 0, payload))
        else:
            raise FormatError(f"未知指令类型: {kind}")
    cur.end()
    total = sum(op.length for op in ops)
    if total != target_length:
        raise FormatError("指令总长与目标长度不符")
    return Patch(target_length, base_digest, target_digest, ops)


def patch_digest(patch: Patch) -> bytes:
    """目标摘要的便捷封装，便于与 hashlib 结果比对。"""
    return patch.target_digest


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
