"""基线签名：256 字节定长分块（保留末尾短块）。

签名二进制格式（版本 1，大端整数）：

    magic   5 字节  "RDSIG"
    version 1 字节  = 1
    blklen  2 字节  分块长度 = 256
    base_len 4 字节 基线总长度
    base_sha 32 字节 基线整体 SHA-256
    每个块一条记录：
        length  2 字节  本块实际长度（末块可能小于 256）
        offset  4 字节  源偏移（基线内）
        weak    4 字节  滚动弱校验和
        strong 32 字节  本块 SHA-256
"""

from dataclasses import dataclass
import hashlib

from . import BLOCK_SIZE, VERSION
from .weak import weak_checksum
from .wire import Cursor, FormatError

MAGIC = b"RDSIG"


@dataclass(frozen=True)
class BlockSig:
    length: int        # 实际块长（<= 256）
    offset: int        # 基线内源偏移
    weak: int          # 32 位滚动弱校验和
    strong: bytes      # 32 字节 SHA-256


@dataclass(frozen=True)
class Signature:
    block_size: int
    base_length: int
    base_digest: bytes
    blocks: list  # list[BlockSig]


def make_signature(data: bytes, block_size: int = BLOCK_SIZE) -> Signature:
    blocks = []
    for off in range(0, len(data), block_size):
        chunk = data[off:off + block_size]
        blocks.append(BlockSig(
            length=len(chunk),
            offset=off,
            weak=weak_checksum(chunk),
            strong=hashlib.sha256(chunk).digest(),
        ))
    return Signature(
        block_size=block_size,
        base_length=len(data),
        base_digest=hashlib.sha256(data).digest(),
        blocks=blocks,
    )


def serialize_sig(sig: Signature) -> bytes:
    out = bytearray()
    out += MAGIC
    out.append(VERSION)
    out += sig.block_size.to_bytes(2, "big")
    out += sig.base_length.to_bytes(4, "big")
    out += sig.base_digest
    for blk in sig.blocks:
        out += blk.length.to_bytes(2, "big")
        out += blk.offset.to_bytes(4, "big")
        out += blk.weak.to_bytes(4, "big")
        out += blk.strong
    return bytes(out)


def parse_signature(data: bytes) -> Signature:
    cur = Cursor(data)
    if bytes(cur.take(len(MAGIC))) != MAGIC:
        raise FormatError("签名 magic 不匹配")
    version = cur.u8()
    if version != VERSION:
        raise FormatError(f"不支持的签名版本: {version}")
    block_size = cur.u16()
    if block_size != BLOCK_SIZE:
        raise FormatError(f"不支持的分块长度: {block_size}")
    base_length = cur.u32()
    base_digest = bytes(cur.take(32))
    blocks = []
    while cur.remaining():
        length = cur.u16()
        offset = cur.u32()
        weak = cur.u32()
        strong = bytes(cur.take(32))
        if not (1 <= length <= block_size):
            raise FormatError("块长度越界")
        blocks.append(BlockSig(length, offset, weak, strong))
    cur.end()
    return Signature(block_size, base_length, base_digest, blocks)
