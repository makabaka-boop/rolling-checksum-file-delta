"""应用补丁：先冻结并核对基线，再在内存中完整重建、校验，最后原子替换。

apply 只读：基线 + 补丁，绝不读取新文件。
COPY 只引用这份冻结基线，不引用正在增长的输出。
任何截断指令、越界引用、基线摘要或最终摘要不符都视为失败，
保留原目标文件（临时候选文件删除，不留下貌似成功的新文件）。
"""

import hashlib
import os

from .patch import OP_COPY, OP_LITERAL, parse_patch
from .wire import FormatError


class ApplyError(Exception):
    """补丁无法安全应用。"""


def build_target(baseline: bytes, patch_data: bytes) -> bytes:
    """纯函数式重建：返回重建结果；任何不一致直接抛 ApplyError。

    此函数不触碰文件系统，调用方负责原子替换与失败清理。
    """
    try:
        patch = parse_patch(patch_data)
    except FormatError as exc:
        raise ApplyError(f"补丁格式非法: {exc}") from exc

    # 1) 冻结基线并核对摘要（基线在进入函数时已是不可变 bytes）
    frozen = bytes(baseline)
    if hashlib.sha256(frozen).digest() != patch.base_digest:
        raise ApplyError("基线 SHA-256 与补丁声明不一致")
    base_len = len(frozen)

    # 2) 逐条核对并重建；COPY 只能切片冻结基线
    out = bytearray()
    for op in patch.ops:
        if op.kind == OP_COPY:
            offset = op.a
            length = op.data
            if offset > base_len or length > base_len - offset:
                raise ApplyError("COPY 越界引用基线")
            out += frozen[offset:offset + length]
        elif op.kind == OP_LITERAL:
            out += op.data
        else:  # parse_patch 已拦截，这里属于防御
            raise ApplyError("未知指令")
        # 超出声明长度立即失败（不允许靠截断“凑对”）
        if len(out) > patch.target_length:
            raise ApplyError("重建长度超出目标长度")

    # 3) 长度与最终摘要都必须吻合
    if len(out) != patch.target_length:
        raise ApplyError("重建长度与目标长度不符")
    result = bytes(out)
    if hashlib.sha256(result).digest() != patch.target_digest:
        raise ApplyError("重建结果 SHA-256 与补丁声明不一致")
    return result


def apply_patch(baseline_path: str, patch_path: str, target_path: str,
                max_size: int) -> None:
    with open(baseline_path, "rb") as f:
        baseline = f.read()
    with open(patch_path, "rb") as f:
        patch_data = f.read()

    # 先在内存中完成全部核对，任何失败都不会触及目标
    result = build_target(baseline, patch_data)

    target_dir = os.path.dirname(os.path.abspath(target_path))
    tmp_path = None
    try:
        # 同目录临时文件保证 rename 是原子替换
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd, tmp_path = _mkstemp_in_dir(target_dir, flags)
        with os.fdopen(fd, "wb") as f:
            f.write(result)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target_path)
        tmp_path = None
    except OSError as exc:
        raise ApplyError(f"写入目标失败: {exc}") from exc
    finally:
        # 失败路径：候选绝不残留
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    _ = max_size  # 大小上限由 CLI 读文件时统一执行


def _mkstemp_in_dir(directory: str, flags: int):
    import random
    import time
    for _ in range(100):
        name = f".rdiff-apply-{os.getpid()}-{time.time_ns()}-{random.randrange(1 << 32):08x}.tmp"
        path = os.path.join(directory, name)
        try:
            return os.open(path, flags, 0o644), path
        except FileExistsError:
            continue
    raise ApplyError("无法创建临时候选文件")
