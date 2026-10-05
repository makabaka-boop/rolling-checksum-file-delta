# rdiff —— 基于分块滚动校验的二进制增量交付

只传输新文件中**无法从基线复用**的字节。三个命令，均只使用 Python 标准库，
不调用任何现成的 rsync / 二进制差分库：

| 命令 | 输入 | 输出 | 能读到什么 |
|---|---|---|---|
| `signature` | 基线文件 | 签名文件 | 仅基线 |
| `delta` | 签名 + 新文件 | 补丁 | **只读签名和新文件，绝不读基线正文** |
| `apply` | 基线 + 补丁 | 目标文件 | **只读基线和补丁，绝不读新文件** |

处理对象为各不超过 **32 KiB** 的二进制文件。

## 快速开始

主机直跑（无需 Docker）：

```sh
./scripts/run_pipeline.sh --host            # 自带演示数据（搬移+短尾+插入）
./scripts/run_pipeline.sh old.bin new.bin --host
```

Docker Compose（每个阶段是独立容器，只读输入目录 / 可写输出目录分开挂载）：

```sh
./scripts/run_pipeline.sh
./scripts/run_pipeline.sh old.bin new.bin
```

单独使用：

```sh
python3 rdiff.py signature baseline base.sig
python3 rdiff.py delta     base.sig newfile update.patch
python3 rdiff.py apply     baseline update.patch target
```

测试：

```sh
python3 -m unittest discover -s tests -v
```

## 分块与匹配

* 基线按固定 **256 字节**分块，**保留末尾短块**（短块同样可被匹配）。
* 每条签名记录：源偏移 `u64`、长度 `u64`、弱校验和 `u32`、强摘要 `SHA-256(32)`。
* 弱校验和是 rsync 的 Adler-32 家族滚动校验：
  `s1 = Σb mod 65536`，`s2 = Σ b[i]·(n−i) mod 65536`，`weak = s1 | s2<<16`。
  窗口滑动时用 O(1) 公式更新：`s1' = s1 − old + new`，
  `s2' = s2 − n·old + s1'`，而不是重算整窗。
* delta 从新文件**每个位置**尝试匹配；弱校验命中后**必须**再核对 SHA-256，
  弱碰撞不能产生 COPY（测试里有刻意构造的弱碰撞）。
* 同一位置有多个候选时：**先选最长块；长度相同选最小源偏移**。
* 相邻字面量自动合并为一个 LITERAL。

## 容器隔离（docker-compose.yml）

每个阶段挂载不同目录，物理上保证命令拿不到不该读的输入：

```
signature  ro stages/1_sig_in   (baseline)      rw stages/1_sig_out  (signature)
delta      ro stages/2_delta_in (signature,newfile; 无 baseline)
                                             rw stages/2_delta_out (patch)
apply      ro stages/3_apply_in (baseline,patch; 无 newfile)
                                             rw stages/3_apply_out (target)
```

编排脚本只把允许的产物复制进下一阶段目录，并在最后检查
`2_delta_in/baseline`、`3_apply_in/newfile` 均不存在。

## 二进制格式（版本化，小端序）

### 签名（magic `RDSG`, version 1）

```
4s  magic = "RDSG"
u16 version = 1
u32 block_len = 256
u64 baseline_len
32  baseline_sha256
u32 block_count
  重复 block_count 次：
    u64 src_offset
    u64 length            (1..256，最后一块可短)
    u32 weak
    32  strong_sha256
```

### 补丁（magic `BDPF`, version 1）

头部声明基线摘要、目标长度与目标摘要：

```
4s  magic = "BDPF"
u16 version = 1
32  baseline_sha256
u64 target_len
32  target_sha256
u32 op_count
  操作仅两种：
    'C'(0x43) u64 src_offset, u64 length   # COPY，只引用基线
    'L'(0x4C) u64 length, bytes[length]    # LITERAL
```

## apply 的安全语义

1. **先冻结并核对基线**：启动时读入基线并计算 SHA-256，与补丁头部不符即失败；
   所有 COPY 只引用这份冻结的不可变字节，**绝不引用正在增长的输出**。
2. 严格解析：magic/版本不符、操作被截断、未知操作码、零长度操作、
   长度与操作流不一致、尾部多余字节——全部拒绝。
3. 越界 COPY（偏移或长度超出基线）拒绝；拼接结果长度不等于 `target_len` 拒绝。
4. 最终 SHA-256 与 `target_sha256` 不符拒绝。
5. 任何失败都**保留原目标不动**：先把完整候选写入同目录临时文件、`fsync`、
   校验全部通过后才 `rename` 原子替换；失败时删除临时文件，不会留下
   “貌似成功”的新文件。（不要求跨进程恢复。）

## 测试覆盖

`tests/test_rdiff.py`：

* 滚动弱校验与直接逐窗计算在多种窗口长度下完全一致；
* 插入（对齐 / 非对齐）、整块搬移、短尾块搬移、短尾在非对齐位置命中、
  重复块取最小源偏移、最长块优先、32 KiB 全量块置换；
* **刻意构造的弱校验碰撞**：构造与某基线块弱校验相同但 SHA-256 不同的
  256 字节块，确认它以 LITERAL 逐字节交付，而基线中真实存在的相同块
  仍能在弱误报之后被强校验找到；
* 60 轮随机编辑（插入 / 删除 / 搬移 / 翻转）逐字节还原，并校验每个 COPY
  引用的基线段与新文件对应段完全相等；
* 失败补丁（基线摘要不符、越界 COPY、目标摘要不符、补丁截断、未知操作等）
  下原目标保持不变且无临时文件残留。
