# rdiff —— 滚动弱校验 + SHA-256 的二进制差分工具

接收方已有旧文件（基线），发送方只交付新文件中**无法从基线复用的字节**。
三个命令各自运行在独立的 Compose 容器中，输入目录只读、输出目录唯一可写：

| 命令 | 可读输入 | 写出 | 不能读 |
|---|---|---|---|
| `signature` | 基线 | 签名 | — |
| `delta` | 签名、新文件 | 补丁 | **基线正文** |
| `apply` | 基线、补丁 | 重建目标 | **新文件** |

不使用任何现成的 rsync 或二进制差分库；仅依赖 Python 标准库
（`hashlib.sha256`、`argparse` 等）。所有文件不超过 **32 KiB**。

## 目录结构

```
rdiff/                 工具实现（无第三方依赖）
  weak.py              32 位滚动弱校验（O(1) 窗口滑动，自行实现）
  signature.py         分块、签名生成与解析（版本化二进制格式）
  delta.py             滑窗匹配：弱命中 -> 强摘要核对 -> 最长/最小偏移
  patch.py             补丁格式与 COPY / LITERAL 指令
  apply.py             冻结基线、内存校验、原子替换、失败清理
  cli.py / __main__.py 命令行入口
compose.yaml           signature / delta / apply 三个服务
Dockerfile             python:3.11-slim，只读根文件系统
scripts/make_sample.py 生成块搬移+插入+短尾的样本
scripts/run_example.sh 本地或 compose 端到端跑通并逐字节比对
tests/test_rdiff.py    27 个用例（unittest，无需安装依赖）
data/  work/           演示流水线的挂载目录（git 忽略内容）
```

## 使用

### Docker Compose（推荐，访问隔离由挂载保证）

```sh
python3 scripts/make_sample.py    # 生成 data/in/baseline.bin、data/new/new.bin
docker compose build
docker compose run --rm signature     # data/in/baseline.bin -> work/sig/baseline.sig
docker compose run --rm delta         # 签名 + data/new/new.bin -> work/patch/new.patch
docker compose run --rm apply         # 基线 + 补丁 -> data/out/reconstructed.bin
cmp data/new/new.bin data/out/reconstructed.bin
```

`delta` 容器只挂载了签名目录与新文件目录，**没有挂载基线正文**；
`apply` 容器只挂载了基线目录与补丁目录，**没有挂载新文件**。

### 直接运行（本地有 Python 3.11+）

```sh
python3 -m rdiff signature baseline.bin baseline.sig
python3 -m rdiff delta     baseline.sig new.bin new.patch
python3 -m rdiff apply     baseline.bin new.patch reconstructed.bin
```

### 测试

```sh
python3 -m unittest discover -s tests -t . -v
```

## 弱校验（支持滑动，自行实现）

32 位值，低 16 位为 `a`、高 16 位为 `b`，窗口长 `n`：

```
a = (n + Σ x_i)                  mod 2^16
b = (n + Σ (n-i)·x_i)            mod 2^16      # i 从 0 起，左端权重最高
weak = a | (b << 16)
```

窗口右移（移出 `out`、移入 `in`）时 O(1) 更新，不重新整窗求和：

```
a' = a - out + in
b' = b - n·out + a' - n
```

测试在随机数据上逐位置比对滑动值与整窗重算值。弱校验只用于筛候选；
**弱命中后必须对候选窗口算 SHA-256 强摘要核对**，碰撞用例被刻意构造并否决。

## 匹配规则

1. 基线按 **256 字节**分块，**保留末尾短块**（签名记录每块真实长度与源偏移）。
2. delta 在新文件的**每个位置**，对所有可行窗口长度（256，以及短尾长度）
   各维护一个滚动计算器；未命中时所有窗口 O(1) 滑动一格，命中后从新位置重开窗口。
3. 弱校验命中桶内候选块后，计算窗口 SHA-256 与候选强摘要比对。
4. 多个匹配：**先选最长块，长度相同选最小源偏移**。
5. 相邻未命中字节**合并为单个 LITERAL**。

## 二进制格式（均大端、带 magic 与版本号）

签名（`RDSIG`）：

```
"RDSIG" | ver=1(u8) | blklen=256(u16) | base_len(u32) | base_sha256(32)
重复每块: length(u16) | offset(u32) | weak(u32) | sha256(32)
```

补丁（`RDPAT`，仅 COPY / LITERAL 两种指令）：

```
"RDPAT" | ver=1(u8) | target_len(u32) | base_sha256(32) | target_sha256(32)
指令流:
  COPY    1 | offset(u32) | length(u16)        # 只引用冻结基线
  LITERAL 2 | length(u32)  | bytes[length]
  END     0                                    # 显式结束，其后不允许字节
```

补丁声明了**基线摘要、目标长度、目标摘要**。

## apply 的安全语义

1. 基线读入后即为不可变 `bytes`（冻结），先核对 SHA-256 是否与补丁声明一致。
2. 所有 COPY 都切片这份冻结基线，**绝不引用正在增长的输出**；越界
   （`offset + length > base_len`）立即失败。
3. 重建在内存中完整完成；长度或最终 SHA-256 不符即失败。
4. 全部通过后才写同目录 `O_EXCL` 临时候选文件，`fsync` 后 `os.replace`
   原子替换目标；任何失败都删除临时文件，**保留原目标**，不会留下貌似
   成功的新文件。不要求跨进程恢复。
5. 截断指令、未知版本/opcode、END 后的多余字节、指令总长与目标长度不符，
   在解析阶段即拒绝。

失败时进程以非零退出码退出并向 stderr 输出原因。

## 测试覆盖

- **插入**：开头 / 中间 / 末尾插入，验证 COPY 与 LITERAL 混合且逐字节还原；
- **块搬移**：整段块顺序颠倒，补丁全部为 COPY，引用原源偏移（512/256/0）；
- **短尾块**：末尾 1 / 88 / 255 字节短块搬到任意位置仍命中；基线不足
  256 字节时同样工作；
- **刻意构造的弱校验碰撞**：两对字节按权重配对修改使弱校验不变，强摘要核对
  将其否决为 LITERAL，未受影响的后续块仍通过 COPY 复用，整体逐字节还原；
- **失败原子性**：篡改负载、多点截断、END 后垃圾、坏 magic/版本、越界 COPY、
  边界 COPY、基线摘要不符、目标长度撒谎、目标目录缺失、基线被掉包——
  原目标内容保持不变，且无临时候选文件残留。
