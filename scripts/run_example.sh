#!/bin/sh
# 端到端示例：造样本 -> signature -> delta -> apply -> 逐字节比对。
set -eu

cd "$(dirname "$0")/.."

rm -rf work data/in data/new data/out
python3 scripts/make_sample.py

if command -v docker >/dev/null 2>&1; then
    docker compose build
    docker compose run --rm signature
    docker compose run --rm delta
    docker compose run --rm apply
else
    echo "[warn] 未找到 docker，改用本地 python 执行流水线" >&2
    mkdir -p work/sig work/patch data/out
    python3 -m rdiff signature data/in/baseline.bin work/sig/baseline.sig
    python3 -m rdiff delta     work/sig/baseline.sig data/new/new.bin work/patch/new.patch
    python3 -m rdiff apply     data/in/baseline.bin work/patch/new.patch data/out/reconstructed.bin
fi

cmp data/new/new.bin data/out/reconstructed.bin
echo "OK: $(wc -c < data/out/reconstructed.bin) bytes, 与新文件逐字节一致"
echo "补丁大小: $(wc -c < work/patch/new.patch) bytes（基线 $(wc -c < data/in/baseline.bin) bytes）"
