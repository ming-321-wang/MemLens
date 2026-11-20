# -*- coding: utf-8 -*-
"""
用西电 Wiki 公布的 2025 平航杯检材密码，对 70 GB 容器做格式与密码验证。

密码来源：https://forensics.xidian.edu.cn/writeups/Pinghang2025/
    "挂载/解压密码: 早起王的爱恋日记❤"

注意：密码含中文与 emoji（U+2764），
  · 必须 UTF-8 编码（VeraCrypt / 7z 都按 UTF-8 处理口令）；
  · 不能经 PowerShell 命令行传参（会被 GBK 转码破坏），
    所以写死在脚本文件里、以 UTF-8 读取，或用 --pw-file 传文件。
"""
import io
import os
import subprocess
import sys
from pathlib import Path

VOL = r"E:\2025平航杯\平航杯题目"

# 密码候选：含无 emoji / 带变体选择符 等写法
CANDS = [
    "早起王的爱恋日记❤",           # Wiki 原文
    "早起王的爱恋日记",             # 去掉 emoji
    "早起王的爱恋日记\u2764\ufe0f",  # emoji + 变体选择符
    "早起王的爱恋日记 ",            # 尾部空格
]


def hr(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


def main() -> int:
    p = Path(VOL)
    if not p.is_file():
        print("卷文件不存在:", VOL)
        return 1
    size = p.stat().st_size
    hr("目标容器")
    print(f"  路径: {p}")
    print(f"  大小: {size:,} 字节（{size / 1024**3:.2f} GiB）")
    for i, c in enumerate(CANDS):
        print(f"  候选{i}: {c!r}  utf8={c.encode('utf-8').hex()}")

    # ── ① VeraCrypt 卷头离线校验 ──
    hr("① VeraCrypt 卷头离线校验")
    sys.path.insert(0, r"D:\MemLens")
    from tools.veracrypt_probe import probe_header, HEADER_SIZE

    with p.open("rb") as f:
        head = f.read(HEADER_SIZE)
    r = probe_header(head, CANDS, "主卷头 @0")
    if r and r.get("password") is not None:
        print("  ★ 命中！", r)
        return 0
    print(f"  主卷头未命中（试了 {r['tried'] if r else 0} 次）")

    # 备份卷头几个可能位置
    for off, name in ((size - 131_072, "末尾-131072"),
                      (size - HEADER_SIZE, "末尾512"),
                      (65536, "偏移65536"),
                      (131_072, "偏移131072")):
        if off < 0 or off + HEADER_SIZE > size:
            continue
        with p.open("rb") as f:
            f.seek(off)
            blk = f.read(HEADER_SIZE)
        r2 = probe_header(blk, CANDS, name)
        if r2 and r2.get("password") is not None:
            print("  ★ 命中！", r2)
            return 0
        print(f"  {name} 未命中")

    # ── ② 7-Zip 尝试（含密码） ──
    hr("② 7-Zip 尝试（含密码）")
    sevenz = r"D:\7zip\7-Zip\7z.exe"
    if os.path.isfile(sevenz):
        for c in CANDS[:2]:
            pr = subprocess.run([sevenz, "l", "-p" + c, VOL],
                                capture_output=True, text=True,
                                encoding="utf-8", errors="replace")
            err = (pr.stderr or "").strip().splitlines()
            tail = err[-1] if err else ""
            print(f"  密码 {c!r} → rc={pr.returncode}  {tail[:110]}")
    else:
        print("  未找到 7z.exe")

    hr("结论")
    print("  以上均未命中 → 需要另想办法（见输出上方提示）")
    return 2


if __name__ == "__main__":
    sys.exit(main())
