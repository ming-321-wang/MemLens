# -*- coding: utf-8 -*-
"""在题目目录遗留的 IDA 数据库里搜注释/字符串（前人可能留下了私钥或 argv）。"""
import re
from pathlib import Path

BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
STEM = BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5"

for ext in (".id1", ".id2", ".nam", ".til", ".id0"):
    p = STEM.with_suffix(ext)
    if not p.exists():
        continue
    blob = p.read_bytes()
    print("=" * 70)
    print(f"{p.name}  ({len(blob):,} B)")
    print("=" * 70)
    # 可打印 ASCII 串（长度>=5）
    seen = []
    for m in re.finditer(rb"[ -~]{5,}", blob):
        s = m.group().decode("latin1")
        seen.append(s)
    # 过滤掉明显是 IDA 内部的噪声
    noise = ("IDAT", "IDA ", r"\.id", "sha256", "SHA-256", "BTree", "node", "IDB", "netnode",
             "checksum", "version", "unused", "blob", "linear", "md5", "%s")
    interesting = [s for s in seen if not any(n.lower() in s.lower() for n in noise)]
    print(f"可打印串 {len(seen)} 个，过滤后 {len(interesting)} 个：")
    for s in interesting[:60]:
        print(f"   {s!r}")

    # 关键：搜 16 进制大数 / 0x 串 / 数字
    hexes = [s for s in seen if re.fullmatch(r"(0x)?[0-9a-fA-F]{20,60}", s)]
    if hexes:
        print(f"十六进制串 {len(hexes)} 个：")
        for s in hexes[:20]:
            print(f"   {s}")
