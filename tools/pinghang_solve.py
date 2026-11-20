# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 检材容器开箱（VeraCrypt + exFAT，用户态、零驱动、零管理员）

背景：
    检材容器是 VeraCrypt 卷（AES-256-XTS / PBKDF2-HMAC-SHA512×500000），
    密码由西电取证 Wiki 公布：`早起王的爱恋日记❤`
    卷内是 exFAT 文件系统。

用法：
    python tools/pinghang_solve.py --info              # 卷信息 + 根目录
    python tools/pinghang_solve.py --tree              # 递归列目录
    python tools/pinghang_solve.py --zip <卷内路径>      # 只读 zip 中央目录
    python tools/pinghang_solve.py --get <卷内路径>      # 提取单个文件到 work/pinghang/
"""

from __future__ import annotations

import argparse
import io
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memlens.core.veracrypt_volume import VeraCryptVolume      # noqa: E402
from memlens.core.exfat import ExFat                           # noqa: E402

VOL = os.environ.get("PINGHANG_VOL", r"E:\2025平航杯\平航杯题目")
PW = os.environ.get("PINGHANG_PW", "早起王的爱恋日记❤")
OUT = Path(os.environ.get("PINGHANG_OUT", r"D:\MemLens\work\pinghang"))


def open_vol() -> tuple[VeraCryptVolume, ExFat]:
    v = VeraCryptVolume(VOL, PW)
    return v, ExFat(v)


def find_entry(fs: ExFat, path: str) -> dict | None:
    """按卷内绝对路径找条目。"""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    cur = fs.root_cluster
    ent = None
    for i, part in enumerate(parts):
        found = None
        for e in fs.list_dir(cur):
            if e["name"].lower() == part.lower():
                found = e
                break
        if not found:
            return None
        ent = found
        cur = found["first_cluster"]
    return ent


def cmd_info() -> int:
    v, fs = open_vol()
    print("=" * 74)
    print("卷信息")
    print("=" * 74)
    for k, val in v.summary().items():
        print(f"  {k:24} {val:,}" if isinstance(val, int) and val > 99999
              else f"  {k:24} {val}")
    print("\n" + "=" * 74)
    print("exFAT")
    print("=" * 74)
    for k, val in fs.summary().items():
        print(f"  {k:24} {val:,}" if isinstance(val, int) and val > 9999
              else f"  {k:24} {val}")
    print("\n" + "=" * 74)
    print("根目录")
    print("=" * 74)
    for e in fs.list_dir(fs.root_cluster):
        kind = "DIR " if e["is_dir"] else "FILE"
        print(f"  {kind} {e['size']:>16,}  {e['mtime']:<20} {e['name']}")
    v.close()
    return 0


def cmd_tree(depth: int) -> int:
    v, fs = open_vol()
    for e in fs.walk(max_depth=depth):
        if "error" in e:
            print(f"  ! {e['path']}: {e['error']}")
            continue
        kind = "DIR " if e["is_dir"] else "FILE"
        print(f"  {kind} {e['size']:>16,}  {e['path']}")
    v.close()
    return 0


def cmd_zip(path: str) -> int:
    """只读 zip 的中央目录（不整包读取）。"""
    v, fs = open_vol()
    ent = find_entry(fs, path)
    if not ent:
        print("找不到:", path)
        return 1
    size = ent["data_len"]
    print(f"zip: {ent['name']}  {size:,} 字节（{size/1024**3:.2f} GiB）")

    def read_at(off: int, n: int) -> bytes:
        if ent["no_fat_chain"]:
            return fs.read_contiguous(ent["first_cluster"], size)[off:off + n] \
                if False else _contig(fs, ent, off, n)
        return _chained(fs, ent, off, n)

    def _contig(fs, ent, off, n):
        base = fs.cluster_offset(ent["first_cluster"]) + off
        return v.read(base, n)

    def _chained(fs, ent, off, n):
        csize = fs.cluster_size
        ci, co = divmod(off, csize)
        out = bytearray()
        for idx, c in enumerate(fs.chain(ent["first_cluster"])):
            if idx < ci:
                continue
            out += fs.read_cluster(c)[co:] if idx == ci else fs.read_cluster(c)
            co = 0
            if len(out) >= n:
                break
        return bytes(out[:n])

    tail = read_at(max(0, size - 65557), min(65557, size))
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        print("未找到 EOCD —— 可能不是 zip，或需要密码")
        return 1
    cd_size, cd_off = struct.unpack("<II", tail[i + 12:i + 20])
    total = struct.unpack("<H", tail[i + 10:i + 12])[0]
    print(f"中央目录: offset={cd_off:,} size={cd_size:,} 条目={total}")
    if cd_off == 0xFFFFFFFF:
        j = tail.rfind(b"PK\x06\x06")
        if j >= 0:
            total = struct.unpack("<Q", tail[j + 32:j + 40])[0]
            cd_size = struct.unpack("<Q", tail[j + 40:j + 48])[0]
            cd_off = struct.unpack("<Q", tail[j + 48:j + 56])[0]
            print(f"Zip64: offset={cd_off:,} size={cd_size:,} 条目={total}")
    cd = read_at(cd_off, cd_size)
    print("-" * 74)
    k = 0
    n_shown = 0
    while k + 46 <= len(cd) and n_shown < 400:
        if cd[k:k + 4] != b"PK\x01\x02":
            break
        comp = struct.unpack("<H", cd[k + 10:k + 12])[0]
        csize = struct.unpack("<I", cd[k + 20:k + 24])[0]
        usize = struct.unpack("<I", cd[k + 24:k + 28])[0]
        nlen = struct.unpack("<H", cd[k + 28:k + 30])[0]
        elen = struct.unpack("<H", cd[k + 30:k + 32])[0]
        clen = struct.unpack("<H", cd[k + 32:k + 34])[0]
        flags = struct.unpack("<H", cd[k + 8:k + 10])[0]
        name = cd[k + 46:k + 46 + nlen].decode("utf-8", "replace")
        enc = " 🔒加密" if flags & 1 else ""
        print(f"  {usize:>14,} → {csize:>14,}  m={comp}  {name}{enc}")
        n_shown += 1
        k += 46 + nlen + elen + clen
    print(f"\n共列出 {n_shown} 条（截断到 400）")
    v.close()
    return 0


def cmd_get(path: str, limit: int | None) -> int:
    v, fs = open_vol()
    ent = find_entry(fs, path)
    if not ent:
        print("找不到:", path)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    dst = OUT / Path(ent["name"]).name
    total = ent["data_len"] if limit is None else min(limit, ent["data_len"])
    print(f"提取 {ent['name']}  {total:,} 字节 → {dst}")
    t0 = time.time()
    csize = fs.cluster_size
    written = 0
    with dst.open("wb") as f:
        if ent["no_fat_chain"]:
            base = fs.cluster_offset(ent["first_cluster"])
            step = 4 << 20
            while written < total:
                n = min(step, total - written)
                f.write(v.read(base + written, n))
                written += n
                _prog(written, total, t0)
        else:
            for c in fs.chain(ent["first_cluster"]):
                data = fs.read_cluster(c)
                n = min(len(data), total - written)
                f.write(data[:n])
                written += n
                _prog(written, total, t0)
                if written >= total:
                    break
    print(f"\n完成：{dst}  {written:,} 字节  {time.time()-t0:.1f}s")
    v.close()
    return 0


def _prog(done: int, total: int, t0: float) -> None:
    if total <= 0:
        return
    pct = done * 100 // total
    mb = done / 1024 / 1024
    el = time.time() - t0
    sp = mb / el if el > 0.2 else 0
    sys.stdout.write(f"\r  {pct:3d}%  {mb:8.1f}/{total/1024/1024:.0f} MB  {sp:5.1f} MB/s")
    sys.stdout.flush()


def main() -> int:
    ap = argparse.ArgumentParser(description="2025 平航杯检材容器开箱")
    ap.add_argument("--info", action="store_true", help="卷信息 + 根目录")
    ap.add_argument("--tree", action="store_true", help="递归列目录")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--zip", metavar="PATH", help="读 zip 中央目录")
    ap.add_argument("--get", metavar="PATH", help="提取文件")
    ap.add_argument("--limit", type=int, default=None, help="只取前 N 字节")
    a = ap.parse_args()
    if a.info or not any([a.tree, a.zip, a.get]):
        return cmd_info()
    if a.tree:
        return cmd_tree(a.depth)
    if a.zip:
        return cmd_zip(a.zip)
    if a.get:
        return cmd_get(a.get, a.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
