# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 从检材容器里按需取证

容器结构：
    VeraCrypt(AES-256-XTS) → exFAT →
        window.e01            55 GB   计算机检材
        20250415_181118.zip   1.93 GB 手机备份（内含 APK 与 app 数据）
        BLE                   5.9 MB  蓝牙流量
        USBPcap               292 KB  USB 抓包
        export-disk0-*.vmdk   15.9 GB 服务器（虚拟机磁盘）

关键技巧：**给 zipfile 套一个"从解密卷读字节"的文件对象**，
         这样就能用标准库 zipfile 只解出需要的成员，而不必把 1.93 GB 全解出来。
"""

from __future__ import annotations

import hashlib
import io
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memlens.core.veracrypt_volume import VeraCryptVolume
from memlens.core.exfat import ExFat

VOL = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记❤"
OUT = Path(r"D:\MemLens\work\pinghang")


class ExFatFile(io.RawIOBase):
    """把一个 exFAT 文件包装成可随机读的文件对象（供 zipfile 使用）。"""

    def __init__(self, vol: VeraCryptVolume, fs: ExFat, ent: dict) -> None:
        self.vol, self.fs, self.ent = vol, fs, ent
        self.size = ent["data_len"]
        self.pos = 0
        self.csize = fs.cluster_size
        self._chain: list[int] | None = None

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, off: int, whence: int = 0) -> int:
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        else:
            self.pos = self.size + off
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""
        out = self._read_at(self.pos, n)
        self.pos += len(out)
        return out

    def _read_at(self, off: int, n: int) -> bytes:
        if self.ent["no_fat_chain"]:
            base = self.fs.cluster_offset(self.ent["first_cluster"])
            return self.vol.read(base + off, n)
        if self._chain is None:
            need = (self.size + self.csize - 1) // self.csize
            self._chain = []
            for c in self.fs.chain(self.ent["first_cluster"]):
                self._chain.append(c)
                if len(self._chain) >= need:
                    break
        ci, co = divmod(off, self.csize)
        out = bytearray()
        while len(out) < n and ci < len(self._chain):
            blk = self.fs.read_cluster(self._chain[ci])
            take = blk[co:co + (n - len(out))]
            out += take
            ci += 1
            co = 0
        return bytes(out)


def find(vol, fs, path: str) -> dict | None:
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    cur = fs.root_cluster
    ent = None
    for part in parts:
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


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    vol = VeraCryptVolume(VOL, PW)
    fs = ExFat(vol)
    print(f"卷已打开（{time.time()-t0:.1f}s）\n")

    # ── ① 根目录小文件直接取出 ──
    for name in ("BLE", "USBPcap"):
        e = find(vol, fs, name)
        if not e:
            print(f"  跳过 {name}（未找到）")
            continue
        dst = OUT / name
        t = time.time()
        with dst.open("wb") as f:
            if e["no_fat_chain"]:
                base = fs.cluster_offset(e["first_cluster"])
                done = 0
                while done < e["data_len"]:
                    n = min(4 << 20, e["data_len"] - done)
                    f.write(vol.read(base + done, n))
                    done += n
            else:
                done = 0
                for c in fs.chain(e["first_cluster"]):
                    d = fs.read_cluster(c)
                    n = min(len(d), e["data_len"] - done)
                    f.write(d[:n])
                    done += n
                    if done >= e["data_len"]:
                        break
        md5 = hashlib.md5(dst.read_bytes()).hexdigest()
        print(f"  ✓ {name:10} {e['data_len']:>12,} 字节  {time.time()-t:5.1f}s  md5={md5}")

    # ── ② 手机备份 zip：只解需要的成员 ──
    zent = find(vol, fs, "20250415_181118.zip")
    if zent:
        print(f"\n手机备份 zip：{zent['data_len']:,} 字节")
        zf_obj = ExFatFile(vol, fs, zent)
        t = time.time()
        with zipfile.ZipFile(zf_obj) as z:
            names = z.namelist()
            print(f"  成员 {len(names)} 个（{time.time()-t:.1f}s 读中央目录）")
            want = [n for n in names
                    if n.lower().endswith(("descript.xml", "puzzle_game.apk",
                                           "fix2_sign.apk", "qidm"))]
            for n in want:
                info = z.getinfo(n)
                dst = OUT / Path(n).name
                t2 = time.time()
                with z.open(n) as src, dst.open("wb") as out:
                    while True:
                        b = src.read(1 << 20)
                        if not b:
                            break
                        out.write(b)
                data = dst.read_bytes()
                print(f"  ✓ {Path(n).name:22} {len(data):>11,} 字节  "
                      f"{time.time()-t2:5.1f}s  md5={hashlib.md5(data).hexdigest()}")
    else:
        print("  未找到手机备份 zip")

    vol.close()
    print(f"\n总耗时 {time.time()-t0:.1f}s   输出目录：{OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
