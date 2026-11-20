# -*- coding: utf-8 -*-
r"""
2025 平航杯 · **真实检材冒烟测试**

在**真实的加密容器**（VeraCrypt + exFAT）里，对真实的大检材跑一遍
EWF / VMDK 解析器，验证它们在生产数据上成立。

全程：
  · **只读**（不写任何检材）
  · **不启动服务**
  · **不碰用户正在运行的 MemLens**（桌面版 PID 与 8765 端口完全不受影响）
  · 唯一写入是临时目录下的报告

用法：
    python tools/smoke_real.py
"""

from __future__ import annotations

import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memlens.core.veracrypt_volume import VeraCryptVolume      # noqa: E402
from memlens.core.exfat import ExFat                           # noqa: E402
from memlens.formats.ewf import EwfReader                     # noqa: E402
from memlens.formats.vmdk import VmdkDisk                     # noqa: E402

VOL = os.environ.get("PINGHANG_VOL", r"E:\2025平航杯\平航杯题目")
PW = os.environ.get("PINGHANG_PW", "早起王的爱恋日记❤")

PASS = 0
FAIL: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS
    if ok:
        PASS += 1
        print(f"  ✅ {name}　{detail}")
    else:
        FAIL.append(name)
        print(f"  ❌ {name}　{detail}")


class VolumeFile:
    """把卷内文件包装成可随机访问的 reader（不落盘）。"""

    def __init__(self, vol: VeraCryptVolume, fs: ExFat, ent: dict) -> None:
        self.vol, self.fs, self.ent = vol, fs, ent
        self.size = ent["data_len"]
        self._chain: list[int] | None = None

    def _clusters(self) -> list[int]:
        if self._chain is None:
            need = (self.size + self.fs.cluster_size - 1) // self.fs.cluster_size
            self._chain = []
            for c in self.fs.chain(self.ent["first_cluster"]):
                self._chain.append(c)
                if len(self._chain) >= need:
                    break
        return self._chain

    def read(self, off: int, n: int) -> bytes:
        out = bytearray()
        if self.ent["no_fat_chain"]:
            base = self.fs.cluster_offset(self.ent["first_cluster"])
            while len(out) < n:
                out += self.vol.read(base + off + len(out), min(4 << 20, n - len(out)))
            return bytes(out)
        csize = self.fs.cluster_size
        ci, co = divmod(off, csize)
        chain = self._clusters()
        while len(out) < n and ci < len(chain):
            blk = self.fs.read_cluster(chain[ci])
            take = min(len(blk) - co, n - len(out))
            out += blk[co:co + take]
            ci += 1
            co = 0
        return bytes(out)


def main() -> int:
    print("=" * 78)
    print("真实检材冒烟测试 —— 2025 平航杯")
    print(f"  容器: {VOL}")
    print("=" * 78)

    t0 = time.time()
    vol = VeraCryptVolume(VOL, PW)
    fs = ExFat(vol)
    print(f"\n[容器] 已打开（{time.time() - t0:.1f}s）")

    def find(name: str):
        for e in fs.list_dir(fs.root_cluster):
            if e["name"].lower() == name.lower():
                return e
        return None

    # ───────────────────────── EWF ─────────────────────────
    print("\n" + "=" * 78)
    print("① EWF 冒烟：window.e01（55 GB，在加密卷内直接读，不落盘）")
    print("=" * 78)
    ent = find("window.e01")
    if not ent:
        check("找到 window.e01", False)
    else:
        rdr = VolumeFile(vol, fs, ent)
        t1 = time.time()
        ew = EwfReader(reader=rdr)
        s = ew.summary()
        print(f"  文件 {s['file_size']:,} 字节   节 {s['section_count']} 个   "
              f"数据节 {s['data_sections']} 个   压缩 {s['compression']}")
        print(f"  节链前 8: {s['sections'][:8]}")
        check("节链被识别", s["section_count"] > 3, f"{s['section_count']} 节")
        check("节名含 sectors/table", "sectors" in s["sections"], str(s["sections"][:6]))

        # 逻辑首块：应为客户机磁盘的引导扇区
        t2 = time.time()
        head = ew.read_at(0, 512)
        print(f"  逻辑首 512 字节（{time.time() - t2:.1f}s）: {head[:16].hex(' ')}")
        check("逻辑首块可读", len(head) == 512)
        check("引导扇区有 55AA 签名", head[510:512] == b"\x55\xaa",
              head[510:512].hex())
        # ★ 引导扇区分两类，别混：
        #   NTFS/FAT 的引导扇区 offset 3 是 8 字节 OEM 名；
        #   **MBR 分区表引导扇区没有 OEM 字段**（offset 3 起是引导代码），
        #   它的特征是 offset 446 起的分区表 + 末尾 55AA。
        oem = head[3:11]
        if all(32 <= c < 127 for c in oem):
            check("OEM 字段可读（NTFS/FAT 引导扇区）", True, repr(oem))
        else:
            part_sig = head[446:462]
            check("为 MBR 分区表引导扇区（无 OEM 字段）",
                  head[510:512] == b"\x55\xaa" and any(part_sig),
                  f"分区表@{part_sig.hex()[:32]}")
            pt = [struct.unpack_from("<I", head, 446 + i * 16)[0]
                  for i in range(4)]
            print(f"     MBR 4 个分区: {[hex(x) for x in pt]}")

        # 再往后读一块，验证能顺序推进
        t3 = time.time()
        blk2 = ew.read_at(32768, 512)
        print(f"  逻辑偏移 32768 处: {blk2[:16].hex(' ')}")
        check("可顺序推进读取", len(blk2) == 512)

    # ───────────────────────── VMDK ─────────────────────────
    print("\n" + "=" * 78)
    print("② VMDK 冒烟：export-disk0-000002.vmdk（15.9 GB，50 GiB 虚拟盘）")
    print("=" * 78)
    ent2 = find("export-disk0-000002.vmdk")
    if not ent2:
        check("找到 vmdk", False)
    else:
        rdr2 = VolumeFile(vol, fs, ent2)
        t4 = time.time()
        vd = VmdkDisk(reader=rdr2)
        s2 = vd.summary()
        print(f"  布局 {s2['create_type']}   虚拟容量 {s2['capacity_sectors']:,} 扇区"
              f"（{s2['capacity_gb']} GiB）")
        print(f"  grain {s2['grain_size_sectors']} 扇区（{s2['grain_size_kb']} KiB）"
              f"   每表 {s2['num_gtes_per_gt']} 项")
        print(f"  gd_offset={s2['gd_offset']:,}  rgd={s2['rgd_offset']:,}"
              f"  over_head={s2['over_head']:,}")
        check("布局识别为稀疏盘", "sparse" in s2["create_type"].lower(),
              s2["create_type"])
        check("虚拟容量 50 GiB", abs(s2["capacity_gb"] - 50.0) < 0.1,
              str(s2["capacity_gb"]))
        check("grain 大小 64 KiB", s2["grain_size_kb"] == 64, str(s2["grain_size_kb"]))

        # 虚拟扇区 0 → 物理扇区 → 引导扇区
        ps = vd.physical_sector(0)
        print(f"  虚拟扇区 0 → 物理扇区 {ps:,}")
        check("虚拟→物理映射有效", ps != 0, f"phys={ps}")
        boot = vd.read_at(0, 512)
        print(f"  虚拟偏移 0 的 512 字节: {boot[:16].hex(' ')}")
        check("读到引导扇区", boot[510:512] == b"\x55\xaa", boot[510:512].hex())
        check("引导码是 x86 jmp", boot[0:2] == b"\xeb\x63", boot[:2].hex())
        check("grain 映射与 over_head 一致", ps == s2["over_head"],
              f"phys={ps} over_head={s2['over_head']}")

        # 未分配区域应返回全零
        t5 = time.time()
        far = vd.read_at(s2["capacity_sectors"] * 512 - 1024, 1024)
        check("未分配尾部返回全零", far == b"\x00" * 1024,
              f"{time.time() - t5:.1f}s")

    vol.close()
    print("\n" + "=" * 78)
    print(f"冒烟测试：通过 {PASS} 项，失败 {len(FAIL)} 项")
    for f in FAIL:
        print("  ❌", f)
    print("=" * 78)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
