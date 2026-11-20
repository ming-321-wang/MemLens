r"""
MemLens · VMDK（VMware 虚拟磁盘）稀疏盘解析

## 真实格式（2025 平航杯 `export-disk0-000002.vmdk` 实测反推）

稀疏盘（monolithicSparse）的头部在文件开头：

    0   u32  magic        0x564D444B ('KDMV')
    4   u32  version      1
    8   u32  flags        3
    12  u64  capacity     虚拟容量（扇区）
    20  u64  grain_size   每 grain 的扇区数（128 = 64 KiB）
    28  u64  descriptor_offset
    36  u64  descriptor_size
    44  u32  num_gtes_per_gt   每个 grain 表的条目数
    48  u64  rgd_offset        冗余 grain 目录（备份）
    56  u64  gd_offset         grain 目录
    64  u32  over_head         首个已分配 grain 的扇区
    68  u32  unclean_shutdown

## 映射链（实测值）

    虚拟扇区 v
      → grain 序号 g = v // grain_size
      → grain 目录项 gd[g // num_gtes_per_gt]  = grain 表所在扇区（u32）
      → grain 表项 gt[g % num_gtes_per_gt]      = 该 grain 所在扇区（u32，0 = 未分配）
      → 物理扇区 = gt[…]，文件偏移 = 物理扇区 * 512

★ **目录项和表项都是 u32，不是 u64** —— 实测 `gd = [6447, 6451, …]`（步长 4 扇区
  = 512 条 × 4 字节）、`gt = [12928, 13056, …]`（步长 128 扇区 = 一个 grain）。
  按 u64 读会得到完全离谱的数值（实测 2.7e13），**这正是第一版解析器错的地方**。

★ `over_head`（12928）正好等于第一个 grain 的物理扇区 → 该处是**客户机磁盘的
  引导扇区**（实测 `eb 63 90` = 标准 x86 引导头），可用来验证映射是否正确。

## 支持直接跑在加密卷上

`reader` 参数让本模块可以**不落盘**直接读容器里的 VMDK。
"""

from __future__ import annotations

import struct
from typing import Any, Iterator

#: 稀疏盘魔数
MAGIC = 0x564D444B

#: 描述符文件头标识
DESCRIPTOR_MARK = b"# Disk DescriptorFile"


class VmdkError(RuntimeError):
    """VMDK 解析失败。"""


class VmdkDisk:
    """
    VMDK 只读访问器（支持 monolithicSparse 与 flat/描述符）。

    Args:
        path: 文件路径（与 reader 二选一）
        reader: 可按偏移读的字节源（用于直接读加密卷里的文件）
    """

    def __init__(self, path: str | None = None, *, reader: Any = None) -> None:
        if reader is None and not path:
            raise VmdkError("需要 path 或 reader")
        self.path = path
        self.reader = reader
        self._fh = open(path, "rb") if path else None
        if self._fh:
            self._fh.seek(0, 2)
            self.size = self._fh.tell()
            self._fh.seek(0)
        else:
            self.size = int(getattr(reader, "size", 0))
        self.descriptor: dict[str, str] = {}
        self.extents: list[dict[str, Any]] = []
        self.create_type = ""
        self.capacity = 0            # 虚拟容量（扇区）
        self.grain_size = 128
        self.num_gtes_per_gt = 512
        self.gd_offset = 0
        self.rgd_offset = 0
        self.over_head = 0
        self._gd: dict[int, int] = {}
        self._gt: dict[int, int] = {}
        self._gt_loaded: set[int] = set()
        self._parse()

    # ------------------------------------------------------------ 底层读
    def read(self, off: int, n: int) -> bytes:
        """按**文件偏移**读原始字节（供 ext4 等上层格式复用）。"""
        if off < 0 or n <= 0:
            return b""
        if self._fh:
            self._fh.seek(off)
            return self._fh.read(n)
        return self.reader.read(off, n)

    #: 兼容旧名
    _read = read

    def _u32(self, off: int) -> int:
        b = self._read(off, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else 0

    # ------------------------------------------------------------ 解析
    def _parse(self) -> None:
        head = self._read(0, 512)
        if len(head) < 64:
            raise VmdkError("文件太小")
        if struct.unpack_from("<I", head, 0)[0] == MAGIC:
            self._parse_sparse(head)
            return
        txt = head.decode("latin-1", "ignore")
        if txt.startswith("# Disk DescriptorFile") or "createType" in txt:
            self._parse_descriptor(txt)
            return
        # flat
        self.create_type = "flat"
        self.capacity = self.size // 512

    def _parse_descriptor(self, txt: str) -> None:
        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                self.descriptor[k.strip()] = v.strip().strip('"')
            elif line.upper().startswith(("RW ", "RDONLY ", "NOACCESS ")):
                p = line.split()
                self.extents.append({
                    "access": p[0],
                    "sectors": int(p[1]) if len(p) > 1 and p[1].isdigit() else 0,
                    "type": p[2] if len(p) > 2 else "",
                    "file": p[3].strip('"') if len(p) > 3 else "",
                    "offset": int(p[4]) if len(p) > 4 and p[4].isdigit() else 0,
                })
        self.create_type = self.descriptor.get("createType", "")
        self.capacity = sum(e.get("sectors", 0) for e in self.extents)
        if self.create_type in ("monolithicSparse",):
            self._parse_sparse(self._read(0, 512))

    def _parse_sparse(self, head: bytes) -> None:
        self.create_type = self.create_type or "monolithicSparse"
        (_magic, _ver, _flags) = struct.unpack_from("<III", head, 0)
        (self.capacity, self.grain_size, self._desc_off,
         self._desc_sz) = struct.unpack_from("<QQQQ", head, 12)
        self.num_gtes_per_gt = struct.unpack_from("<I", head, 44)[0] or 512
        self.rgd_offset, self.gd_offset = struct.unpack_from("<QQ", head, 48)
        self.over_head = struct.unpack_from("<I", head, 64)[0]

    # ------------------------------------------------------------ grain 映射
    def _gd_entry(self, idx: int) -> int:
        """grain 目录第 idx 项 = grain 表所在扇区（u32）。"""
        if idx in self._gd:
            return self._gd[idx]
        v = self._u32(self.gd_offset * 512 + idx * 4)
        self._gd[idx] = v
        return v

    def _gt_entry(self, grain: int) -> int:
        """grain 表中第 grain 项 = 该 grain 的物理扇区（u32，0 = 未分配）。"""
        if grain in self._gt:
            return self._gt[grain]
        gd_idx = grain // self.num_gtes_per_gt
        gt_sector = self._gd_entry(gd_idx)
        if not gt_sector:
            self._gt[grain] = 0
            return 0
        # ★ 一次读整个 GT（num_gtes_per_gt 个 u32）并缓存，
        #   避免逐 grain 4 字节读把大范围扫描拖死（实测 2.7MB/s → 数十 MB/s）。
        if gd_idx not in self._gt_loaded:
            gt = self._read(gt_sector * 512, self.num_gtes_per_gt * 4)
            base = gd_idx * self.num_gtes_per_gt
            for i in range(self.num_gtes_per_gt):
                self._gt[base + i] = (struct.unpack_from("<I", gt, i * 4)[0]
                                      if len(gt) >= i * 4 + 4 else 0)
            self._gt_loaded.add(gd_idx)
        return self._gt[grain]

    def physical_sector(self, virtual_sector: int) -> int:
        """
        虚拟扇区 → 物理扇区（0 = 未分配）。

        ★ grain 表项给的是 **grain 的起始物理扇区**，
          grain 内的偏移必须自己加回去，否则整盘只会反复读到每个 grain 的头 512 字节
          （第一版解析器就栽在这里：逻辑扫描看起来"什么都没有"）。
        """
        grain = virtual_sector // self.grain_size
        base = self._gt_entry(grain)
        if not base:
            return 0
        return base + (virtual_sector % self.grain_size)

    # ------------------------------------------------------------ 读取
    def read_at(self, offset: int, length: int) -> bytes:
        """
        按**虚拟盘偏移**读数据（未分配区域返回全零）。

        ★ 已分配 grain 在 grain 表里通常是**连续**的（phys = 虚拟扇区 + 常数），
          因此把连续已分配 grain 聚合成一个整块 `_read`，避免逐 64 KiB 解密
          把吞吐压死（实测 2.7MB/s → 数十 MB/s）。
        """
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            vs = pos // 512
            within = vs % self.grain_size
            grain = vs // self.grain_size
            base = self._gt_entry(grain)
            if not base:
                take = min((self.grain_size - within) * 512, end - pos)
                out += b"\x00" * take
                pos += take
                continue
            # 找连续已分配 run：grain..g（物理连续）
            g = grain
            b = base
            while True:
                ng = g + 1
                nb = self._gt_entry(ng)
                if nb != b + self.grain_size:
                    break
                g = ng
                b = nb
            run_start = (base + within) * 512
            run_len = (g - grain + 1) * self.grain_size * 512 - within * 512
            take = min(run_len, end - pos)
            chunk = self._read(run_start, take)
            if not chunk:
                chunk = b"\x00" * take
            out += chunk[:take]
            pos += take
        return bytes(out[:length])

    # ------------------------------------------------------------ 摘要
    def summary(self) -> dict[str, Any]:
        return {
            "path": str(self.path or "reader"),
            "create_type": self.create_type or "(未标注)",
            "capacity_sectors": self.capacity,
            "capacity_gb": round(self.capacity * 512 / 1024 ** 3, 2),
            "grain_size_sectors": self.grain_size,
            "grain_size_kb": self.grain_size * 512 // 1024,
            "num_gtes_per_gt": self.num_gtes_per_gt,
            "gd_offset": self.gd_offset,
            "rgd_offset": self.rgd_offset,
            "over_head": self.over_head,
            "file_size": self.size,
            "descriptor": dict(self.descriptor),
        }

    def records(self) -> Iterator[dict[str, Any]]:
        s = self.summary()
        yield {"项目": "文件", "值": s["path"], "说明": "VMDK"}
        yield {"项目": "布局", "值": s["create_type"], "说明": "createType"}
        yield {"项目": "虚拟容量", "值": f"{s['capacity_sectors']:,} 扇区"
                                  f"（{s['capacity_gb']} GiB）", "说明": ""}
        yield {"项目": "grain 大小", "值": f"{s['grain_size_sectors']} 扇区"
                                       f"（{s['grain_size_kb']} KiB）", "说明": ""}
        yield {"项目": "每表条目数", "值": str(s["num_gtes_per_gt"]), "说明": "num_gtes_per_gt"}
        yield {"项目": "grain 目录", "值": f"sector {s['gd_offset']:,}", "说明": "gd_offset"}
        yield {"项目": "冗余目录", "值": f"sector {s['rgd_offset']:,}", "说明": "rgd_offset"}
        yield {"项目": "over_head", "值": f"sector {s['over_head']:,}", "说明": "首个已分配 grain"}
        for k, v in s["descriptor"].items():
            yield {"项目": f"descriptor.{k}", "值": v, "说明": ""}

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass

    def __enter__(self) -> "VmdkDisk":
        return self

    def __exit__(self, *a) -> None:
        self.close()
