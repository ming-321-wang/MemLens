r"""
MemLens · EXFAT 只读解析（配合 VeraCrypt 用户态读取器）

## 为什么是 EXFAT

2025 平航杯检材容器（VeraCrypt，AES-256-XTS）里面是 **exFAT** 文件系统，
不是 NTFS —— 所以按 NTFS 的引导扇区特征（`EB 52 90 'NTFS    '`）去找会一直找不到。
exFAT 引导扇区特征在偏移 3 处是 `EXFAT   `。

## exFAT 为什么比 NTFS 好读

exFAT 没有 MFT，目录就是**普通的簇链**，簇里是 32 字节定长目录项：

    0x85  File Entry        属性 + 时间戳
    0xC0  Stream Extension  首簇号 + 数据长度
    0xC1  File Name         文件名（UTF-16LE，最多 15 字符/项）
    0x81  Allocation Bitmap

一组条目（File → Stream → FileName×N）描述一个文件。跟着 FAT 链就能遍历整棵树，
不用像 NTFS 那样解析 MFT record / 属性头 / runlist。

## 一个容易踩的坑：NoFatChain

Stream Extension 的第 1 个字节里有 `NoFatChain` 标志位（0x02）。
置位时表示**文件在簇堆里是连续存放的**，此时数据不跟 FAT 链走，
而是从首簇号开始连续占 `DataLength` 字节。
按 FAT 链读会读错（尤其在容器里这种"一次写入、连续分配"的场景，这个标志很常见）。

参考：Microsoft exFAT 文件系统规范。
"""

from __future__ import annotations

import struct
from typing import Any, Iterator

ENTRY_END = 0x00
ENTRY_BITMAP = 0x81
ENTRY_UPCASE = 0x82
ENTRY_LABEL = 0x83
ENTRY_FILE = 0x85
ENTRY_STREAM = 0xC0
ENTRY_NAME = 0xC1

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


class ExFat:
    """只读 exFAT。所有读取都经底层卷（可解密）完成。"""

    def __init__(self, vol: Any, verbose: bool = False) -> None:
        self.vol = vol
        boot = vol.read(0, 512)
        if boot[3:11] != b"EXFAT   ":
            raise ValueError(f"不是 exFAT 引导扇区：oem={boot[3:11]!r}")
        self.boot = boot
        self.bps_shift = boot[108]
        self.spc_shift = boot[109]
        self.bps = 1 << self.bps_shift                       # 字节/扇区
        self.spc = 1 << self.spc_shift                       # 扇区/簇
        self.cluster_size = self.bps * self.spc
        self.fat_offset = u32(boot, 80) * self.bps           # FAT 起点（字节，相对数据区）
        self.fat_length = u32(boot, 84)
        self.heap_offset = u32(boot, 88) * self.bps          # 簇堆起点（字节）
        self.cluster_count = u32(boot, 92)
        self.root_cluster = u32(boot, 96)
        self.serial = u32(boot, 100)
        self.revision = f"{u16(boot,104)>>8}.{(u16(boot,104)&0xFF)}"
        self.n_fats = boot[110]
        self.percent_in_use = boot[112]
        self.volume_label = self._read_label()
        self._fat_cache: dict[int, int] = {}

    # ------------------------------------------------------------ 基础
    def cluster_offset(self, cluster: int) -> int:
        return self.heap_offset + (cluster - 2) * self.cluster_size

    def read_cluster(self, cluster: int) -> bytes:
        return self.vol.read(self.cluster_offset(cluster), self.cluster_size)

    def fat_next(self, cluster: int) -> int:
        # 注意：FAT 表项是 4 字节，从 FAT 起点开始按簇号索引（簇 0/1 保留）
        v = self._fat_cache.get(cluster)
        if v is None:
            raw = self.vol.read(self.fat_offset + cluster * 4, 4)
            v = u32(raw, 0)
            self._fat_cache[cluster] = v
        return v

    def chain(self, cluster: int, *, limit: int = 2_000_000) -> Iterator[int]:
        seen = 0
        c = cluster
        while 2 <= c < 0xFFFFFFF7 and seen < limit:
            yield c
            seen += 1
            nxt = self.fat_next(c)
            if nxt == c:
                break
            c = nxt

    def read_chain(self, cluster: int, length: int | None = None) -> bytes:
        out = bytearray()
        for c in self.chain(cluster):
            out += self.read_cluster(c)
            if length is not None and len(out) >= length:
                break
        return bytes(out[:length]) if length is not None else bytes(out)

    def read_contiguous(self, cluster: int, length: int) -> bytes:
        """NoFatChain：连续存放，直接从首簇读 length 字节。"""
        return self.vol.read(self.cluster_offset(cluster), length)

    def _read_label(self) -> str:
        try:
            c = self.root_cluster
            buf = self.read_chain(c, self.cluster_size * 4)
            for off in range(0, len(buf), 32):
                t = buf[off]
                if t == ENTRY_END:
                    break
                if t == ENTRY_LABEL:
                    n = buf[off + 1]
                    return buf[off + 2:off + 2 + n * 2].decode("utf-16-le", "replace")
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------ 目录
    def list_dir(self, cluster: int) -> list[dict[str, Any]]:
        """列出一个目录簇链里的所有条目。"""
        buf = self.read_chain(cluster, self.cluster_size * 4096)
        out: list[dict[str, Any]] = []
        i = 0
        n = len(buf)
        while i + 32 <= n:
            t = buf[i]
            if t == ENTRY_END:
                break
            if t == ENTRY_FILE:
                ent = self._parse_file_set(buf, i)
                if ent:
                    out.append(ent)
                    i += ent["_span"]
                    continue
            i += 32
        return out

    def _parse_file_set(self, buf: bytes, i: int) -> dict[str, Any] | None:
        """解析 File + Stream + FileName×N 这一组条目。"""
        f = buf[i:i + 32]
        if f[0] != ENTRY_FILE:
            return None
        attr = u16(f, 4)
        # 紧随其后应当是 Stream Extension
        if i + 64 > len(buf) or buf[i + 32] != ENTRY_STREAM:
            return None
        s = buf[i + 32:i + 64]
        name_len = s[3]
        name_hash = u16(s, 4)
        valid_size = u64(s, 8)
        first_cluster = u32(s, 20)
        data_len = u64(s, 24)
        flags = s[1]
        no_fat_chain = bool(flags & 0x02)

        # 文件名条目数量 = ceil(name_len / 15)
        n_name = (name_len + 14) // 15
        chars = bytearray()
        ok = True
        for k in range(n_name):
            o = i + 64 + k * 32
            if o + 32 > len(buf) or buf[o] != ENTRY_NAME:
                ok = False
                break
            chars += buf[o + 2:o + 32]
        if not ok:
            return None
        name = bytes(chars[:name_len * 2]).decode("utf-16-le", "replace")
        span = 64 + n_name * 32

        return {
            "name": name,
            "attr": attr,
            "is_dir": bool(attr & ATTR_DIRECTORY),
            "hidden": bool(attr & ATTR_HIDDEN),
            "system": bool(attr & ATTR_SYSTEM),
            "size": valid_size,
            "data_len": data_len,
            "first_cluster": first_cluster,
            "no_fat_chain": no_fat_chain,
            "ctime": self._ts(f, 8),
            "mtime": self._ts(f, 12),
            "atime": self._ts(f, 16),
            "_span": span,
        }

    @staticmethod
    def _ts(entry: bytes, off: int) -> str:
        """exFAT 时间戳（DOS 风格 32 位）。"""
        try:
            v = u32(entry, off)
            if not v:
                return ""
            sec = (v & 0x1F) * 2
            minute = (v >> 5) & 0x3F
            hour = (v >> 11) & 0x1F
            day = (v >> 16) & 0x1F
            month = (v >> 21) & 0x0F
            year = ((v >> 25) & 0x7F) + 1980
            return "%04d-%02d-%02d %02d:%02d:%02d" % (year, month, day, hour, minute, sec)
        except Exception:
            return ""

    # ------------------------------------------------------------ 文件读取
    def read_file(self, ent: dict[str, Any], *, limit: int | None = None) -> bytes:
        """读文件内容。NoFatChain 时走连续读取。"""
        need = ent["data_len"] if limit is None else min(limit, ent["data_len"])
        if need <= 0:
            return b""
        fc = ent["first_cluster"]
        if ent["no_fat_chain"] or ent["is_dir"]:
            return self.read_contiguous(fc, need)
        return self.read_chain(fc, need)

    # ------------------------------------------------------------ 遍历
    def walk(self, cluster: int | None = None, prefix: str = "",
             depth: int = 0, max_depth: int = 6) -> Iterator[dict[str, Any]]:
        c = self.root_cluster if cluster is None else cluster
        try:
            entries = self.list_dir(c)
        except Exception as exc:
            yield {"path": prefix or "/", "error": f"{type(exc).__name__}: {exc}",
                   "is_dir": True}
            return
        for e in entries:
            path = f"{prefix}/{e['name']}"
            yield {"path": path, **{k: v for k, v in e.items() if not k.startswith("_")}}
            if e["is_dir"] and depth < max_depth and e["first_cluster"] >= 2:
                yield from self.walk(e["first_cluster"], path, depth + 1, max_depth)

    # ------------------------------------------------------------ 摘要
    def summary(self) -> dict[str, Any]:
        return {
            "fs": "exFAT",
            "revision": self.revision,
            "bytes_per_sector": self.bps,
            "sectors_per_cluster": self.spc,
            "cluster_size": self.cluster_size,
            "cluster_count": self.cluster_count,
            "heap_offset": self.heap_offset,
            "fat_offset": self.fat_offset,
            "root_cluster": self.root_cluster,
            "volume_label": self.volume_label,
            "total_bytes": self.cluster_count * self.cluster_size,
            "percent_in_use": self.percent_in_use,
        }
