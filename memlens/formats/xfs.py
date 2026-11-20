# -*- coding: utf-8 -*-
r"""
MemLens · XFS 只读解析器（服务器镜像取证专用）

## 背景与定位（重要，先读）

本解析器针对 **2025 平航杯** 这类检材：客户机磁盘是 VMware VMDK，根文件系统在 LVM 逻辑卷里（XFS），
且该 XFS 是出题方用脚本 **合成** 的 —— 部分元数据（inobt 指针、bmbt blockcount、dir3 的 inumber）
是 **假的**，不能盲信。本模块因此采用 **"内容优先 + 魔数锚定 + 逐层校验"** 的策略，
只在字段自洽时才采信，避免被假元数据带偏。

## 已实测确认的布局（CentOS7 / XFS v3 / 4KiB 块）

    超级块（块 0，前 512B）：
      +0x00 magic "XFSB"
      +0x04 blocksize = 4096
      +0x08 dblocks
      +0x38 rootino = 64
      +0x54 agblocks   +0x58 agcount
    AG0 头（块 1 内）：
      +0x200 AGF (magic XAGF)   +0x400 AGI (magic XAGI, +0x14 = inobt 根)
    inode 块（chunk）：小 inode（≥64）落在块 8 起，每块 8 个 512B 槽；
      大 inode 靠 **全卷扫 "IN"(0x494E) @512B 边界** 定位（inobt 指针不可信）。
    dinode（v3，176B + 数据 fork @0xB0）：
      +0x00 magic 0x494E   +0x02 mode   +0x04 ver=3   +0x05 fmt
      +0x38 size（可信）   +0x4C nextents   +0x98 ino（可信）
      数据 fork @0xB0：
        · fmt=1 (LOCAL)：数据内嵌
        · fmt=2 (EXTENTS)：bmbt 记录，标准 128-bit 解法
          startoff=a>>2；startblock=((a&3)<<48)|(b>>16)（可信）；
          blockcount（不可信，用 di_size 定长）
    目录数据块（XDB3/XDD3）：
      +0x28 owner（可信）  数据区 ~0x44 起，条目 [ino:4][nl:1][name][ft:1]
      （条目里的 ino 字段不可信；名字可信）

## LVM 感知

`open_server_fs()` 解析 PV 里 LVM2 文本元数据，按 `pe_start + 起始extent × pe_size`
把逻辑卷映射回虚拟盘字节偏移，从而直接读出卷内的 XFS。
"""

from __future__ import annotations

import re
import struct
from typing import Any, Iterator, Optional

SB_MAGIC = b"XFSB"
AGF_MAGIC = b"XAGF"
AGI_MAGIC = b"XAGI"
INODE_MAGIC = 0x494E       # 'IN'
DIR_MAGICS = (b"XDB3", b"XDD3")

FMT_LOCAL = 1
FMT_EXTENTS = 2
FMT_BMAP = 3
FMT_BNODES = 4

FT = {1: "reg", 2: "dir", 3: "lnk", 4: "chr", 5: "blk", 6: "fif", 7: "sock"}


class XfsError(RuntimeError):
    """XFS 解析失败。"""


def bmbt_unpack(rec16: bytes) -> dict[str, int]:
    """XFS bmbt 128-bit extent 记录解包（标准公式，startblock 可信）。"""
    a = int.from_bytes(rec16[0:8], "big")
    b = int.from_bytes(rec16[8:16], "big")
    return {
        "startoff": (a >> 2) & 0x3FFFFFFFFFF,
        "startblock": ((a & 3) << 48) | (b >> 16),
        "blockcount": (b >> 15) & 0x1FFFFF,   # 合成 FS 里常为假值
        "state": (b >> 31) & 1,
    }


class Xfs:
    """
    只读 XFS。`reader` 需实现 `read(off, n)->bytes`（off 为文件系统内偏移）。
    `offset` 指定该 XFS 在 reader 里的起点字节偏移。
    """

    def __init__(self, reader: Any, offset: int = 0) -> None:
        self.r = reader
        self.base = offset
        self.bs = 0
        self.dblocks = 0
        self.rootino = 0
        self.agblocks = 0
        self.agcount = 0
        self.uuid = b""
        self._ino_loc: dict[int, tuple[int, int]] = {}
        self._dir_cache: dict[int, list[dict]] = {}
        self._parse_super()

    # ------------------------------------------------------------ 底层
    def read(self, off: int, n: int) -> bytes:
        return self.r.read(self.base + off, n)

    def block(self, blk: int, count: int = 1) -> bytes:
        return self.read(blk * self.bs, count * self.bs)

    # ------------------------------------------------------------ 超级块
    def _parse_super(self) -> None:
        sb = self.read(0, 512)
        if len(sb) < 512 or sb[:4] != SB_MAGIC:
            raise XfsError("不是 XFS 超级块（magic != XFSB）")
        self.bs = struct.unpack_from(">I", sb, 0x04)[0] or 4096
        self.dblocks = struct.unpack_from(">Q", sb, 0x08)[0]
        self.uuid = sb[0x20:0x30]
        self.rootino = struct.unpack_from(">Q", sb, 0x38)[0]
        self.agblocks = struct.unpack_from(">I", sb, 0x54)[0]
        self.agcount = struct.unpack_from(">I", sb, 0x58)[0]

    def summary(self) -> dict[str, Any]:
        return {
            "magic": "XFSB", "blocksize": self.bs, "dblocks": self.dblocks,
            "total_gb": round(self.dblocks * self.bs / 1024 ** 3, 2),
            "agblocks": self.agblocks, "agcount": self.agcount,
            "rootino": self.rootino, "uuid": self.uuid.hex(),
        }

    # ------------------------------------------------------------ inode 定位
    def find_inodes_range(self, base: int, length: int,
                          progress_cb=None) -> int:
        """扫 [base, base+length) 建 ino→(块,槽偏移)，返回新增 inode 数。"""
        step = 128 * 4096
        pos = base
        end = base + length
        while pos < end:
            n = min(step, end - pos)
            buf = self.read(pos, n)
            for blk in range(pos // self.bs, (pos + n) // self.bs + 1):
                off = blk * self.bs - pos
                if off < 0 or off + self.bs > len(buf):
                    continue
                d = buf[off:off + self.bs]
                if d[:2] != b"\x49\x4e" or d[4] not in (2, 3):
                    continue
                for s in range(0, self.bs, 512):
                    if d[s:s + 2] != b"\x49\x4e":
                        continue
                    ino = struct.unpack_from(">Q", d, s + 0x98)[0]
                    if ino and ino not in self._ino_loc:
                        self._ino_loc[ino] = (blk, s)
            pos += n
            if progress_cb:
                progress_cb(pos - base, length, len(self._ino_loc))
        return len(self._ino_loc)

    def find_content(self, pattern: bytes, max_bytes: int | None = None,
                     chunk: int = 32 << 20, progress_cb=None,
                     ctx_before: int = 96, ctx_after: int = 160) -> list[dict]:
        """
        扫描 XFS 数据区找 pattern，返回 [{off, blk, ctx}]。
        ★ 合成 FS 常把文件数据放在 extent 指向之外的原始块（extent 被伪造），
          因此**内容搜索**是定位这类文件的可靠手段（inode 路径不可信）。
        max_bytes：只扫前 N 字节（默认全盘 dblocks*bs）。
        """
        end = max_bytes if max_bytes is not None else self.dblocks * self.bs
        out: list[dict] = []
        pos = 0
        while pos < end:
            n = min(chunk, end - pos)
            d = self.read(pos, n)
            idx = d.find(pattern)
            while idx >= 0:
                abs_off = pos + idx
                out.append({
                    "off": abs_off, "blk": abs_off // self.bs,
                    "ctx": d[max(0, idx - ctx_before):idx + len(pattern) + ctx_after],
                })
                idx = d.find(pattern, idx + 1)
            pos += n
            if progress_cb:
                progress_cb(pos, end, len(out))
        return out

    def find_contents(self, patterns: list[bytes], max_bytes: int | None = None,
                      chunk: int = 32 << 20, progress_cb=None,
                      ctx_before: int = 96, ctx_after: int = 160) -> dict:
        """
        一次扫描 XFS 数据区，同时搜多个 pattern → {pat_index: [{off, blk, ctx}]}。
        ★ 用一次全盘扫描替代多次 find_content（合成 FS 里定位文件内容的主力手段）。
        """
        end = max_bytes if max_bytes is not None else self.dblocks * self.bs
        out: dict = {i: [] for i in range(len(patterns))}
        pos = 0
        while pos < end:
            n = min(chunk, end - pos)
            d = self.read(pos, n)
            for i, pat in enumerate(patterns):
                idx = d.find(pat)
                while idx >= 0:
                    abs_off = pos + idx
                    out[i].append({
                        "off": abs_off, "blk": abs_off // self.bs,
                        "ctx": d[max(0, idx - ctx_before):idx + len(pat) + ctx_after],
                    })
                    idx = d.find(pat, idx + 1)
            pos += n
            if progress_cb:
                progress_cb(pos, end, sum(len(v) for v in out.values()))
        return out

    def find_inodes(self, scan_bytes: int, progress_cb=None) -> int:
        """
        在 [0, scan_bytes) 内找 inode 块（"IN"@512B 边界）建 ino→(块,槽偏移)。        返回找到的 inode 数。大卷可分段调用（结果累加）。
        """
        return self.find_inodes_range(0, scan_bytes, progress_cb)

    def inode_loc(self, ino: int) -> tuple[int, int]:
        """ino → (块, 512B 槽)。小 inode 可直接算；否则用 find_inodes 结果。"""
        if ino in self._ino_loc:
            return self._ino_loc[ino]
        if 64 <= ino < 64 + 64:      # 实测：块8 起 8 个/块
            blk = 8 + (ino - 64) // 8
            return blk, ((ino - 64) % 8) * 512
        raise XfsError(f"定位不到 inode {ino}（请先 find_inodes）")

    # ------------------------------------------------------------ dinode
    def inode(self, ino: int) -> dict[str, Any]:
        blk, slot = self.inode_loc(ino)
        raw = self.read(blk * self.bs + slot, 512)
        if raw[:2] != b"\x49\x4e":
            raise XfsError(f"inode {ino} 位置无 IN 魔数")
        mode = struct.unpack_from(">H", raw, 2)[0]
        ver = raw[4]
        fmt = raw[5]
        size = struct.unpack_from(">Q", raw, 0x38)[0]
        nxt = struct.unpack_from(">I", raw, 0x4C)[0]
        real_ino = struct.unpack_from(">Q", raw, 0x98)[0]
        return {
            "ino": ino, "mode": mode, "ver": ver, "fmt": fmt,
            "size": size, "nextents": nxt, "real_ino": real_ino,
            "is_dir": (mode & 0xF000) == 0x4000,
            "is_reg": (mode & 0xF000) == 0x8000,
            "is_link": (mode & 0xF000) == 0xA000,
            "raw": raw, "blk": blk, "slot": slot,
        }

    def extents(self, ino: int) -> list[dict[str, int]]:
        """EXTENTS 格式 → bmbt 记录列表（startblock 可信，blockcount 存疑）。"""
        info = self.inode(ino)
        out: list[dict[str, int]] = []
        if info["fmt"] == FMT_EXTENTS:
            for k in range(max(1, info["nextents"])):
                rec = info["raw"][0xB0 + k * 16: 0xB0 + k * 16 + 16]
                if len(rec) < 16:
                    break
                out.append(bmbt_unpack(rec))
        return out

    # ------------------------------------------------------------ 数据读取
    def read_inode_data(self, ino: int) -> bytes:
        """读文件的完整内容（LOCAL 内嵌 / EXTENTS 跟随）。"""
        info = self.inode(ino)
        size = info["size"]
        if size == 0:
            return b""
        raw = info["raw"]
        if info["fmt"] == FMT_LOCAL:
            # 本地数据 fork：紧贴 dinode 头（0xB0 附近），只取 size 字节
            off = 0xB0
            chunk = raw[off:off + size]
            if len(chunk) < size:
                chunk += self.read(info["blk"] * self.bs + off, size - len(chunk))
            return chunk[:size]
        exts = self.extents(ino)
        out = bytearray()
        for e in exts:
            nblocks = max(1, (size + self.bs - 1) // self.bs)
            data = self.read(e["startblock"] * self.bs, nblocks * self.bs)
            out += data
        return bytes(out[:size])

    # ------------------------------------------------------------ 目录
    def dir_entries(self, ino: int) -> list[dict[str, Any]]:
        """
        解析目录数据（LOCAL 内嵌 / 合成 FS 内嵌 shortform / dir3 数据块）
        → [(name, ino, ftype)]。
        ★ 合成 FS 里 inumber 字段常为 0/假值 —— 名字可信，ino 尽力而为。
        """
        if ino in self._dir_cache:
            return self._dir_cache[ino]
        info = self.inode(ino)
        data = self._dir_data(info)
        if not data:
            out: list[dict[str, Any]] = []
        elif data[:4] in DIR_MAGICS:
            out = self._parse_dir3(data, info)
        else:
            out = self._parse_shortform(data)
        self._dir_cache[ino] = out
        return out

    def _dir_data(self, info: dict[str, Any]) -> bytes:
        if info["fmt"] == FMT_LOCAL:
            off = 0xB0
            return info["raw"][off:off + max(info["size"], 1)]
        # fmt=2(EXTENTS)：合成 FS 常在 inode 内嵌区仍放着 shortform 目录数据，
        # 而 extent 指向被伪造的位置（读到 ELF/垃圾）。先探测内嵌区。
        emb = info["raw"][0xB0:0xB0 + 112]
        if self._looks_shortform(emb):
            return emb
        exts = self.extents(info["ino"])
        if not exts:
            return b""
        nblocks = max(1, (info["size"] + self.bs - 1) // self.bs)
        return self.read(exts[0]["startblock"] * self.bs, nblocks * self.bs)

    # ------------------------------------------------------------ shortform
    @staticmethod
    def _name_chars(c: int) -> bool:
        return (0x30 <= c <= 0x39 or 0x61 <= c <= 0x7a or 0x41 <= c <= 0x5a
                or c in (0x2e, 0x2d, 0x5f, 0x2f))

    def _shortform_runs(self, data: bytes) -> list[tuple[str, int]]:
        """扫描 shortform 数据，返回 [(name, ftype)]。名字可信；ftype 取名字后一字节。"""
        out: list[tuple[str, int]] = []
        i = 0
        n = len(data)
        while i < n:
            if self._name_chars(data[i]):
                j = i
                while j < n and self._name_chars(data[j]):
                    j += 1
                name = data[i:j].decode("ascii", "replace")
                ftype = data[j] if j < n else 0
                if 1 <= len(name) <= 255 and 1 <= ftype <= 7:
                    out.append((name, ftype))
                i = j
            else:
                i += 1
        return out

    def _looks_shortform(self, data: bytes) -> bool:
        """内嵌区是否像 shortform 目录数据（有 ≥2 个可解析名+ftype）。"""
        return len(self._shortform_runs(data)) >= 2

    def _parse_shortform(self, data: bytes) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name, ftype in self._shortform_runs(data):
            if name in (".", ".."):
                continue
            out.append({"name": name, "ino": 0, "ftype": ftype,
                        "ftype_s": FT.get(ftype, "?")})
        return out

    def _parse_dir3(self, data: bytes, info: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not data:
            return out
        # dir3 数据区：找第一个可打印名字，倒推条目起点；再顺序扫
        p = self._dir3_data_start(data)
        while p + 8 <= len(data):
            inum = struct.unpack_from(">I", data, p)[0]
            nl = data[p + 4]
            if nl == 0 or nl > 100:
                break
            name_b = data[p + 5:p + 5 + nl]
            ft = data[p + 5 + nl]
            if not all(32 <= c < 127 for c in name_b):
                break
            name = name_b.decode("ascii", "replace")
            if name not in (".", ".."):
                out.append({"name": name, "ino": inum, "ftype": ft,
                            "ftype_s": FT.get(ft, "?")})
            p += (5 + nl + 1 + 7) & ~7
        return out

    def _dir3_data_start(self, data: bytes) -> int:
        """定位 dir3 数据区起点（0x44~0x50 之间，按首个可解析条目）。"""
        for start in (0x44, 0x48, 0x4C, 0x50):
            nl = data[start + 4] if start + 4 < len(data) else 0
            if 1 <= nl <= 100:
                nb = data[start + 5:start + 5 + nl]
                if all(32 <= c < 127 for c in nb):
                    return start
        return 0x44

    # ------------------------------------------------------------ 树
    def walk(self, ino: int = 0, depth: int = 6,
             parent: str = "") -> Iterator[tuple[str, int, str]]:
        """yield (path, ino, ftype_s)。跳过 proc/sys/dev/run。"""
        cur = ino or self.rootino
        root = parent == ""
        for e in self.dir_entries(cur):
            p = (parent + "/" + e["name"]) if parent else e["name"]
            if not root and e["name"] in ("proc", "sys", "dev", "run"):
                continue
            yield p, e["ino"], e["ftype_s"]
            if e["ftype_s"] == "dir" and depth > 1 and e["ino"]:
                yield from self.walk(e["ino"], depth - 1, p)

    def find(self, name: str, depth: int = 5) -> list[str]:
        found = []
        for p, ino, t in self.walk(depth=depth):
            if p.split("/")[-1] == name or name in p:
                found.append(p)
        return found

    def read_path(self, path: str) -> bytes:
        parts = [x for x in path.replace("\\", "/").split("/") if x and x != "."]
        cur = self.rootino
        for part in parts:
            hit = next((e for e in self.dir_entries(cur) if e["name"] == part), None)
            if hit is None:
                raise XfsError(f"路径不存在：{path}（缺 {part}）")
            cur = hit["ino"] or cur
        return self.read_inode_data(cur)


# ------------------------------------------------------------ LVM 感知
def _lvm_metadata_text(reader: Any, pv_off: int) -> str:
    """
    取 PV 里的 LVM2 文本元数据。

    ★ 元数据会有多份副本（LVM2 在 PV 里写 backup 区），且副本较大。
      窗口开小会截断 logical_volumes 段落 —— 直接读 128 KiB 覆盖所有副本。
    """
    return reader.read(pv_off, 0x20000).decode("latin-1", "replace")


def _iter_brace_regions(txt: str, marker: str):
    """找每处 `marker { ... }` 的内部文本（字符级匹配，支持多次出现）。"""
    i = 0
    while True:
        i = txt.find(marker, i)
        if i < 0:
            return
        j = txt.find("{", i + len(marker))
        if j < 0:
            return
        depth = 0
        k = j
        while k < len(txt):
            c = txt[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        yield txt[j + 1:k]
        i = j + 1


def _split_top_level(region: str) -> dict[str, str]:
    """把 region 内顶层 `name { ... }` 块切出来 → {name: 块文本}。"""
    out: dict[str, str] = {}
    depth = 0
    cur_name = None
    cur_start = None
    for i, c in enumerate(region):
        if c == "{":
            if depth == 0:
                prefix = region[:i].rstrip()
                toks = prefix.split()
                cur_name = toks[-1] if toks else f"lv{len(out)}"
                cur_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and cur_name is not None:
                out[cur_name] = region[cur_start + 1:i]
                cur_name = None
    return out


_LV_STRIPE_RE = re.compile(r'stripes\s*=\s*\[\s*"pv\d+"\s*,\s*(\d+)')
_LV_EXT_COUNT_RE = re.compile(r"extent_count\s*=\s*(\d+)")


def parse_lvm_pv(reader: Any, pv_off: int) -> list[dict[str, Any]]:
    """
    解析 PV 的 LVM2 文本元数据 → 逻辑卷列表（合并所有副本，后者优先）。
    每项：{name, start_pe, extent_count}。

    ★ start_pe 优先取 **stripes 里的真实起点**（`stripes = ["pv0", N]`）。
      合成 FS 里 `start_extent` 字段常被置 0（假值），只有 stripes 可信。
    """
    txt = _lvm_metadata_text(reader, pv_off)
    out: dict[str, dict[str, Any]] = {}
    for region in _iter_brace_regions(txt, "logical_volumes"):
        for name, block in _split_top_level(region).items():
            sm = _LV_STRIPE_RE.search(block)
            em = _LV_EXT_COUNT_RE.search(block)
            if not em:
                continue
            start_pe = int(sm.group(1)) if sm else 0
            out[name] = {"name": name, "start_pe": start_pe,
                         "extent_count": int(em.group(1))}
    return list(out.values())


def lvm_layout(reader: Any, pv_off: int) -> dict[str, Any]:
    """PV 布局：pe_start / extent_size（扇区）/ 各 LV（取当前副本值）。"""
    txt = _lvm_metadata_text(reader, pv_off)
    pes = re.findall(r"pe_start\s*=\s*(\d+)", txt)
    ess = re.findall(r"extent_size\s*=\s*(\d+)", txt)
    if not pes or not ess:
        raise XfsError("LVM 元数据里找不到 pe_start / extent_size")
    return {
        "pe_start": int(pes[-1]),
        "extent_size": int(ess[-1]),     # 扇区
        "lvs": parse_lvm_pv(reader, pv_off),
    }


def lvm_lv_offset(reader: Any, pv_off: int, lv_name: str) -> int:
    """逻辑卷在 reader 里的字节偏移（PV 起点 + PE 换算）。"""
    lay = lvm_layout(reader, pv_off)
    for lv in lay["lvs"]:
        if lv["name"] == lv_name:
            sectors = lay["pe_start"] + lv["start_pe"] * lay["extent_size"]
            return pv_off + sectors * 512
    names = ", ".join(lv["name"] for lv in lay["lvs"]) or "(空)"
    raise XfsError(f"LVM 里找不到逻辑卷 {lv_name}（现有：{names}）")


# ------------------------------------------------------------ 服务器根 FS 打开
class _VmdkView:
    """把 VmdkDisk 的 read_at（虚拟盘偏移）适配成 read（Xfs/LVM 期望的接口）。"""

    def __init__(self, vd: Any) -> None:
        self.vd = vd
        self.size = getattr(vd, "capacity", 0) * 512

    def read(self, off: int, n: int) -> bytes:
        return self.vd.read_at(off, n)


def open_server_fs(image: str, password: str = "",
                   vmdk_name: str = "export-disk0-000002.vmdk",
                   lv_name: str = "root"):
    """
    把检材一路开到服务器根文件系统（XFS），返回 (Xfs, 摘要 dict)。
    链路：VeraCrypt 卷（若有口令）→ exFAT → VMDK 稀疏盘 → MBR 分区
          → LVM PV → 逻辑卷（root）→ XFS。
    这是 2025 平航杯检材容器的实际结构，也适用于一般的
    "加密卷里套虚拟机盘" 取证场景。
    """
    from memlens.core.exfat import ExFat
    from memlens.formats.vmdk import VmdkDisk
    from memlens.core.veracrypt_volume import VeraCryptVolume

    if password:
        vol = VeraCryptVolume(image, password)
        fs = ExFat(vol)
        ent = next((e for e in fs.list_dir(fs.root_cluster)
                    if e["name"].lower() == vmdk_name.lower()), None)
        if ent is None:
            raise XfsError(f"卷内找不到 {vmdk_name}")

        class _R:
            def __init__(s, e, f, v):
                s.e, s.f, s.v = e, f, v
                s.size = e["data_len"]

            def read(s, off, n):
                out = bytearray()
                if s.e.get("no_fat_chain"):
                    b = s.f.cluster_offset(s.e["first_cluster"])
                    while len(out) < n:
                        out += s.v.read(b + off + len(out),
                                        min(8 << 20, n - len(out)))
                    return bytes(out)
                ci, co = divmod(off, s.f.cluster_size)
                need = (s.e["data_len"] + s.f.cluster_size - 1) // s.f.cluster_size
                chain = list(s.f.chain(s.e["first_cluster"]))[:need]
                while len(out) < n and ci < len(chain):
                    blk = s.f.read_cluster(chain[ci])
                    take = min(len(blk) - co, n - len(out))
                    out += blk[co:co + take]
                    ci += 1; co = 0
                return bytes(out)

        rd = _R(ent, fs, vol)
        vd = VmdkDisk(reader=rd)
        closer = lambda: vol.close()
    else:
        vd = VmdkDisk(image)
        closer = vd.close

    # ★ VmdkDisk.read() 是「按容器文件偏移读原始字节」，虚拟盘读取是 read_at()。
    #   Xfs / LVM 解析都按 reader.read(off,n) 调用，所以这里必须做一层视图适配，
    #   否则超级块会读到容器文件头（第一版就栽在这：magic != XFSB）。
    view = _VmdkView(vd)

    # MBR 分区表
    mbr = vd.read_at(0, 512)
    parts = []
    for i in range(4):
        e = mbr[0x1BE + i * 16:0x1BE + (i + 1) * 16]
        if not any(e):
            continue
        parts.append({
            "idx": i + 1,
            "lba": struct.unpack_from("<I", e, 8)[0],
            "ptype": e[4],
            "sectors": struct.unpack_from("<I", e, 12)[0],
        })

    # ★ 先全局找 LVM PV（0x8E）。服务器根文件系统通常在 LVM 里，
    #   而 0x83 的 /boot 分区也是 XFS —— 若按顺序遇到 0x83 就返回，
    #   会错挂成 1 GiB 的 /boot（第一版就栽在这）。
    pv = next((p for p in parts if p["ptype"] == 0x8E), None)
    if pv is not None:
        pv_off = pv["lba"] * 512
    else:
        # 没有 LVM：退化为第一个 XFS 分区
        for p in parts:
            if vd.read_at(p["lba"] * 512, 4) == SB_MAGIC:
                x = Xfs(view, p["lba"] * 512)
                meta = dict(vd.summary())
                meta["xfs_offset"] = p["lba"] * 512
                meta["partitions"] = parts
                return x, meta
        raise XfsError("既没有 LVM PV，也找不到 XFS 分区")

    lv_off = lvm_lv_offset(view, pv_off, lv_name)
    x = Xfs(view, lv_off)
    meta = dict(vd.summary())
    meta["lvm_lv"] = lv_name
    meta["lvm_offset"] = lv_off
    meta["partitions"] = parts
    meta["pv_offset"] = pv_off
    return x, meta
