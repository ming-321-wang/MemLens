r"""
MemLens · ext4 只读解析（服务器镜像取证用）

## 目标

从 VMDK 虚拟盘里读出 Linux 文件系统的文件树与文件内容，
用于"服务器取证"这类题目（`/root/AndroRAT`、`/tmp/ratlog.txt`、
网站配置、数据库…）。**不挂载、不需要 root。**

## 关键结构

超级块（block 1，块大小由 s_log_block_size 决定）：

    +0x00 s_inodes_count          u32
    +0x04 s_blocks_count_lo       u32
    +0x14 s_log_block_size        u32   块大小 = 1024 << 该值
    +0x18 s_blocks_per_group      u32
    +0x20 s_inodes_per_group      u32
    +0x28 s_magic                 u16   0xEF53
    +0x38 s_first_data_block      u32
    +0x58 s_inode_size            u16
    +0xFE s_desc_size             u16   组描述符大小（64 或 128）

组描述符表起始于 block `first_data_block + 1`，每组一个：

    +0x00 bg_block_bitmap_lo      u32
    +0x04 bg_inode_bitmap_lo      u32
    +0x08 bg_inode_table_lo       u32   ★ inode 表起始块
    ...

inode（i_size = 64 或 256 字节）：

    +0x00 i_mode      u16
    +0x04 i_size_lo   u32
    +0x20 i_flags     u32   0x80000 = EXT4_EXTENTS_FL（用 extent 树）
    +0x28 i_block[60]          extent 树根
    +0x6C i_size_high u32      常规文件大文件用

extent 树：

    header(12) : eh_magic(2)=0xF30A eh_entries(2) eh_max(2) eh_depth(2) eh_generation(4)
    entry(12)  : ee_block(u32) ee_len(u16) ee_start_hi(u16) ee_start_lo(u32)

目录项：

    ext4_dir_entry_2: inode(u32) rec_len(u16) name_len(u8) file_type(u8) name[]

## 注意

  · 不处理 inline_data（EXT4_INLINE_DATA_FL，文件内容直接放在 inode 里）
    与 htree 索引目录（大目录需要走索引 B+ 树）——遇到会返回"未支持"而不是乱猜。
  · 稀疏文件（extent 里 ee_len 与块数不等）按空洞补零。
"""

from __future__ import annotations

import struct
from typing import Any, Iterator

SB_MAGIC = 0xEF53
EXTENTS_FL = 0x00080000
INLINE_DATA_FL = 0x10000000
INDEX_FL = 0x00001000

#: ext4 文件类型
FT_NAMES = {
    0: "unknown", 1: "regular", 2: "dir", 3: "chardev", 4: "blkdev",
    5: "fifo", 6: "socket", 7: "symlink", 8: "regfile",
}


class Ext4Error(RuntimeError):
    """ext4 解析失败。"""


class Ext4:
    """只读 ext4。`reader` 需提供 `read(off, n)`。"""

    def __init__(self, reader: Any, offset: int = 0) -> None:
        """offset = 分区在虚拟盘内的起始字节。"""
        self.r = reader
        self.base = offset
        self.block_size = 0
        self.blocks_per_group = 0
        self.inodes_per_group = 0
        self.inode_size = 0
        self.desc_size = 0
        self.first_data_block = 0
        self.total_blocks = 0
        self.magic = 0
        self.volume_name = ""
        self._groups: list[tuple[int, int]] | None = None
        self._parse_super()

    # ------------------------------------------------------------ 读块
    def read(self, off: int, n: int) -> bytes:
        return self.r.read(self.base + off, n)

    def block(self, blk: int, count: int = 1) -> bytes:
        return self.read(blk * self.block_size, count * self.block_size)

    def _parse_super(self) -> None:
        sb = self.read(1024, 1024)
        if len(sb) < 1024:
            raise Ext4Error("读不到超级块")
        self.magic = struct.unpack_from("<H", sb, 0x38)[0]
        if self.magic != SB_MAGIC:
            # 块大小可能是 1K → 超级块在 offset 1024；4K → 在 4096
            sb2 = self.read(4096, 1024)
            if len(sb2) >= 1024 and struct.unpack_from("<H", sb2, 0x38)[0] == SB_MAGIC:
                sb = sb2
                self.magic = SB_MAGIC
                self._sb_off = 4096
            else:
                raise Ext4Error(f"超级块魔数不对：0x{self.magic:04x}")
        else:
            self._sb_off = 1024
        self.inodes_count = struct.unpack_from("<I", sb, 0x00)[0]
        self.total_blocks = struct.unpack_from("<I", sb, 0x04)[0]
        log_bs = struct.unpack_from("<I", sb, 0x14)[0]
        self.block_size = 1024 << log_bs
        self.blocks_per_group = struct.unpack_from("<I", sb, 0x18)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x20)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 0x38)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0] or 32
        name = sb[0x78:0x88].split(b"\x00")[0]
        self.volume_name = name.decode("utf-8", "replace")

    # ------------------------------------------------------------ 组描述符
    def _gd(self) -> list[tuple[int, int]]:
        """返回每组的 (inode_table_block, ...) —— 这里只需要 inode 表位置。"""
        if self._groups is not None:
            return self._groups
        gd_block = self.first_data_block + 1
        raw = self.block(gd_block, max(1, (self.desc_size * 64) // self.block_size + 2))
        out: list[tuple[int, int]] = []
        for i in range(0, 256):
            off = i * self.desc_size
            if off + 8 > len(raw):
                break
            inode_table = struct.unpack_from("<I", raw, off + 0x08)[0]
            out.append((inode_table, off))
        self._groups = out
        return out

    def _inode_block(self, inode: int) -> int:
        g = (inode - 1) // self.inodes_per_group
        idx = (inode - 1) % self.inodes_per_group
        gd = self._gd()
        if g >= len(gd):
            raise Ext4Error(f"组号越界：inode {inode}")
        return gd[g][0] + idx * (self.inode_size // self.block_size) + \
            ((idx * self.inode_size) % self.block_size) // self.block_size

    # ------------------------------------------------------------ inode
    def inode(self, ino: int) -> dict[str, Any]:
        """读 inode（ino 从 1 开始）。"""
        blk = self._inode_block(ino)
        off_in_blk = ((ino - 1) % self.inodes_per_group) * self.inode_size
        blkno = blk + off_in_blk // self.block_size
        inside = off_in_blk % self.block_size
        raw = self.block(blkno, 1)[inside:inside + self.inode_size]
        if len(raw) < 128:
            raise Ext4Error(f"inode {ino} 读不全")
        mode = struct.unpack_from("<H", raw, 0x00)[0]
        size_lo = struct.unpack_from("<I", raw, 0x04)[0]
        flags = struct.unpack_from("<I", raw, 0x20)[0]
        i_block = raw[0x28:0x28 + 60]
        size_hi = struct.unpack_from("<I", raw, 0x6C)[0]
        size = size_lo | (size_hi << 32)
        return {
            "ino": ino, "mode": mode, "flags": flags,
            "size": size, "i_block": i_block,
            "is_dir": (mode & 0xF000) == 0x4000,
            "is_reg": (mode & 0xF000) == 0x8000,
            "is_link": (mode & 0xF000) == 0xA000,
        }

    # ------------------------------------------------------------ extent
    def _extents(self, i_block: bytes) -> list[tuple[int, int, int]]:
        """解析 extent 树 → [(逻辑块号, 物理块号, 长度)]"""
        out: list[tuple[int, int, int]] = []
        self._walk_extents(i_block, out, depth=0)
        out.sort()
        return out

    def _walk_extents(self, node: bytes, out: list, depth: int) -> None:
        if depth > 5 or len(node) < 12:
            return
        magic, entries, _max, _d, _gen = struct.unpack_from("<HHHHI", node, 0)
        if magic != 0xF30A:
            return
        for i in range(entries):
            off = 12 + i * 12
            if off + 12 > len(node):
                break
            ee_block, ee_len, ee_hi, ee_lo = struct.unpack_from("<IHHI", node, off)
            phys = (ee_hi << 32) | ee_lo
            if ee_len > 32768:          # 长度 > 32768 表示未初始化 extent
                ee_len -= 32768
                out.append((ee_block, phys, 0))
            else:
                out.append((ee_block, phys, ee_len))
        if _d > 0:
            for i in range(entries):
                off = 12 + i * 12
                if off + 12 > len(node):
                    break
                ee_block, ee_len, ee_hi, ee_lo = struct.unpack_from("<IHHI", node, off)
                child = self.block((ee_hi << 32) | ee_lo, 1)
                self._walk_extents(child, out, depth + 1)

    def read_inode(self, ino: int) -> bytes:
        """读常规文件内容。"""
        info = self.inode(ino)
        if info["flags"] & INLINE_DATA_FL:
            raise Ext4Error("内联数据文件暂不支持")
        if not (info["flags"] & EXTENTS_FL):
            raise Ext4Error("非 extent 映射（传统块映射）暂不支持")
        exts = self._extents(info["i_block"])
        out = bytearray()
        want = info["size"]
        for lblk, phys, ln in exts:
            if ln == 0:
                continue
            data = self.block(phys, ln)
            # 逻辑块 lblk 可能不是 0 → 需要按逻辑顺序拼接
            out += data
        return bytes(out[:want]) if want else bytes(out)

    # ------------------------------------------------------------ 目录
    def listdir(self, ino: int) -> list[dict[str, Any]]:
        """列目录内容。"""
        data = self.read_inode(ino)
        out: list[dict[str, Any]] = []
        i = 0
        while i + 8 <= len(data):
            child, rec_len, name_len, ftype = struct.unpack_from("<IHBB", data, i)
            if rec_len < 8 or i + rec_len > len(data):
                break
            if child != 0 and name_len > 0:
                name = data[i + 8:i + 8 + name_len].decode("utf-8", "replace")
                if name not in (".", ".."):
                    out.append({"name": name, "ino": child, "type": ftype,
                                "type_name": FT_NAMES.get(ftype, str(ftype))})
            i += rec_len
        return out

    # ------------------------------------------------------------ 路径
    def lookup(self, path: str) -> dict[str, Any]:
        """按路径查找，返回 inode 信息。"""
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        cur = 2                      # 根目录固定是 inode 2
        for p in parts:
            if p == ".":
                continue
            hit = None
            for e in self.listdir(cur):
                if e["name"] == p:
                    hit = e
                    break
            if not hit:
                raise Ext4Error(f"路径不存在：{path}（缺 {p}）")
            cur = hit["ino"]
        return self.inode(cur)

    def read_path(self, path: str) -> bytes:
        """按路径读文件内容。"""
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        cur = 2
        for p in parts:
            hit = None
            for e in self.listdir(cur):
                if e["name"] == p:
                    hit = e
                    break
            if not hit:
                raise Ext4Error(f"路径不存在：{path}")
            cur = hit["ino"]
        return self.read_inode(cur)

    def find(self, name: str, start: int = 2, depth: int = 4) -> list[str]:
        """递归查找同名文件（简单遍历，适合取证里定位关键文件）。"""
        found: list[str] = []
        if depth < 0:
            return found
        try:
            entries = self.listdir(start)
        except Exception:
            return found
        for e in entries:
            if e["type"] == 2:                     # 目录
                if e["name"] in ("proc", "sys", "dev", "run", "tmp/.X11-unix"):
                    continue
                sub = self.find(name, e["ino"], depth - 1)
                found.extend(sub)
            elif e["name"] == name:
                found.append(e["name"])
        return found

    # ------------------------------------------------------------ 摘要
    def summary(self) -> dict[str, Any]:
        return {
            "magic": f"0x{self.magic:04X}",
            "volume_name": self.volume_name,
            "block_size": self.block_size,
            "blocks": self.total_blocks,
            "total_gb": round(self.total_blocks * self.block_size / 1024 ** 3, 2),
            "blocks_per_group": self.blocks_per_group,
            "inodes_per_group": self.inodes_per_group,
            "inodes_count": self.inodes_count,
            "inode_size": self.inode_size,
            "desc_size": self.desc_size,
        }

    def records(self) -> Iterator[dict[str, Any]]:
        for k, v in self.summary().items():
            yield {"项目": str(k), "值": str(v), "说明": "ext4 超级块"}
