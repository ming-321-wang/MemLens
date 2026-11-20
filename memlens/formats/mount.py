# -*- coding: utf-8 -*-
"""MemLens · 镜像挂载子系统（新增 · CarveScope 同类能力）

把"打开一个镜像 → 看到分区/文件系统 → 浏览文件树 → 读/提取文件"统一成
一个入口，复用 MemLens 已有的解析器：

    容器层  VeraCrypt（core.veracrypt_volume）/ EWF（formats.ewf）
            / VMDK（formats.vmdk）/ 裸镜像
    分区表  MBR / GPT（formats.partitions）
    文件系统 XFS（formats.xfs）/ ext4（formats.ext4）/ FAT12/16/32（formats.fat）
            / exFAT（core.exfat）

对外：
    ImageMount.open(path, password=...) → .volumes（list[FsVolume]）
    FsVolume.tree()/.listdir(path)/.read(path)/.extract(path,dst)/.summary()

不依赖第三方解析引擎（dissect/pytsk3），与 MemLens 零外网定位一致；
NTFS 若未内置解析器则标注 unsupported，仍可对该分区做雕刻/哈希。
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from memlens.formats.partitions import parse_partitions, Partition

_FS_SIGS = (
    # (名称, 偏移, 魔数)
    ("ntfs", 3, b"NTFS    "),
    ("exfat", 3, b"EXFAT   "),
    ("fat", 54, b"FAT12   "), ("fat", 54, b"FAT16   "), ("fat", 82, b"FAT32   "),
    ("xfs", 0, b"XFSB"),
)


def _detect_fs(read: Callable[[int, int], bytes], offset: int) -> str:
    """在 offset 处探测文件系统签名。"""
    boot = read(offset, 512)
    if len(boot) >= 90:
        for name, o, magic in _FS_SIGS:
            if boot[o:o + len(magic)] == magic:
                return name
    # ext 超级块魔数 0xEF53 @ superblock+0x38（offset=1024*1）
    ext = read(offset + 1024 + 0x38, 2)
    if ext == b"\x53\xef":
        return "ext"
    return ""


@dataclass
class FsVolume:
    """一个可浏览的文件系统卷。"""
    index: int
    fs_type: str
    offset: int
    size: int
    label: str = ""
    engine: Any = None
    kind: str = ""                 # xfs/ext/fat/exfat/raw/unsupported
    note: str = ""

    # ── 统一接口 ──────────────────────────────────────────
    def summary(self) -> dict[str, Any]:
        s = {"index": self.index, "fs": self.fs_type, "kind": self.kind,
             "offset": self.offset, "size": self.size, "label": self.label}
        try:
            if self.engine is not None and hasattr(self.engine, "summary"):
                s.update(self.engine.summary() or {})
        except Exception:
            pass
        return s

    def tree(self, max_entries: int = 5000) -> list[dict[str, Any]]:
        """目录树（含已删除标记，尽力而为）。"""
        if self.engine is None:
            return []
        e = self.engine
        out: list[dict[str, Any]] = []
        try:
            if hasattr(e, "walk") and not hasattr(e, "list_dir"):     # XFS：yield (path, ino, ftype)
                for p, ino, t in e.walk():
                    out.append({"name": p.split("/")[-1], "path": p,
                                "dir": t == "dir", "size": 0,
                                "deleted": False, "ino": ino})
            elif hasattr(e, "walk"):                                  # exFAT：yield dict
                for item in e.walk():
                    out.append(self._norm(item, max_entries))
            elif hasattr(e, "tree"):                                  # FAT
                for item in e.tree():
                    out.append({"name": item.name, "path": item.path,
                                "dir": item.is_dir, "size": item.size,
                                "deleted": item.is_deleted,
                                "cluster": getattr(item, "start_cluster", None)})
            elif hasattr(e, "records"):                               # ext4
                for item in e.records():
                    out.append(self._norm(item, max_entries))
        except Exception:
            pass
        return out[:max_entries]

    def _norm(self, item: dict[str, Any], cap: int) -> dict[str, Any]:
        if isinstance(item, tuple):            # XFS (path, ino, ftype) —— 防御
            p = item[0]
            return {"name": p.split("/")[-1], "path": p,
                    "dir": item[2] == "dir", "size": 0, "deleted": False, "ino": item[1]}
        name = item.get("name") or item.get("path") or ""
        return {"name": name, "path": item.get("path") or name,
                "dir": bool(item.get("dir") or item.get("is_dir")),
                "size": int(item.get("size") or 0),
                "deleted": bool(item.get("deleted") or item.get("is_deleted"))}

    def listdir(self, path: str = "/") -> list[dict[str, Any]]:
        e = self.engine
        if e is None:
            return []
        try:
            if hasattr(e, "list_dir"):                   # exFAT
                cluster = self._resolve_cluster(path)
                return list(e.list_dir(cluster))
            if hasattr(e, "listdir"):                    # ext4
                ino = self._resolve_ino(path)
                return list(e.listdir(ino))
            if hasattr(e, "dir_entries"):                # xfs
                ino = self._resolve_ino(path)
                return list(e.dir_entries(ino))
        except Exception:
            pass
        return [i for i in self.tree() if self._parent(i["path"]) == path.strip("/")]

    def _parent(self, path: str) -> str:
        parts = path.strip("/").split("/")
        return "/".join(parts[:-1])

    def _resolve_cluster(self, path: str):
        parts = [p for p in path.strip("/").split("/") if p]
        node = self.engine.root_cluster
        for p in parts:
            nxt = next((x for x in self.engine.list_dir(node)
                        if (x.get("name") or "").lower() == p.lower()), None)
            if nxt is None:
                return node
            node = nxt.get("cluster") or node
        return node

    def _resolve_ino(self, path: str):
        parts = [p for p in path.strip("/").split("/") if p]
        node = 2  # root inode (ext/xfs)
        cur = ""
        for p in parts:
            cur = (cur + "/" + p).strip("/")
            if hasattr(self.engine, "lookup"):
                ent = self.engine.lookup(cur)
                if ent is not None:
                    node = ent.get("ino") if isinstance(ent, dict) else getattr(ent, "ino", node)
                    continue
            try:
                de = next((d for d in self.engine.dir_entries(node)
                           if (d.get("name") or "").lower() == p.lower()), None)
                if de is not None:
                    node = de.get("ino", node)
            except Exception:
                break
        return node

    def read(self, path: str) -> bytes:
        e = self.engine
        if e is None:
            raise RuntimeError(f"卷 {self.fs_type} 无解析引擎，不能读文件")
        if hasattr(e, "read_path"):
            return e.read_path(path)
        if hasattr(e, "read_file"):
            ent = self._find_entry(path)
            return e.read_file(ent) if ent else b""
        raise RuntimeError("该引擎不支持按路径读文件")

    def _find_entry(self, path: str):
        if hasattr(self.engine, "walk"):
            for item in self.engine.walk():
                if (item.get("path") or "").strip("/") == path.strip("/"):
                    return item
        return None

    def extract(self, path: str, dst: str | Path) -> Path:
        data = self.read(path)
        p = Path(dst)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def carve(self, names: list[str] | None = None,
              offset: int | None = None, length: int | None = None) -> list[dict[str, Any]]:
        """对卷（或其子区间）做文件雕刻，返回命中列表。"""
        from memlens.core.carver import carve_region, CARVE_RULES
        off = self.offset + (offset or 0)
        ln = length or self.size
        read = self._abs_read
        hits = list(carve_region(read, off, ln, names))
        return [{"rule": h.rule, "start": h.start, "end": h.end,
                 "size": h.size, "note": h.note, "header": h.header.hex()} for h in hits]

    def _abs_read(self, off: int, n: int) -> bytes:
        if self._raw_read is None:
            return b""
        return self._raw_read(off, n)

    _raw_read: Callable[[int, int], bytes] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self._raw_read is None:
            self._raw_read = lambda off, n: b""


class ImageMount:
    """一个已打开的镜像。"""

    def __init__(self, path: str | Path, kind: str, size: int,
                 password: str = "") -> None:
        self.path = str(path)
        self.kind = kind
        self.size = size
        self.password = password
        self.volumes: list[FsVolume] = []
        self.notes: list[str] = []

    def summary(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "size": self.size,
                "volumes": [v.summary() for v in self.volumes],
                "notes": self.notes}

    @classmethod
    def open(cls, path: str | Path, password: str = "",
             vmdk_name: str = "export-disk0-000002.vmdk") -> "ImageMount":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(p)
        size = p.stat().st_size
        head = p.open("rb").read(512)

        # 容器层识别
        if head[:8] == b"EVF\x09\x0d\x0a\xff\x00":
            return cls._open_ewf(p, size)
        if head[:4] == b"KDMV" or head.startswith(b"# Disk DescriptorFile"):
            return cls._open_vmdk(p, size)
        # VeraCrypt：头是加密的，无口令无法判断 → 给了口令就试解一次。
        if password:
            from memlens.core.veracrypt_volume import VeraCryptVolume
            try:
                VeraCryptVolume(p, password)   # 认证失败会抛；成功即确认是 VeraCrypt
            except Exception:
                pass                           # 口令不对则按裸镜像处理
            else:
                return cls._open_veracrypt(p, password, size, vmdk_name)
        return cls._open_raw(p, size)

    # ── 容器打开 ──────────────────────────────────────────
    @staticmethod
    def _looks_veracrypt(p: Path) -> bool:
        # VeraCrypt 头：0..64 盐（随机），64..72 加密头（含 magic），无法简单判；
        # 回退：若口令解密成功即认定。
        return False

    @classmethod
    def _open_veracrypt(cls, p: Path, password: str, size: int,
                        vmdk_name: str) -> "ImageMount":
        from memlens.core.veracrypt_volume import VeraCryptVolume
        vol = VeraCryptVolume(p, password)
        m = cls(p, "veracrypt", size, password)
        fs_info = vol.identify_fs() or {}
        fst = str(fs_info.get("fs", ""))
        if fst and "exfat" in fst.lower():
            from memlens.core.exfat import ExFat
            ex = ExFat(vol)
            v = FsVolume(1, "exfat", vol.data_start, size, "exFAT",
                         engine=ex, kind="exfat")
            v._raw_read = vol.read
            m.volumes.append(v)
            m.notes.append("VeraCrypt 卷内文件系统：exFAT")
            # 若能开服务器链路（VMDK→LVM→XFS），追加为第二个卷
            try:
                from memlens.formats.xfs import open_server_fs
                x, meta = open_server_fs(str(p), password, vmdk_name=vmdk_name)
                xv = FsVolume(2, "xfs", meta.get("lvm_offset", 0),
                              x.summary().get("total_bytes", 0),
                              f"XFS lv={meta.get('lvm_lv')}",
                              engine=x, kind="xfs",
                              note=f"LVM lv={meta.get('lvm_lv')}")
                xv._raw_read = x.read
                m.volumes.append(xv)
                m.notes.append("已解开服务器链路：VMDK→LVM→XFS")
            except Exception as exc:
                m.notes.append(f"服务器链路未解开：{exc}")
        else:
            m.volumes.append(FsVolume(1, str(fst or "unknown"), vol.data_start,
                                      size, "", engine=vol, kind="raw"))
            m.notes.append(f"VeraCrypt 卷内文件系统未识别：{fst}")
        return m

    @classmethod
    def _open_ewf(cls, p: Path, size: int) -> "ImageMount":
        from memlens.formats.ewf import EwfReader
        r = EwfReader(p)
        m = cls(p, "ewf", r.logical_size())
        m._add_disk(r, m.size)
        return m

    @classmethod
    def _open_vmdk(cls, p: Path, size: int) -> "ImageMount":
        from memlens.formats.vmdk import VmdkDisk
        d = VmdkDisk(p)
        m = cls(p, "vmdk", d.logical_size() if hasattr(d, "logical_size") else size)
        m._add_disk(d, m.size)
        return m

    @classmethod
    def _open_raw(cls, p: Path, size: int) -> "ImageMount":
        m = cls(p, "raw", size)
        fh = p.open("rb")

        def _read(off: int, n: int) -> bytes:
            fh.seek(off)
            return fh.read(n)

        m._add_disk(_read, size)
        return m

    def _add_disk(self, reader: Any, size: int) -> None:
        """对裸盘/容器盘：分区表 → 各分区文件系统；无分区表则整盘单卷。"""
        read = reader.read if hasattr(reader, "read") else reader
        parts = parse_partitions(read, size)
        if not parts:
            self._add_whole(read, size)
            return
        for i, pt in enumerate(parts):
            if pt.fs_type == "extended" or (pt.fs_type == "GPT" and i == 0):
                continue
            fst = _detect_fs(read, pt.offset)
            eng = self._open_fs(fst, read, pt.offset)
            v = FsVolume(i + 1, fst or pt.fs_type or "unknown", pt.offset,
                         pt.size, pt.label, engine=eng, kind=fst or "raw",
                         note=f"分区类型 {pt.fs_type}")
            v._raw_read = read
            self.volumes.append(v)
        self.notes.append(f"分区表：{len(parts)} 个分区")

    def _add_whole(self, read: Callable[[int, int], bytes], size: int) -> None:
        fst = _detect_fs(read, 0)
        eng = self._open_fs(fst, read, 0)
        v = FsVolume(1, fst or "raw", 0, size, "", engine=eng, kind=fst or "raw",
                     note="整盘单卷（无分区表）")
        v._raw_read = read
        self.volumes.append(v)

    @staticmethod
    def _open_fs(fst: str, read: Callable[[int, int], bytes], offset: int):
        try:
            if fst == "xfs":
                from memlens.formats.xfs import Xfs
                return Xfs(_ReadAdapter(read), offset)
            if fst == "ext":
                from memlens.formats.ext4 import Ext4
                return Ext4(_ReadAdapter(read), offset)
            if fst == "fat":
                from memlens.formats.fat import FAT
                return FAT(_ReadAdapter(read), offset)
        except Exception:
            return None
        return None


class _ReadAdapter:
    """把 read(off,n) 函数包成带 .read 的对象（Xfs/Ext4/FAT 期望）。"""

    def __init__(self, read: Callable[[int, int], bytes]) -> None:
        self._fn = read

    def read(self, off: int, n: int) -> bytes:
        return self._fn(off, n)


def _looks_veracrypt(p: Path) -> bool:
    return False


__all__ = ["ImageMount", "FsVolume", "Partition"]
