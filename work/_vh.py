# -*- coding: utf-8 -*-
"""平航杯容器 → VMDK 的公共句柄（带 4 MiB 读缓存）。"""
import sys
sys.path.insert(0, r"D:\MemLens")
from memlens.core.veracrypt_volume import VeraCryptVolume
from memlens.core.exfat import ExFat
from memlens.formats.vmdk import VmdkDisk

VOL = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记❤"
CACHE = 4 << 20


class R:
    """容器内文件的按偏移读取器（4 MiB 对齐缓存）。"""

    def __init__(self, fs, ent):
        self.ent = ent
        self.fs = fs
        self.size = ent["data_len"]
        self._c = None
        self._cache = {}

    def _chain(self):
        if self._c is None:
            need = (self.size + self.fs.cluster_size - 1) // self.fs.cluster_size
            self._c = []
            for c in self.fs.chain(self.ent["first_cluster"]):
                self._c.append(c)
                if len(self._c) >= need:
                    break
        return self._c

    def _raw(self, off, n):
        """不缓存的读取。"""
        out = bytearray()
        if self.ent.get("no_fat_chain"):
            b = self.fs.cluster_offset(self.ent["first_cluster"])
            while len(out) < n:
                out += self.vol.read(b + off + len(out), min(8 << 20, n - len(out)))
            return bytes(out)
        cs = self.fs.cluster_size
        ci, co = divmod(off, cs)
        chain = self._chain()
        while len(out) < n and ci < len(chain):
            blk = self.fs.read_cluster(chain[ci])
            take = min(len(blk) - co, n - len(out))
            out += blk[co:co + take]
            ci += 1
            co = 0
        return bytes(out)

    def read(self, off, n):
        if n <= 0:
            return b""
        out = bytearray()
        pos = off
        while len(out) < n:
            key = pos // CACHE
            base = key * CACHE
            buf = self._cache.get(key)
            if buf is None:
                buf = self._raw(base, CACHE)
                self._cache[key] = buf
                if len(self._cache) > 64:
                    self._cache.pop(next(iter(self._cache)))
            off_in = pos - base
            take = min(len(buf) - off_in, n - len(out))
            if take <= 0:
                break
            out += buf[off_in:off_in + take]
            pos += take
        return bytes(out)


def open_vmdk():
    vol = VeraCryptVolume(VOL, PW)
    fs = ExFat(vol)
    ent = next(e for e in fs.list_dir(fs.root_cluster)
               if e["name"].lower() == "export-disk0-000002.vmdk")
    r = R(fs, ent)
    r.vol = vol
    vd = VmdkDisk(reader=r)
    return vol, fs, ent, r, vd
