# -*- coding: utf-8 -*-
# 检查 vmdk grain 表连续性（XFS 数据区虚拟扇区→物理扇区映射）
import sys
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
vd = None
# 从 open_server_fs 内部拿 vd 不可行，直接重开链路
from memlens.core.veracrypt_volume import VeraCryptVolume
from memlens.core.exfat import ExFat
from memlens.formats.vmdk import VmdkDisk
vol = VeraCryptVolume(IMG, PW)
fs = ExFat(vol)
ent = next(e for e in fs.list_dir(fs.root_cluster) if e["name"].lower() == "export-disk0-000002.vmdk")
class _R:
    def __init__(s, e, f, v): s.e, s.f, s.v = e, f, v; s.size = e["data_len"]
    def read(s, off, n):
        out = bytearray()
        if s.e.get("no_fat_chain"):
            b = s.f.cluster_offset(s.e["first_cluster"])
            while len(out) < n:
                out += s.v.read(b + off + len(out), min(8 << 20, n - len(out)))
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
print("capacity GB:", vd.capacity*512/2**30, "grain_size:", vd.grain_size, "num_gtes_per_gt:", vd.num_gtes_per_gt, "gd_offset:", vd.gd_offset, flush=True)
# 采样 grain 0-10, 1000-1010, 200000-200010
prev = None
contig = 0; total = 0
for g in range(0, 400000, 7):
    p = vd._gt_entry(g)
    total += 1
    if prev is not None and p == prev + 7*1:
        contig += 1
    prev = p
print(f"grain contiguity: {contig}/{total}", flush=True)
# 具体看几个 grain
for g in (0, 1, 100, 1000, 288000, 288001, 288002):
    print(f"grain {g}: phys_sector={vd._gt_entry(g)}", flush=True)
