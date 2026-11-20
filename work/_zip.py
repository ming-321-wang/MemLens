# -*- coding: utf-8 -*-
# 列出 exFAT 根目录 + 检查 zip 内容
import sys, struct, io, zipfile
sys.path.insert(0, r"D:\MemLens")
from memlens.core.exfat import ExFat
from memlens.core.veracrypt_volume import VeraCryptVolume

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
vol = VeraCryptVolume(IMG, PW)
fs = ExFat(vol)
print("=== exFAT root ===")
for e in fs.list_dir(fs.root_cluster):
    print(f"  {e['name']}  size={e.get('data_len')}")

# 找 zip
ent = next((e for e in fs.list_dir(fs.root_cluster) if e['name'].lower().endswith('.zip')), None)
if ent:
    print(f"\n=== zip {ent['name']} ===")
    # 读 zip 中央目录
    # 用 _R 视图读
    import io
    class _R:
        def __init__(s, e, f, v):
            s.e, s.f, s.v = e, f, v
            s.size = e["data_len"]
        def read(s, off, n):
            out = bytearray()
            if s.e.get("no_fat_chain"):
                b = s.f.cluster_offset(s.e["first_cluster"])
                while len(out) < n:
                    out += s.v.read(b + off + len(out), min(8<<20, n-len(out)))
                return bytes(out)
            ci, co = divmod(off, s.f.cluster_size)
            need = (s.e["data_len"] + s.f.cluster_size - 1)//s.f.cluster_size
            chain = list(s.f.chain(s.e["first_cluster"]))[:need]
            while len(out) < n and ci < len(chain):
                blk = s.f.read_cluster(chain[ci])
                take = min(len(blk)-co, n-len(out))
                out += blk[co:co+take]
                ci += 1; co = 0
            return bytes(out)
    rd = _R(ent, fs, vol)
    try:
        zf = zipfile.ZipFile(io.BytesIO(rd.read(0, min(rd.size, 8<<20))))
        for info in zf.infolist():
            print(f"  {info.filename}  size={info.file_size}")
    except Exception as e:
        print("  zip read err:", e)
