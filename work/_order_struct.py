# -*- coding: utf-8 -*-
# 检查 tp_order INSERT 结构，确定 add_time 字段位置
import sys, struct, math, re, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)

def read_data(info, maxlen=1<<20):
    if info["fmt"] == 1:
        return info["raw"][0xB0:0xB0+min(maxlen, info["size"])]
    if info["size"] > maxlen: return b""
    exts = x.extents(info["ino"])
    if not exts: return b""
    nb = max(1, math.ceil(info["size"] / x.bs))
    return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:info["size"]]

# 收集 tp_order 所有行
rows = []
for ino in sorted(x._ino_loc.keys()):
    if not (60000 <= ino <= 100000): continue
    try:
        info = x.inode(ino)
    except Exception: continue
    if (info["mode"] & 0xF000) != 0x8000: continue
    if info["size"] == 0 or info["size"] > 1<<20: continue
    d = read_data(info)
    if b"tp_order`" in d:
        for line in d.decode("utf-8","ignore").splitlines():
            if line.startswith("INSERT INTO `tp_order` VALUES"):
                rows.append(line)
print("tp_order INSERT 行数:", len(rows))
# 打印第一个 INSERT 的前 500 字节
if rows:
    line = rows[0]
    print("首行长度:", len(line))
    print("首行前 600 字节:")
    print(line[:600])
    # 统计所有 ( 元组 数
    allvals = re.findall(r"\('[^']*'", line)
    print("元组近似数:", len(allvals))
