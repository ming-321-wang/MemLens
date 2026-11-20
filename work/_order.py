# -*- coding: utf-8 -*-
# 收集 tp_order / tp_users SQL 数据，解 题9（订单数 2016-04-01~2025-04-01）与 题14
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

order_data = bytearray()
user_data = bytearray()
admin_data = bytearray()
t0 = time.time()
for ino in sorted(x._ino_loc.keys()):
    if not (60000 <= ino <= 72000):
        continue
    try:
        info = x.inode(ino)
    except Exception:
        continue
    if (info["mode"] & 0xF000) != 0x8000:
        continue
    if info["size"] == 0 or info["size"] > 1<<20:
        continue
    d = read_data(info)
    if b"tp_order`" in d or b"tp_order " in d:
        order_data += d
    if b"tp_users`" in d:
        user_data += d
    if b"tp_admin`" in d:
        admin_data += d

print(f"order bytes={len(order_data)} users bytes={len(user_data)} admin bytes={len(admin_data)} in {time.time()-t0:.0f}s", flush=True)

# 解 tp_order
import datetime
start_ts = int(datetime.datetime(2016,4,1,0,0,0).timestamp())
end_ts = int(datetime.datetime(2025,4,1,0,0,0).timestamp())
def split_tuples(txt):
    # 顶层括号分割
    tuples=[]; buf=[]; depth=0; instr=False; esc=False
    for ch in txt:
        if instr:
            buf.append(ch)
            if esc: esc=False
            elif ch=="\\": esc=True
            elif ch=="'": instr=False
            continue
        if ch=="'": instr=True; buf.append(ch)
        elif ch=="(":
            if depth>0: buf.append(ch)
            depth+=1
        elif ch==")":
            depth-=1
            if depth==0: tuples.append("".join(buf)); buf=[]
            else: buf.append(ch)
        elif depth>0: buf.append(ch)
    if buf: tuples.append("".join(buf))
    return tuples

def vals_of(t):
    m=re.findall(r"'((?:\\'|[^'])*)'", t)
    return m

start_ts=int(datetime.datetime(2016,4,1,0,0,0).timestamp())
end_ts=int(datetime.datetime(2025,4,1,0,0,0).timestamp())
cnt=0; earliest=[]; latest=[]
text=order_data.decode("utf-8","ignore")
for line in text.splitlines():
    if not line.startswith("INSERT INTO `tp_order` VALUES"):
        continue
    for t in split_tuples(line):
        v=vals_of(t)
        if len(v)>=30:
            try: at=int(v[29])
            except: continue
            if start_ts<=at<end_ts:
                cnt+=1
                earliest.append(at); latest.append(at)
print("题9 订单数:", cnt, flush=True)
if earliest:
    print("  最早 add_time:", datetime.datetime.fromtimestamp(min(earliest)), flush=True)
    print("  最晚 add_time:", datetime.datetime.fromtimestamp(max(latest)), flush=True)
