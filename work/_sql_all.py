# -*- coding: utf-8 -*-
# 全 inode 收集 dump.sql 所有表数据，解 题9/10/14
import sys, struct, math, re, time, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)
print("inodes:", len(x._ino_loc), flush=True)

def read_data(info, maxlen=1<<20):
    if info["fmt"] == 1:
        return info["raw"][0xB0:0xB0+min(maxlen, info["size"])]
    if info["size"] > maxlen: return b""
    exts = x.extents(info["ino"])
    if not exts: return b""
    nb = max(1, math.ceil(info["size"] / x.bs))
    return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:info["size"]]

tables = {k: bytearray() for k in ("order","users","admin","config","region","goods")}
t0 = time.time()
n=0
for ino in sorted(x._ino_loc.keys()):
    try:
        info = x.inode(ino)
    except Exception:
        continue
    if (info["mode"] & 0xF000) != 0x8000:
        continue
    if info["size"] == 0 or info["size"] > 1<<20:
        continue
    n += 1
    d = read_data(info)
    if b"tp_order`" in d or b"tp_order " in d: tables["order"] += d
    if b"tp_users`" in d: tables["users"] += d
    if b"tp_admin`" in d: tables["admin"] += d
    if b"tp_config`" in d: tables["config"] += d
    if b"tp_region`" in d: tables["region"] += d
    if b"tp_order_goods`" in d or b"tp_order_goods " in d: tables["goods"] += d
    if n % 10000 == 0:
        print(f"  ...{n} files {time.time()-t0:.0f}s", flush=True)
print(f"=== {n} files in {time.time()-t0:.0f}s ===", flush=True)
for k, v in tables.items():
    print(f"table {k}: {len(v)} bytes", flush=True)

def split_tuples(txt):
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

# 题9: tp_order add_time（第30个字段）2016-04-01~2025-04-01
start_ts=int(datetime.datetime(2016,4,1).timestamp())
end_ts=int(datetime.datetime(2025,4,1).timestamp())
cnt=0; times=[]
for line in tables["order"].decode("utf-8","ignore").splitlines():
    if not line.startswith("INSERT INTO `tp_order` VALUES"): continue
    for t in split_tuples(line):
        v=re.findall(r"'((?:\\'|[^'])*)'", t)
        if len(v)>=30:
            try: at=int(v[29])
            except: continue
            if start_ts<=at<end_ts:
                cnt+=1; times.append(at)
print("题9 订单数:", cnt, flush=True)
if times:
    print("  最早:", datetime.datetime.fromtimestamp(min(times)), "最晚:", datetime.datetime.fromtimestamp(max(times)), flush=True)

# 题10: tp_config freight_free
for line in tables["config"].decode("utf-8","ignore").splitlines():
    if "freight_free" in line:
        print("题10 freight_free line:", line[:200], flush=True)

# 题14: 用户注册到首次下单间隔最短的用户id
# tp_users 注册时间戳字段、tp_order 用户+时间
# 先看表结构线索
print("users head:", tables["users"][:200], flush=True)
