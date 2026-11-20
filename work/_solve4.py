# -*- coding: utf-8 -*-
# 读更大范围 dump + 修复题14 + 找 tp_config
import sys, struct, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

def extract_inserts(txt, table):
    rows = []
    for m in re.finditer(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);", txt, re.S):
        body = m.group(1)
        vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", body)
        vals = [v[1:-1] if v.startswith("'") else v for v in vals]
        rows.append(vals)
    return rows

# 找 dump.sql 实际范围（从 blk 228231 开始，找 "INSERT INTO `tp_order`" 连续区域）
print("扫描 dump 范围...", flush=True)
base = 934836886
d = x.read(base, 64 << 20)
text = d.decode("utf-8", "replace")

# 找到最后一个 tp_order INSERT 的位置
last = 0
for m in re.finditer(r"INSERT INTO\s+`tp_order`", text):
    last = m.end()
print(f"tp_order INSERT 结束偏移: {last} ({base+last} 绝对)", flush=True)

start_ts = int(datetime.datetime(2016,4,1).timestamp())
end_ts = int(datetime.datetime(2025,4,1).timestamp())
rows = extract_inserts(text, "tp_order")
cnt=0; times=[]
for r in rows:
    if len(r) > 29:
        try: at = int(r[29])
        except: continue
        if start_ts <= at < end_ts: cnt+=1; times.append(at)
print(f"题9: tp_order 总行={len(rows)} 区间内={cnt}", flush=True)

# 题14
users = extract_inserts(text, "tp_users")
print(f"题14: tp_users 行={len(users)}", flush=True)
reg_idx = 5
from collections import defaultdict
first_order = {}
for r in rows:
    if len(r) > 29:
        try:
            uid = r[2]; at = int(r[29])
        except: continue
        if uid not in first_order or at < first_order[uid]:
            first_order[uid] = at
best=None
for u in users:
    if len(u) <= reg_idx: continue
    try:
        uid = u[0]; reg = int(u[reg_idx])
    except: continue
    if reg < 100000000 or reg >= 4000000000: continue
    fo = first_order.get(uid)
    if fo is None: continue
    if reg <= fo:
        gap = fo - reg
        if best is None or gap < best["gap"]:
            best = {"uid":uid,"reg":reg,"fo":fo,"gap":gap}
if best:
    print(f"题14: 最短间隔 用户id={best['uid']} reg={datetime.datetime.fromtimestamp(best['reg'])} 首单={datetime.datetime.fromtimestamp(best['fo'])} gap={best['gap']}s", flush=True)
else:
    print("题14: 无结果", flush=True)

# 题10 tp_config
cfg = extract_inserts(text, "tp_config")
print(f"题10: tp_config 行={len(cfg)}", flush=True)
for r in cfg[:3]:
    print("  ", r[:6], flush=True)
