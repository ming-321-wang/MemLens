# -*- coding: utf-8 -*-
# 更大范围 recount 题9 + 搜 tp_config + 题14
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

# 更大范围 dump
print("读 48MB dump...", flush=True)
d = x.read(934836886, 48 << 20)
text = d.decode("utf-8", "replace")

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
# 用户结构：id, email, pwd, ?, is_lock?, reg_time(field5), ...
def reg_of(u):
    for i,v in enumerate(u):
        if v.isdigit() and int(v) > 100000000 and int(v) < 4000000000 and v != "0":
            return int(v)
    return None
# 找 reg_time 字段：user2 有 19490101（无效），user1 有 1472486400（有效）
# 先确定字段位置
reg_idx = None
for u in users[:5]:
    for i,v in enumerate(u):
        if v.isdigit() and int(v) > 100000000:
            if reg_idx is None: reg_idx = i
            print(f"  用户{u[0]} reg 字段{i}={v} ({datetime.datetime.fromtimestamp(int(v)) if int(v)>100000000 else v})", flush=True)
            break
    if reg_idx is not None: break
print("  reg_idx 候选:", reg_idx, flush=True)

# 订单结构：找 user_id 字段（第0是order_id，找第2或第3）
print("  order 字段样例:", rows[0][:6], flush=True)

# 计算 gap：用户 reg_time → 该用户最早订单 add_time
from collections import defaultdict
first_order = defaultdict(lambda: None)
for r in rows:
    if len(r) > 29:
        try:
            uid = r[2]  # user_id 字段（待验证）
            at = int(r[29])
        except: continue
        if first_order[uid] is None or at < first_order[uid]:
            first_order[uid] = at
best = None
for u in users:
    try:
        uid = u[0]
        reg = int(u[reg_idx]) if reg_idx is not None else None
    except: continue
    if reg is None or reg < 100000000 or reg >= 4000000000: continue
    fo = first_order.get(uid)
    if fo is None: continue
    if reg <= fo:
        gap = fo - reg
        if best is None or gap < best["gap"]:
            best = {"uid": uid, "reg": reg, "fo": fo, "gap": gap}
if best:
    print(f"题14: 最短间隔用户 id={best['uid']} reg={datetime.datetime.fromtimestamp(best['reg'])} 首单={datetime.datetime.fromtimestamp(best['fo'])} gap={best['gap']}s", flush=True)
