# -*- coding: utf-8 -*-
# 按 WP 精确方法（CREATE TABLE 列位置）重算 题9/14
import sys, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(934836886, 64 << 20)
text = d.decode("utf-8", "replace")

# 提取 CREATE TABLE
def get_cols(table):
    m = re.search(r"CREATE TABLE\s+`" + re.escape(table) + r"`\s*\((.*?)\)\s*ENGINE", text, re.S)
    if not m: return None
    cols = re.findall(r"^\s*`([^`]+)`", m.group(1), re.M)
    return cols

ucols = get_cols("tp_users")
ocols = get_cols("tp_order")
print("tp_users 列:", ucols, flush=True)
print("tp_order 列:", ocols, flush=True)

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

def split_fields(t):
    fields=[]; buf=[]; instr=False; esc=False
    for ch in t:
        if instr:
            if esc: buf.append(ch); esc=False
            elif ch=="\\": esc=True
            elif ch=="'": instr=False
            else: buf.append(ch)
        else:
            if ch=="'": instr=True
            elif ch==",": fields.append("".join(buf).strip()); buf=[]
            else: buf.append(ch)
    fields.append("".join(buf).strip())
    return [None if v.upper()=="NULL" else v for v in fields]

def parse_inserts(table):
    rows=[]
    for m in re.finditer(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);", text, re.S):
        for t in split_tuples(m.group(1)):
            rows.append(split_fields(t))
    return rows

users = parse_inserts("tp_users")
orders = parse_inserts("tp_order")
print(f"users={len(users)} orders={len(orders)}", flush=True)

# 题9
start_ts = int(datetime.datetime(2016,4,1).timestamp())
end_ts = int(datetime.datetime(2025,4,1).timestamp())
add_idx = ocols.index("add_time") if ocols else 29
uid_idx_o = ocols.index("user_id") if ocols else 2
cnt=0
for o in orders:
    if len(o) <= add_idx: continue
    try: at = int(o[add_idx])
    except: continue
    if start_ts <= at < end_ts: cnt+=1
print(f"题9: {cnt}", flush=True)

# 题14
reg_idx = ucols.index("reg_time") if ucols else 5
uid_idx_u = ucols.index("user_id") if ucols else 0
user_reg = {}
for u in users:
    if len(u) <= max(reg_idx, uid_idx_u): continue
    try:
        uid = int(u[uid_idx_u]); reg = int(u[reg_idx])
    except: continue
    if uid > 0: user_reg[uid] = reg
first_order = {}
for o in orders:
    if len(o) <= max(uid_idx_o, add_idx): continue
    try:
        uid = int(o[uid_idx_o]); at = int(o[add_idx])
    except: continue
    if uid <= 0 or at <= 0: continue
    if uid not in first_order or at < first_order[uid]: first_order[uid] = at
best=None
for uid, reg in user_reg.items():
    if uid not in first_order: continue
    fo = first_order[uid]
    if fo < reg: continue
    gap = fo - reg
    if best is None or gap < best["gap"]:
        best = {"uid":uid,"reg":reg,"fo":fo,"gap":gap}
if best:
    print(f"题14: 最短间隔用户id={best['uid']} reg={datetime.datetime.fromtimestamp(best['reg'])} 首单={datetime.datetime.fromtimestamp(best['fo'])} gap={best['gap']}s", flush=True)
else:
    print("题14: 无结果", flush=True)
