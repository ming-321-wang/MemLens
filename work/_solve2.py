# -*- coding: utf-8 -*-
# 完整 dump.sql（更大范围）+ tp_config + 题14
import sys, struct, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

print("读 dump.sql 更大范围...", flush=True)
d = x.read(934836886, 24 << 20)
text = d.decode("utf-8", "replace")

def extract_inserts(txt, table):
    rows = []
    for m in re.finditer(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);", txt, re.S):
        body = m.group(1)
        vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", body)
        vals = [v[1:-1] if v.startswith("'") else v for v in vals]
        rows.append(vals)
    return rows

# 题9
start_ts = int(datetime.datetime(2016,4,1).timestamp())
end_ts = int(datetime.datetime(2025,4,1).timestamp())
rows = extract_inserts(text, "tp_order")
cnt = 0; times=[]
for r in rows:
    if len(r) > 29:
        try: at = int(r[29])
        except: continue
        if start_ts <= at < end_ts:
            cnt += 1; times.append(at)
print(f"题9: tp_order 总行={len(rows)} 区间内={cnt} 最早={datetime.datetime.fromtimestamp(min(times)) if times else '-'} 最晚={datetime.datetime.fromtimestamp(max(times)) if times else '-'}", flush=True)

# 题10 tp_config
cfg = extract_inserts(text, "tp_config")
print(f"题10: tp_config 行={len(cfg)}", flush=True)
for r in cfg:
    joined = "|".join(r)
    if "freight_free" in joined or "shopping" in joined.lower():
        print("  ", r[:8], flush=True)

# 题14 tp_users + tp_order
users = extract_inserts(text, "tp_users")
print(f"题14: tp_users 行={len(users)}", flush=True)
# tp_users 结构：先看前2行
for r in users[:2]:
    print("  users 样例:", r[:8], flush=True)
for r in rows[:2]:
    print("  order 样例:", r[:3], flush=True)
