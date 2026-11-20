# -*- coding: utf-8 -*-
# 列出边界附近订单（题9 差1）
import sys, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(934836886, 1 << 20)
text = d.decode("utf-8", "replace")

start_ts = int(datetime.datetime(2016,4,1).timestamp())
end_ts = int(datetime.datetime(2025,4,1).timestamp())
print(f"start_ts={start_ts} ({datetime.datetime.fromtimestamp(start_ts)})  end_ts={end_ts} ({datetime.datetime.fromtimestamp(end_ts)})", flush=True)

rows = []
for m in re.finditer(r"INSERT INTO\s+`tp_order` VALUES\s*(.*?);", text, re.S):
    body = m.group(1)
    vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", body)
    vals = [v[1:-1] if v.startswith("'") else v for v in vals]
    if len(vals) > 29:
        try: rows.append((int(vals[0]), int(vals[29])))
        except: rows.append((vals[0], "ERR"))
print("总行:", len(rows), flush=True)

# 边界附近
for oid, at in rows:
    if isinstance(at, int) and (abs(at - start_ts) < 86400 or abs(at - end_ts) < 86400):
        print(f"  order_id={oid} add_time={at} ({datetime.datetime.fromtimestamp(at)})", flush=True)
# 检查是否有 add_time == end_ts 或 == start_ts
print("add_time==end_ts:", [o for o,a in rows if isinstance(a,int) and a==end_ts], flush=True)
print("add_time==start_ts:", [o for o,a in rows if isinstance(a,int) and a==start_ts], flush=True)
# 区间计数
c = sum(1 for o,a in rows if isinstance(a,int) and start_ts<=a<end_ts)
print("区间内:", c, flush=True)
