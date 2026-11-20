# -*- coding: utf-8 -*-
# 第二个 dump（blk 288229）tp_order 计数
import sys, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(288229*4096, 1 << 20)
text = d.decode("utf-8", "replace")
start_ts = int(datetime.datetime(2016,4,1).timestamp())
end_ts = int(datetime.datetime(2025,4,1).timestamp())
cnt=0; total=0
for m in re.finditer(r"INSERT INTO\s+`tp_order` VALUES\s*(.*?);", text, re.S):
    body = m.group(1)
    vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", body)
    vals = [v[1:-1] if v.startswith("'") else v for v in vals]
    total += 1
    if len(vals) > 29:
        try:
            at = int(vals[29])
            if start_ts <= at < end_ts: cnt += 1
        except: pass
print(f"第二个 dump: tp_order 行={total} 区间内={cnt}", flush=True)
# 也看是否有 CREATE TABLE
print("有 tp_users:", "tp_users" in text, " 有 tp_config:", "tp_config" in text, flush=True)
