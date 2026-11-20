# -*- coding: utf-8 -*-
# 复查题9：dump 中所有 tp_order INSERT 位置分布
import sys, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(934836886, 64 << 20)
text = d.decode("utf-8", "replace")

offs = [m.start() for m in re.finditer(r"INSERT INTO\s+`tp_order`", text)]
print(f"tp_order INSERT 数: {len(offs)}", flush=True)
print(f"  首 {offs[0]}  末 {offs[-1]}  跨度 {offs[-1]-offs[0]}", flush=True)
# 检查连续性（相邻差）
gaps = [(offs[i+1]-offs[i]) for i in range(len(offs)-1)]
print(f"  最大间隙: {max(gaps)}  平均: {sum(gaps)//len(gaps)}", flush=True)

# 统计所有订单行（不含区间过滤）
start_ts = int(datetime.datetime(2016,4,1).timestamp())
end_ts = int(datetime.datetime(2025,4,1).timestamp())
cnt=0; cnt_all=0; boundary=[]
for m in re.finditer(r"INSERT INTO\s+`tp_order` VALUES\s*(.*?);", text, re.S):
    for t in re.finditer(r"\('(\d+)',\s*'[^']*',\s*'([^']*)',[^)]*?',\s*'(\d+)'", m.group(1)):
        pass
# 用更直接的：统计每个元组的第30个值
vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", text)
print("总 token 数（近似）:", len(vals), flush=True)
