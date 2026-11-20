# -*- coding: utf-8 -*-
# 用挑战 dump.sql 计算题14（最短注册→首单间隔）
import sys, re, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(934836886, 64 << 20)
text = d.decode("utf-8", "replace")

def extract(table):
    rows = []
    pat = re.compile(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);", re.I | re.S)
    for m in pat.finditer(text):
        body = m.group(1)
        vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", body)
        vals = [v[1:-1] if v.startswith("'") else v for v in vals]
        if vals: rows.append(vals)
    return rows

users = extract("tp_user") + extract("tp_users")
orders = extract("tp_order")
print(f"tp_users 行={len(users)} tp_order 行={len(orders)}", flush=True)
if users:
    print("  user 样例:", users[0][:6], flush=True)
if orders:
    print("  order 样例:", orders[0][:5], flush=True)
