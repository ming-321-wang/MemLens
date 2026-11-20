# -*- coding: utf-8 -*-
# 复现 solve_server_fs 的 sql 解析错误
import sys, traceback
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs
from memlens.core import server_forensics as sf

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
# 取 dump.sql 上下文（不扫全盘，直接读已知位置）
d = x.read(934836886, 256 << 20)
text = d.decode("utf-8", "replace")
try:
    r = sf.parse_sql_orders(text, 1459440000, 1743436800)
    print("parse_sql_orders OK:", r["orders"], flush=True)
except Exception as e:
    traceback.print_exc()
    print("parse_sql_orders ERROR:", e, flush=True)
try:
    g = sf.parse_sql_first_order_gap(text)
    print("gap OK:", g.get("best"), flush=True)
except Exception as e:
    traceback.print_exc()
    print("gap ERROR:", e, flush=True)
