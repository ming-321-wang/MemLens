# -*- coding: utf-8 -*-
# 用提取出的实体文件跑 MemLens 的各解析函数，确认逐题可用
import sys, os
sys.path.insert(0, r"D:\MemLens")
from memlens.core import server_forensics as sf

OUT = r"D:\MemLens\work\extracted"

def rd(n):
    with open(os.path.join(OUT, n), "rb") as f:
        return f.read().decode("utf-8", "replace")

# 题3 passwd
t = rd("passwd")
r = sf.parse_passwd(t)
print("题3 passwd count:", r["count"], [u["name"] for u in r["users"]][:8], flush=True)

# 题4/5/6 trojan
t = rd("config.json")
r = sf.parse_trojan_config(t)
print("题4/5/6 trojan:", {k: r.get(k) for k in ("run_type", "local_addr", "local_port", "remote_addr", "remote_port")}, flush=True)

# 题7 config（论坛 HTML 形态）
d = None
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs
x, meta = open_server_fs(r"E:\2025平航杯\平航杯题目", "早起王的爱恋日记\u2764")
t = x.read(228004 * 4096, 16384).decode("utf-8", "replace")
r = sf.parse_php_encrypt(t, "sbwyz1")
print("题7 config:", r, flush=True)

# 题9 SQL 订单数
t = rd("dump.sql")
import datetime
s = int(datetime.datetime(2016, 4, 1).timestamp())
e = int(datetime.datetime(2025, 4, 1).timestamp())
r = sf.parse_sql_orders(t, s, e)
print("题9 sql:", r.get("orders"), "rows", r.get("total_insert_rows"), flush=True)

# 题1 wtmp
r = sf.parse_wtmp(os.path.join(OUT, "wtmp"))
print("题1 wtmp:", r.get("boot_count"), "boots; earliest:", r.get("earliest"), "latest:", r.get("latest"), flush=True)
