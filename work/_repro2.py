# -*- coding: utf-8 -*-
# 复现 solve_server_fs（受限扫描 200MB）
import sys, traceback
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs
from memlens.core import server_forensics as sf

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
# 直接调用 find_contents 受限 + 解析（模拟 solve_server_fs 逻辑）
targets = [
    ("passwd",   b"root:x:0:0",      "text"),
    ("trojan",   b"run_type",        "json"),
    ("config",   b"AUTH_CODE",       "text"),
    ("database", b"DB_PWD",          "text"),
    ("access",   b"invokefunction",  "line"),
    ("result",   b"[RDP]",           "line"),
    ("sql",      b"INSERT INTO `tp_order`", "sql"),
    ("wtmp",     b"reboot\x00",      "wtmp"),
]
pats = [t[1] for t in targets]
hits = x.find_contents(pats, max_bytes=400 << 20)
for (name, _pat, kind), hitlist in zip(targets, hits):
    print(f"[{name}] {len(hitlist)} 命中", flush=True)
    for h in hitlist[:3]:
        try:
            if kind == "sql":
                r = sf.parse_sql_orders(h["ctx"].decode("utf-8","replace"), 1459440000, 1743436800)
                g = sf.parse_sql_first_order_gap(h["ctx"].decode("utf-8","replace"))
                print(f"   sql: orders={r['orders']} gap={g.get('best')}", flush=True)
            elif kind == "json":
                print(f"   json: {h['ctx'][:60]!r}", flush=True)
            elif kind == "wtmp":
                rec = x.read(max(0,h["off"]-44), 384)
                import struct
                ut = struct.unpack_from("<h", rec, 0)[0] if len(rec)>=384 else -1
                print(f"   wtmp: ut_type={ut}", flush=True)
            else:
                print(f"   {name}: {h['ctx'][:40]!r}", flush=True)
        except Exception as e:
            traceback.print_exc()
            print(f"   ERROR {name}: {e}", flush=True)
