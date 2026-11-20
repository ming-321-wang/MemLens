# -*- coding: utf-8 -*-
"""离线验证各解析器（用从真实镜像里提取出的文件，不重扫全盘）。"""
import json, re, sys
sys.path.insert(0, r"D:\MemLens")
from memlens.core import server_forensics as sf

E = r"D:\MemLens\work\extracted"
rd = lambda n: open(E + "\\" + n, "rb").read()

print("=" * 20, "题3 passwd", "=" * 20)
p = sf.parse_passwd(rd("passwd").decode("utf-8", "replace"))
print("count =", p["count"], "| all_count =", p["all_count"],
      "| with_shell =", p["with_shell"], "| loginable =", p["loginable"])
for u in p["users"]:
    print("   ", u)

print("=" * 20, "题4/5/6 trojan config.json", "=" * 20)
t = sf.parse_trojan_config(rd("config.json").decode("utf-8", "replace"))
print(json.dumps(t, ensure_ascii=False)[:1200])

print("=" * 20, "题12 webshell", "=" * 20)
w = sf.parse_webshell(rd("access.log").decode("utf-8", "replace"))
print(json.dumps(w, ensure_ascii=False)[:800])

print("=" * 20, "题13 result.txt 的 [RDP] 行", "=" * 20)
rt = rd("result.txt").decode("utf-8", "replace")
i = rt.find("[RDP]")
cand = [ln for ln in rt.splitlines() if "[RDP]" in ln]
print("含 [RDP] 的行数:", len(cand))
for ln in cand[:3]:
    print("   score=%.3f len=%d | %s" % (sf._line_score(ln), len(ln), ln.strip()[:160]))

print("=" * 20, "题9/14 dump.sql", "=" * 20)
d = rd("dump.sql").decode("utf-8", "replace")
from datetime import datetime as _dt
o = sf.parse_sql_orders(d, int(_dt(2016, 4, 1).timestamp()), int(_dt(2025, 4, 1).timestamp()))
print("orders =", o["orders"], "rows =", o["total_insert_rows"])
g = sf.parse_sql_first_order_gap(d)
print("gap =", json.dumps(g, ensure_ascii=False))
