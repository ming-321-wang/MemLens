# -*- coding: utf-8 -*-
"""打包版端到端复核：JSON 端点（UTF-8 正确解码）+ CSV 端点。"""
import json
import urllib.request

BASE = "http://127.0.0.1:8810"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=300) as r:
        return r.read()


print("=== GET /api/browser-history（关键词 ctf）===")
d = json.loads(get("/api/browser-history?browser=edge&keyword=ctf&show=3").decode("utf-8"))
print("total =", d["total"], " 来源库 =", len(d["sources"]), " all_drives =", d["all_drives"])
s = d["summary"]
print("时间范围:", s["first"], "~", s["last"])
print("按浏览器:", s["by_browser"])
print("Top 域名:")
for x in s["top_domains"][:8]:
    print("   %-42s %d" % (x["域名"], x["次数"]))
print("明细样例:")
for v in d["visits"][:3]:
    print("   %s | %s | %s" % (v["visited_at"], v["browser"], v["url"][:70]))

print("\n=== GET /api/browser-history.csv（前 3 行）===")
raw = get("/api/browser-history.csv?browser=edge&keyword=ctf&limit=5")
print("字节数:", len(raw), " BOM:", raw[:3] == b"\xef\xbb\xbf")
for line in raw.decode("utf-8-sig").splitlines()[:3]:
    print("   ", line[:110])

print("\n=== 全盘扫描模式（all_drives=true，只探测不采集）===")
d2 = json.loads(get("/api/browser-history?sources_only=true&all_drives=true").decode("utf-8"))
print("全盘来源库数:", len(d2["sources"]), " all_drives =", d2["all_drives"])
for x in d2["sources"][:8]:
    print("   %-8s %-20s %7.2f MB  [%s]" % (x["browser"], x["profile"], x["size_mb"], x.get("drive", "")))
