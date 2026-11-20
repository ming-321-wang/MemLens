# -*- coding: utf-8 -*-
"""造 MemLens 解题演示样本（模拟平航杯检材：浏览器历史 + 服务器文件 + 日志 + 扫描器）。"""
import sqlite3, struct, sys, shutil
from datetime import datetime, timezone
from pathlib import Path

demo = Path(r"D:\MemLens\work\_demo")
shutil.rmtree(demo, ignore_errors=True)

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
def wk(iso):
    return int((datetime.strptime(iso, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                - WEBKIT_EPOCH).total_seconds() * 1_000_000)
def ff(iso):
    return int((datetime.strptime(iso, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000)

def chrome(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER, last_visit_time INTEGER)")
    c.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)")
    for i, (u, t, n, iso) in enumerate(rows, 1):
        c.execute("INSERT INTO urls VALUES (?,?,?,?,?)", (i, u, t, n, wk(iso)))
        c.execute("INSERT INTO visits VALUES (?,?,?,0)", (i, i, wk(iso)))
    c.commit(); c.close()

def firefox(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER, last_visit_date INTEGER)")
    c.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)")
    for i, (u, t, n, iso) in enumerate(rows, 1):
        c.execute("INSERT INTO moz_places VALUES (?,?,?,?,?)", (i, u, t, n, ff(iso)))
        c.execute("INSERT INTO moz_historyvisits VALUES (?,?,?,1)", (i, i, ff(iso)))
    c.commit(); c.close()

# ── 浏览器历史：境外IP + 可疑TLD + 内网 + C2 域名 ──
chrome(demo / "AppData/Local/Google/Chrome/User Data/Default/History",
       [("https://8.8.8.8/admin", "境外IP直连", 3, "2025-04-06 20:00:00"),
        ("http://abc.xyz/pay", "可疑TLD", 2, "2025-04-06 20:05:00"),
        ("https://www.baidu.com/", "百度首页", 5, "2025-04-06 21:00:00")])
chrome(demo / "AppData/Local/Microsoft/Edge/User Data/Default/History",
       [("http://192.168.100.1:8098/", "小米路由器", 4, "2025-04-06 21:10:00")])
firefox(demo / "AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite",
        [("https://evil.c2.com/panel", "C2面板", 2, "2025-04-06 22:00:00")])

# ── 服务器文件 ──
sv = demo / "server"; sv.mkdir(parents=True)
recs = []
for iso in ["2022-02-23 12:23:49"]:
    rec = bytearray(384)
    struct.pack_into("<h", rec, 0, 2)
    struct.pack_into("<i", rec, 338, int(datetime.strptime(iso, "%Y-%m-%d %H:%M:%S").timestamp()))
    recs.append(bytes(rec))
(sv / "wtmp").write_bytes(b"".join(recs))
(sv / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n"
                           "www:x:1000:1000::/var/www:/sbin/nologin\n"
                           "mysql:x:1001:1001::/var/lib/mysql:/sbin/nologin\n"
                           "bin:x:1:1:bin:/bin:/sbin/nologin\n")
(sv / "trojan.json").write_text('{"run_type":"you guess","local_addr":"127.0.0.1","local_port":12345,'
                                '"remote_addr":"wyzshop1.com","remote_port":443}')
(sv / "config.php").write_text("return ['AUTH_CODE' => 'TPSHOP', 'type' => 'mysql'];")
x = ",".join(["'x'"] * 25)
(sv / "dump.sql").write_text(
    "INSERT INTO `tp_order` VALUES (1,'2020-01-01',0,0," + x + ",1577836800);\n"
    "INSERT INTO `tp_order` VALUES (2,'2026-01-01',0,0," + x + ",1767225600);\n")

# ── 网站日志 + 扫描器 ──
web = demo / "web"; web.mkdir(parents=True)
(web / "access.log").write_text(
    '192.168.100.100 - - [10/Apr/2025:09:40:01 +0800] "GET /?s=admin HTTP/1.1" 200 20 "-" "Mozilla/5.0"\n'
    '222.2.2.2 - - [10/Apr/2025:09:41:01 +0800] "POST /index.php?s=/public/upload/peiqi.php HTTP/1.1" 200 120 "-" "curl/7.68"\n'
    '222.2.2.2 - - [10/Apr/2025:09:41:05 +0800] "POST /peiqi.php HTTP/1.1" 200 80 "-" "curl/7.68"\n'
    '1.1.1.1 - - [10/Apr/2025:09:42:00 +0800] "GET /index.php HTTP/1.1" 200 60 "-" "Mozilla/5.0"\n')
(web / "result.txt").write_text(
    "------------------------------------icmp-----------------------\n"
    "[icmp] 192.168.100.100\n[icmp] 192.168.100.1\n"
    "------------------------------------port-----------------------\n"
    "[url] http://192.168.100.1:8098\n[url] http://192.168.100.100:80\n"
    "------------------------------------title----------------------\n"
    "[title] http://192.168.100.1:8098      小米路由器\n"
    "[title] http://192.168.100.100:80      首页 - 开源商城  | B2C 商城\n"
    "------------------------------------finger---------------------\n"
    "[finger] http://192.168.100.100:80      打印机\n")

print("演示样本就绪：", demo)
for p in sorted(demo.rglob("*")):
    if p.is_file():
        print(f"  {p.relative_to(demo)}  ({p.stat().st_size}B)")
