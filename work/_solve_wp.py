# -*- coding: utf-8 -*-
"""解实际 0x05 服务器取证：VeraCrypt→VMDK→XFS 直接按路径读 WP 文件 + MemLens 分析。"""
import sys, io, time
from pathlib import Path
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs
from memlens.core import server_forensics as sf
from memlens.core.web_log_analyze import analyze_access_log
from memlens.core.url_analyze import parse_scanner_output

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记❤"
t0 = time.time()
x, meta = open_server_fs(IMG, PW)
print(f"═══ XFS 打开 {time.time()-t0:.1f}s  rootino={x.rootino} ═══")

def rd(path):
    try:
        return x.read_path(path)
    except Exception as e:
        return None

# ── 题1 开机时间（wtmp）──
wt = rd("/var/log/wtmp")
if wt:
    p = Path(r"D:\MemLens\work\_wtmp_real"); p.write_bytes(wt)
    r = sf.parse_wtmp(p); p.unlink()
    print(f"[题1] 开机次数 {r['boot_count']} 最早 {r['earliest']}")

# ── 题3 用户数（passwd）──
for pp in ["/etc/passwd"]:
    b = rd(pp)
    if b:
        r = sf.parse_passwd(b.decode("utf-8", "replace"))
        print(f"[题3] {pp} 用户数 {r['count']}: {[u['name'] for u in r['users']]}")

# ── 题4/5/6 Trojan 配置 ──
for pp in ["/root/trojan/config.json", "/trojan/config.json", "/etc/trojan/config.json"]:
    b = rd(pp)
    if b:
        r = sf.parse_trojan_config(b.decode("utf-8", "replace"))
        print(f"[题4] {pp} run_type={r.get('run_type')} local={r.get('local_addr')}:{r.get('local_port')} "
              f"remote={r.get('remote_addr')}:{r.get('remote_port')} 域名={r.get('remote_domain')}")
        break

# ── 题7 密码 md5（config.php AUTH_CODE）──
for pp in ["/application/config.php", "/application/function.php", "/application/common.php",
           "/www/wwwroot/*/application/config.php", "/www/wwwroot/config.php"]:
    if "*" in pp:
        hits = x.find(pp.split("/")[-1], depth=6)
        for h in hits[:3]:
            b = rd("/" + h)
            if b:
                r = sf.parse_php_encrypt(b.decode("utf-8", "replace"), "sbwyz1")
                if r["auth_code"]:
                    print(f"[题7] /{h} AUTH_CODE={r['auth_code']} md5={r['hashes'].get('sbwyz1')}")
    else:
        b = rd(pp)
        if b:
            r = sf.parse_php_encrypt(b.decode("utf-8", "replace"), "sbwyz1")
            if r["auth_code"]:
                print(f"[题7] {pp} AUTH_CODE={r['auth_code']} md5={r['hashes'].get('sbwyz1')}")

# ── 题11/12 网站日志 ──
for pp in ["/www/wwwlogs/access.log", "/www/wwwlogs/*.log"]:
    if "*" in pp:
        hits = x.find("access.log", depth=6)
        for h in hits[:2]:
            b = rd("/" + h)
            if b:
                r = analyze_access_log(b.decode("utf-8", "replace"))
                print(f"[题11/12] /{h} 攻击者 {[a['ip'] for a in r['attackers']]} "
                      f"可疑{r['summary']['suspicious_count']} 木马{[w['sha256'][:16] for w in r['webshell']]}")
    else:
        b = rd(pp)
        if b:
            r = analyze_access_log(b.decode("utf-8", "replace"))
            print(f"[题11/12] {pp} 攻击者 {[a['ip'] for a in r['attackers']]} 木马{[w['sha256'][:16] for w in r['webshell']]}")

# ── 题13 扫描器 result.txt ──
for pp in ["/application/result.txt", "/result.txt", "/www/wwwroot/result.txt", "/tmp/result.txt"]:
    b = rd(pp)
    if b:
        r = parse_scanner_output(b.decode("utf-8", "replace"))
        print(f"[题13] {pp} URL {len(r['items'])} icmp {r['icmp_hosts']}")
        for it in r["items"][:8]:
            print(f"    {it.get('risk')} {it.get('country')} {it.get('url')} title={it.get('title','')[:20]}")
        break

# ── 题9/14 SQL 订单 ──
sql_hits = [h for h in x.find(".sql", depth=6) if "dump" in h.lower() or "backup" in h.lower() or "sql" in h.lower()]
for h in sql_hits[:3]:
    b = rd("/" + h)
    if b:
        txt = b.decode("utf-8", "replace")
        import datetime as _dt
        start = int(_dt(2016, 4, 1).timestamp()); end = int(_dt(2025, 4, 1).timestamp())
        o = sf.parse_sql_orders(txt, start, end)
        if o["orders"] or o["total_insert_rows"]:
            print(f"[题9] /{h} 订单数 {o['orders']} 总行 {o['total_insert_rows']}")

print(f"\n═══ 完成 {time.time()-t0:.1f}s ═══")
