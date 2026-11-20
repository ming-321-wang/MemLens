# -*- coding: utf-8 -*-
# 提取挑战文件（按全扫描找到的 raw offset）并验证
import sys, struct, json, re, hashlib
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

def dump(off, n):
    return x.read(off, n)

# 1) trojan config.json (题4/5/6)
print("="*70)
print("[题4/5/6] trojan config.json @ blk 3000143")
for probe in (12288585835,):
    start = probe - 600
    d = dump(start, 4096)
    # 找 { 起始
    i = d.find(b"{")
    j = d.rfind(b"}")
    if i >= 0 and j > i:
        txt = d[i:j+1].decode("utf-8", "replace")
        print(txt)
        try:
            cfg = json.loads(txt)
            print("  run_type:", cfg.get("run_type"), "| local_addr:", cfg.get("local_addr"),
                  "| local_port:", cfg.get("local_port"), "| remote_addr:", cfg.get("remote_addr"),
                  "| remote_port:", cfg.get("remote_port"))
        except Exception as e:
            print("  json err:", e)

# 2) result.txt (题13)
print("="*70)
print("[题13] result.txt @ blk 6129187")
d = dump(25105150186 - 200, 4096)
txt = d.decode("utf-8", "replace")
rdp = re.findall(r"\[RDP\][^\n]*", txt)
for r in rdp: print("  ", r.strip())
icmp = re.findall(r"\[icmp\][^\n]*", txt)
for r in icmp[:8]: print("  ", r.strip())
title = re.findall(r"\[title\][^\n]*", txt)
for r in title[:6]: print("  ", r.strip())

# 3) access.log (题11/12)
print("="*70)
print("[题11/12] access.log @ blk 3256475")
d = dump(13338522614 - 4096, 65536)
txt = d.decode("utf-8", "replace")
lines = [l for l in txt.splitlines() if "invokefunction" in l or "peiqi.php" in l or "222.2.2.2" in l]
for l in lines[:25]:
    print("  ", l[:220])
# 找攻击者 IP：POST /peiqi.php 或 invokefunction 请求的源 IP
ips = re.findall(r'"([\d.]+)"[^\n]*?invokefunction[^\n]*?HTTP', txt)
print("  invokefunction 源IP 候选:", set(ips))
ips2 = re.findall(r'"([\d.]+)"[^\n]*?POST /peiqi\.php[^\n]*?HTTP', txt)
print("  POST /peiqi.php 源IP:", set(ips2))

# 4) database.php (题9 密码)
print("="*70)
print("[题9] database.php DB_PWD @ blk 3210550")
d = dump(13150413001 - 200, 1024)
i = d.find(b"DB_PWD")
print(d[max(0,i-40):i+80].decode("utf-8","replace"))
