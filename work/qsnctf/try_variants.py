# -*- coding: utf-8 -*-
"""对指定 codeId 批量尝试验证码变体（手写体误读 + 大小写）。"""
import sys
import time
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
W = Path(r"D:\MemLens/work/qsnctf")
USER, PASS = "冥", "wzh211955"
CID = (W / "code_now.txt").read_text().strip()

first = sys.argv[1] if len(sys.argv) > 1 else "dVth"
print(f"codeId={CID[:8]}…  用户读作: {first}")

# 候选字符集（按手写体常见误读）
C1 = ["d", "D", "0", "O", "o", "a", "cl", "ci", "Q"]
C3 = ["t", "+", "f", "T", "1", "r"]
C4 = ["h", "b", "k", "li", "ll"]

# 变体清单：先精确，再受限笛卡尔积
variants = [first, first.lower(), first.upper(), first.swapcase()]
seen = set(variants)
for a in C1:
    for c in C3:
        for d in C4:
            v = f"{a}V{c}{d}"
            if v not in seen:
                seen.add(v)
                variants.append(v)
# 兜底：纯小写/纯大写的常见形态
for extra in ("dVth", "duth", "0V+h", "DVth", "dVtH", "dvth", "aV+h"):
    if extra not in seen:
        seen.add(extra)
        variants.append(extra)

print(f"共 {len(variants)} 个变体\n")

found = None
for i, cap in enumerate(variants, 1):
    s = requests.Session()
    s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
    try:
        s.get(BASE + "/", timeout=20)
    except Exception:
        pass
    try:
        r = s.post(BASE + "/api/login",
                   json={"username": USER, "password": PASS, "captcha": cap, "code": CID},
                   timeout=30)
        ok = r.status_code == 200
        tag = "✅" if ok else "  "
        print(f"{tag} [{i:>3}/{len(variants)}] {cap!r:<12} → {r.status_code} {r.text[:80]}")
        if ok:
            try:
                j = r.json()
            except Exception:
                j = {}
            if j.get("access"):
                (W / "token.txt").write_text(j["access"])
                (W / "refresh.txt").write_text(j.get("refresh", ""))
                (W / "used_code.txt").write_text(CID)
                print(f"\n*** 登录成功！验证码实为 {cap!r} ***")
                found = cap
                break
            else:
                print("  (200 但无 access)")
    except Exception as e:
        print(f"    [{i}] {cap!r} 异常 {e}")
    if i % 10 == 0:
        time.sleep(0.5)
    else:
        time.sleep(0.15)

if not found:
    print("\n全部失败 —— 这个 codeId 对应的图我大概率看错了。")
