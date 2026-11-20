# -*- coding: utf-8 -*-
"""对比三种口径统计 tp_order 订单数（2016-04-01 ~ 2025-04-01）。"""
import re, datetime, collections
T = open(r'D:\MemLens\work\extracted\dump.sql', 'rb').read().decode('utf-8', 'replace')
s = int(datetime.datetime(2016, 4, 1).timestamp())
e = int(datetime.datetime(2025, 4, 1).timestamp())
print("区间秒:", s, e, "->", datetime.datetime.fromtimestamp(s), "~",
      datetime.datetime.fromtimestamp(e))

# 口径 A：WP 原文（逐行 INSERT 语句 + 只取带引号字符串 + 第 30 个）
cntA = 0; nA = 0
for line in T.split("\n"):
    if line.startswith("INSERT INTO `tp_order` VALUES"):
        nA += 1
        vals = re.findall(r"'((?:\\'|[^'])*)'", line)
        try:
            at = int(vals[29])
        except Exception:
            continue
        if s <= at < e:
            cntA += 1
print(f"A WP口径   : INSERT 语句 {nA} 条, 命中 {cntA}")

# 口径 B：按顶层括号拆元组，add_time=索引29
def tuples(body):
    out=[]; d=0; cur=[]; q=False
    for c in body:
        if q:
            cur.append(c)
            if c=="'": q=False
            continue
        if c=="'": q=True; cur.append(c)
        elif c=="(":
            d+=1
            if d>1: cur.append(c)
        elif c==")":
            d-=1
            if d==0: out.append("".join(cur)); cur=[]
        else: cur.append(c)
    return out
rows=[]; nB=0
for m in re.finditer(r"INSERT INTO `tp_order` VALUES (.*?);", T, re.S):
    for tp in tuples(m.group(1)):
        v = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", tp)
        v=[x[1:-1] if x.startswith("'") else x for x in v]
        if v: rows.append(v)
for r in rows:
    try: at=int(r[29])
    except Exception: continue
    if s<=at<e: nB+=1
print(f"B 元组口径 : 元组 {len(rows)} 个, 命中 {nB}")

# 边界探测
cnt=collections.Counter()
for r in rows:
    try: at=int(r[29])
    except Exception: continue
    if at in (s, e, s-1, s+1, e-1, e+1): cnt[at]+=1
print("边界值分布:", dict(cnt))
