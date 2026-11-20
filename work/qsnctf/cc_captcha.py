# -*- coding: utf-8 -*-
"""连通域分析：分离字符块与细长干扰线，再逐个判读。"""
import sys
from collections import deque
from pathlib import Path
from PIL import Image

sys.setrecursionlimit(100000)
SRC = Path(r"D:\MemLens\work\qsnctf\captcha.png")
im = Image.open(SRC).convert("RGB")
W, H = im.size
px = im.load()
TEXT = (179, 74, 159)


def dist(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b))


ink = [[False] * W for _ in range(H)]
for y in range(H):
    for x in range(W):
        p = px[x, y]
        if dist(p, TEXT) < 12000:
            ink[y][x] = True

# 连通域（8 邻接）
comp = [[0] * W for _ in range(H)]
cid = 0
comps = []
for y in range(H):
    for x in range(W):
        if ink[y][x] and comp[y][x] == 0:
            cid += 1
            q = deque([(x, y)])
            comp[y][x] = cid
            cells = []
            while q:
                cx, cy = q.popleft()
                cells.append((cx, cy))
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        nx, ny = cx + dx, cy + dy
                        if 0 <= nx < W and 0 <= ny < H and ink[ny][nx] and comp[ny][nx] == 0:
                            comp[ny][nx] = cid
                            q.append((nx, ny))
            xs = [c[0] for c in cells]
            ys = [c[1] for c in cells]
            comps.append({
                "id": cid, "n": len(cells),
                "x0": min(xs), "x1": max(xs), "y0": min(ys), "y1": max(ys),
                "cells": cells,
            })

print(f"连通域 {len(comps)} 个：")
for c in comps:
    w = c["x1"] - c["x0"] + 1
    h = c["y1"] - c["y0"] + 1
    fill = c["n"] / (w * h)
    print(f"  id={c['id']:3d}  pixels={c['n']:5d}  bbox=({c['x0']},{c['y0']})-({c['x1']},{c['y1']})  w={w:3d} h={h:2d} fill={fill:.2f}")

# 过滤：字符块特征 —— 尺寸足够、填充率适中、不是极细长
kept = []
for c in comps:
    w = c["x1"] - c["x0"] + 1
    h = c["y1"] - c["y0"] + 1
    if c["n"] < 25:
        continue
    if w >= 55 and h <= 6:      # 细长横线
        continue
    if h >= 45 and w <= 5:      # 细长竖线
        continue
    kept.append(c)
print(f"\n保留 {len(kept)} 个字符块")

# 按 x 排序、按间距聚类成字符（一个字符可能由多个笔画域组成）
kept.sort(key=lambda c: c["x0"])
clusters = []
for c in kept:
    if clusters and c["x0"] - clusters[-1]["x1"] <= 6:
        cl = clusters[-1]
        cl["x1"] = max(cl["x1"], c["x1"])
        cl["y0"] = min(cl["y0"], c["y0"])
        cl["y1"] = max(cl["y1"], c["y1"])
        cl["ids"].append(c["id"])
        cl["n"] += c["n"]
    else:
        clusters.append({"x0": c["x0"], "x1": c["x1"], "y0": c["y0"],
                         "y1": c["y1"], "ids": [c["id"]], "n": c["n"]})
print(f"聚类成 {len(clusters)} 个字符：")
for i, cl in enumerate(clusters):
    print(f"  字符{i+1}: x {cl['x0']}-{cl['x1']}  y {cl['y0']}-{cl['y1']}  域={cl['ids']}")

keepset = set()
for c in kept:
    keepset.add(c["id"])

# 逐个字符渲染
for i, cl in enumerate(clusters):
    x0, x1, y0, y1 = cl["x0"], cl["x1"], cl["y0"], cl["y1"]
    ids = set(cl["ids"])
    cw = x1 - x0 + 1
    ch = y1 - y0 + 1
    print(f"\n===== 字符 {i+1}  (w={cw} h={ch}) =====")
    scale = 30 / ch
    ow = max(6, int(cw * scale))
    out = Image.new("L", (ow, 30), 255)
    op = out.load()
    for yy in range(ch):
        for xx in range(cw):
            if comp[y0 + yy][x0 + xx] in ids:
                op[int(xx * scale), int(yy * scale)] = 0
    sp = out.load()
    for y in range(30):
        print("".join("#" if sp[x, y] < 128 else " " for x in range(ow)))
