# -*- coding: utf-8 -*-
"""自动取色的验证码渲染（不硬编码文字色）。"""
from collections import Counter
from pathlib import Path

from PIL import Image

p = Path(r"D:\MemLens\work\qsnctf\captcha_now.png")
im = Image.open(p).convert("RGB")
W, H = im.size
px = im.load()

c = Counter()
for y in range(0, H, 2):
    for x in range(0, W, 2):
        c[px[x, y]] += 1


def colored(q):
    r, g, b = q
    if r > 225 and g > 225 and b > 225:
        return False
    return (max(q) - min(q)) > 25 or max(q) < 170


cands = [q for q, n in c.items() if colored(q) and n >= 25]
text = max(cands, key=lambda q: c[q]) if cands else (0, 0, 0)
print("size", W, H, "ink-color:", text)


def dist(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b))


ink = [[False] * W for _ in range(H)]
for y in range(H):
    for x in range(W):
        if dist(px[x, y], text) < 16000:
            ink[y][x] = True

# 去水平/垂直长段
for y in range(H):
    row, x = ink[y], 0
    while x < W:
        if row[x]:
            s = x
            while x < W and row[x]:
                x += 1
            if x - s >= 10:
                for k in range(s, x):
                    row[k] = False
        else:
            x += 1
for x in range(W):
    y = 0
    while y < H:
        if ink[y][x]:
            s = y
            while y < H and ink[y][x]:
                y += 1
            if y - s >= 22:
                for k in range(s, y):
                    ink[k][x] = False
        else:
            y += 1

col = [sum(1 for y in range(H) if ink[y][x]) for x in range(W)]
segs, s, gap = [], None, 0
for x in range(W):
    if col[x] > 0:
        if s is None:
            s = x
        gap = 0
    elif s is not None:
        gap += 1
        if gap > 2:
            segs.append((s, x - gap))
            s, gap = None, 0
if s is not None:
    segs.append((s, W - 1))
segs = [(a, b) for a, b in segs if b - a >= 5]
print("segments:", segs)

for i, (a, b) in enumerate(segs):
    cw, ch = b - a + 1, H
    rows = 26
    scale = rows / ch
    ow = max(5, int(cw * scale))
    print(f"\n--- seg{i+1} x={a}-{b} w={cw} ---")
    for r in range(rows):
        line = ""
        for cc in range(ow):
            hit = False
            for dy in range(max(1, H // rows + 1)):
                for dx in range(max(1, cw // ow + 1)):
                    xx = min(W - 1, a + int(cc / scale) + dx)
                    yy = min(H - 1, int(r / scale) + dy)
                    if ink[yy][xx]:
                        hit = True
                        break
                if hit:
                    break
            line += "#" if hit else " "
        print("   " + line)
