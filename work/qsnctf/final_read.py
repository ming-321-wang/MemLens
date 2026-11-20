# -*- coding: utf-8 -*-
"""去线后重算列投影，按间隙精确定位字符，并逐字渲染（最终判读用）。"""
from pathlib import Path
from PIL import Image

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
        if dist(px[x, y], TEXT) < 12000:
            ink[y][x] = True

# 去水平长段与垂直长段
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
print("列投影:", " ".join(f"{v:2d}" for v in col))

# 找字符段（连续 col>0，允许 <=2 的空隙）
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
print(f"\n字符段 {len(segs)} 个: {segs}")

for i, (a, b) in enumerate(segs):
    sub = im.crop((a, 0, b + 1, H)).convert("L")
    sw, sh = sub.size
    scale = 34 / sh
    sub2 = sub.resize((max(6, int(sw * scale)), 34), Image.LANCZOS)
    sp = sub2.load()
    print(f"\n===== 字符 {i+1}  x={a}-{b} (w={b-a+1}) =====")
    for y in range(34):
        print("".join("#" if sp[x, y] < 150 else " " for x in range(sub2.size[0])))
