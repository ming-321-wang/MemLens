# -*- coding: utf-8 -*-
"""按列投影分割字符，逐个放大渲染，便于精确判读。"""
from pathlib import Path
from PIL import Image

SRC = Path(r"D:\MemLens\work\qsnctf\captcha.png")
im = Image.open(SRC).convert("RGB")
W, H = im.size
px = im.load()

TEXT = (179, 74, 159)


def dist(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b))


# 二值墨迹掩码（含暗色）
ink = [[False] * W for _ in range(H)]
for y in range(H):
    for x in range(W):
        p = px[x, y]
        if dist(p, TEXT) < 9000 or (p[0] < 150 and p[1] < 150 and p[2] < 150):
            ink[y][x] = True

# 去水平干扰线：单行墨迹占比 > 50% 视为横线，整行清除
for y in range(H):
    n = sum(ink[y])
    if n > W * 0.5:
        for x in range(W):
            ink[y][x] = False

# 列投影
col = [sum(1 for y in range(H) if ink[y][x]) for x in range(W)]
print("列投影:")
print(" ".join(str(min(v, 9)) for v in col))

# 分割：连续无墨列宽 >= 3 视为间隔
groups = []
start = None
gap = 0
for x in range(W):
    if col[x] > 0:
        if start is None:
            start = x
        gap = 0
    else:
        if start is not None:
            gap += 1
            if gap >= 3:
                groups.append((start, x - gap + 1))
                start = None
                gap = 0
if start is not None:
    groups.append((start, W))

# 合并过窄的分组（噪点）
merged = []
for g in groups:
    if merged and g[0] - merged[-1][1] < 4:
        merged[-1] = (merged[-1][0], g[1])
    else:
        merged.append(g)
print(f"\n分割出 {len(merged)} 段: {merged}")

# 逐段渲染
for i, (a, b) in enumerate(merged):
    if b - a < 4:
        continue
    sub = im.crop((max(0, a - 2), 0, min(W, b + 2), H)).convert("L")
    sw, sh = sub.size
    # 放大到高度 24、宽度等比
    scale = 26 / sh
    sub2 = sub.resize((max(8, int(sw * scale)), 26), Image.LANCZOS)
    sp = sub2.load()
    print(f"\n--- char {i+1}  (cols {a}-{b}, width {b-a}) ---")
    for y in range(26):
        line = ""
        for x in range(sub2.size[0]):
            v = sp[x, y]
            # 紫色在灰度下也是暗的
            line += "#" if v < 150 else " "
        print(line)
