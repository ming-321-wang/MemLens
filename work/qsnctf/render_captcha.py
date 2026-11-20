# -*- coding: utf-8 -*-
"""剔除长水平线段（干扰线），再整幅高清 ASCII 渲染。"""
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

before = sum(sum(r) for r in ink)

# 剔除水平连续段 >= 10 的像素（字符笔画罕见这么长的水平段）
RUN = 10
removed = 0
for y in range(H):
    row = ink[y]
    x = 0
    while x < W:
        if row[x]:
            s = x
            while x < W and row[x]:
                x += 1
            if x - s >= RUN:
                for k in range(s, x):
                    row[k] = False
                    removed += 1
        else:
            x += 1

# 同样剔除垂直长段
for x in range(W):
    y = 0
    while y < H:
        if ink[y][x]:
            s = y
            while y < H and ink[y][x]:
                y += 1
            if y - s >= 22:
                for k in range(s, y):
                    if ink[k][x]:
                        ink[k][x] = False
                        removed += 1
        else:
            y += 1

after = sum(sum(r) for r in ink)
print(f"墨迹像素 {before} -> {after}（移除 {removed}）")

# 整幅渲染到 150x40
AW, AH = 150, 38
out = Image.new("L", (AW, AH), 255)
op = out.load()
for y in range(AH):
    sy = int(y * H / AH)
    for x in range(AW):
        sx = int(x * W / AW)
        # 该格内任一墨迹即点亮
        hit = any(ink[min(H - 1, sy + dy)][min(W - 1, sx + dx)]
                  for dy in range(max(1, H // AH + 1)) for dx in range(max(1, W // AW + 1)))
        op[x, y] = 0 if hit else 255
out.save(r"D:\MemLens\work\qsnctf\captcha_noline.png")

sp = out.load()
print("\n===== 高清渲染（去线后）=====")
for y in range(AH):
    print("".join("#" if sp[x, y] < 128 else " " for x in range(AW)))
