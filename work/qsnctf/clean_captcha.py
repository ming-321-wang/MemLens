# -*- coding: utf-8 -*-
"""分析验证码图片：分离颜色层、去干扰线、放大，输出 ASCII 供判读 + 保存增强图。"""
from pathlib import Path
from PIL import Image

SRC = Path(r"D:\MemLens\work\qsnctf\captcha.png")
im = Image.open(SRC).convert("RGB")
W, H = im.size
px = im.load()
print(f"size {W}x{H}")

# 颜色统计
from collections import Counter
c = Counter()
for y in range(H):
    for x in range(W):
        c[px[x, y]] += 1
print("top colors:")
for col, n in c.most_common(8):
    print(f"   {col}  x{n}")

# 文字颜色：出现频次最高的"非白非灰"颜色（紫色手写体通常是一两种色）
def is_ink(p):
    r, g, b = p
    # 紫色/品红：R、B 高，G 低；或整体偏暗
    return not (r > 230 and g > 230 and b > 230)

ink = [col for col, n in c.most_common(12) if is_ink(col) and n > 40]
print("\n候选墨色:", ink[:6])

# 用候选墨色中最"紫"的作为文字色
def purple_score(p):
    r, g, b = p
    return (r + b) - 2 * g
if ink:
    text_color = max(ink, key=purple_score) if any(purple_score(i) > 30 for i in ink) else ink[0]
else:
    text_color = (0, 0, 0)
print("选定文字色:", text_color)

# 生成二值图：文字色附近 → 黑，其它 → 白
def dist(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b))

out = Image.new("L", (W, H), 255)
op = out.load()
for y in range(H):
    for x in range(W):
        p = px[x, y]
        d = dist(p, text_color)
        # 也接受"暗色"（黑干扰线也暗，但干扰线细且水平）
        op[x, y] = 0 if d < 9000 else 255

# 去水平干扰线：统计每行的黑像素，若某行黑像素占比过高（横线）则清空
for y in range(H):
    row_dark = sum(1 for x in range(W) if op[x, y] < 128)
    if row_dark > W * 0.45:
        for x in range(W):
            op[x, y] = 255

out_big = out.resize((W * 4, H * 4), Image.LANCZOS)
out_big.save(r"D:\MemLens\work\qsnctf\captcha_clean.png")
print("\nsaved captcha_clean.png")

# ASCII 渲染（降采样到 100x30 左右可读）
aw, ah = 96, 26
small = out.resize((aw, ah), Image.LANCZOS)
sp = small.load()
print("\n=== ASCII ===")
for y in range(ah):
    line = ""
    for x in range(aw):
        v = sp[x, y]
        line += "#" if v < 110 else ("+" if v < 190 else " ")
    print(line)
