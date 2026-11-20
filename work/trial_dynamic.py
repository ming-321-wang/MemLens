# -*- coding: utf-8 -*-
"""试跑：生成 5 个关键帧拼成预览，确认动画设计是否合适（避免全量跑完才发现问题）。"""
import math
import random
import sys
from pathlib import Path

import numpy as np
from PIL import Image

# 复用主脚本的构建函数
sys.path.insert(0, r"D:\MemLens\work")
import make_dynamic_wallpaper as M

W, H, FPS, DUR, PERIOD = M.W, M.H, M.FPS, M.DUR, M.PERIOD

print("预计算图层 …")
base = M.build_base()
glow_c = M.build_glow(560, 340, 1050, 760, (0.10, 0.32, 0.47), 1.0)
glow_p = M.build_glow(1420, 860, 1000, 700, (0.23, 0.17, 0.41), 0.85)
grid = M.build_grid()
hexlayer = M.build_hex(PERIOD)
vig = M.build_vignette()[..., None]


def frame(f):
    t = f / FPS
    ph = 0.5 + 0.5 * math.sin(2 * math.pi * t / DUR)
    off = int(PERIOD * t / DUR)
    arr = base + glow_c * (0.28 + 0.22 * ph) + glow_p * (0.22 + 0.20 * ph)
    arr = arr + grid[..., :3]
    rolled = np.roll(hexlayer, -off, axis=0)[:H]
    al = rolled[..., 3:4]
    arr = arr * (1 - al) + rolled[..., :3] * al
    return np.clip(arr * vig, 0, 1)


# 抓 5 个时刻：0s / 3.75s / 7.5s / 11.25s / 14.96s（应几乎与 0s 相同 → 验证无缝）
times = [0, int(FPS * 3.75), int(FPS * 7.5), int(FPS * 11.25), NFRAMES - 1] if (NFRAMES := M.NFRAMES) else [0]
imgs = []
for f in times:
    print(f"  渲染帧 {f} (t={f/FPS:.2f}s)")
    a = frame(f)
    imgs.append(Image.fromarray((a * 255).astype(np.uint8), "RGB"))

# 横向拼成一张 5 连拍
strip = Image.new("RGB", (W // 2 * len(imgs), H // 2), (0, 0, 0))
for i, im in enumerate(imgs):
    strip.paste(im.resize((W // 2, H // 2), Image.LANCZOS), (i * W // 2, 0))
p = Path(r"D:\MemLens\work\dyn_preview_strip.png")
strip.save(p, "PNG", optimize=True)
print(f"\n预览条: {p} ({p.stat().st_size/1024:.0f} KB)  {strip.size}")

# 无缝性检查：首帧 vs 末帧的差异
a0 = np.asarray(imgs[0]).astype(np.float32)
a1 = np.asarray(imgs[-1]).astype(np.float32)
diff = np.abs(a0 - a1)
print(f"\n无缝循环检查：首帧(t=0) vs 末帧(t={times[-1]/FPS:.2f}s)")
print(f"  平均差 = {diff.mean():.3f}/255   最大差 = {diff.max():.0f}/255")
print("  （平均差 <3 即视觉无感知跳变）")
