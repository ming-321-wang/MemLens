# -*- coding: utf-8 -*-
"""
生成 MemLens 应用图标 (.ico)。

设计：深蓝圆角底 + 青色"内存条/镜头"意象 —— 一个简化的透镜（Lens）加一条
内存插槽横纹，配色沿用壁纸的深蓝(#0A1018)/青(#4F8CFF)，与程序主题一致。
输出多尺寸 ico（16/24/32/48/64/128/256），Windows 各场景自动取合适尺寸。
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(r"D:\MemLens\memlens.ico")

BG_TOP = (14, 22, 38)
BG_BOT = (7, 12, 22)
ACCENT = (79, 140, 255)          # 与 DSH/壁纸一致的蓝
ACCENT2 = (86, 200, 232)         # 青色高光
S = 1024


def make(size: int = S) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = int(size * 0.22)

    # 圆角底（垂直渐变）
    grad = Image.new("RGB", (1, size))
    gd = ImageDraw.Draw(grad)
    for y in range(size):
        t = y / max(1, size - 1)
        gd.point((0, y), fill=tuple(
            int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3)))
    grad = grad.resize((size, size))

    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)

    # 边框
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=r,
                        outline=(60, 96, 150, 220), width=max(2, size // 160))

    cx, cy = size * 0.5, size * 0.46
    outer = size * 0.27
    inner = size * 0.13

    # 透镜外环
    d.ellipse([cx - outer, cy - outer, cx + outer, cy + outer],
              outline=ACCENT, width=max(3, int(size * 0.045)))
    # 内圈高光
    d.ellipse([cx - inner, cy - inner, cx + inner, cy + inner],
              outline=ACCENT2, width=max(2, int(size * 0.028)))
    # 镜心亮点
    dot = size * 0.045
    d.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=ACCENT2)

    # 内存插槽横纹（下方三条，宽度递减 → 数据流意象）
    for i, wfrac in enumerate((0.46, 0.34, 0.22)):
        y = size * (0.775 + i * 0.062)
        half = size * wfrac / 2
        alpha = 235 - i * 55
        d.rounded_rectangle(
            [cx - half, y, cx + half, y + size * 0.036],
            radius=size * 0.018,
            fill=(ACCENT[0], ACCENT[1], ACCENT[2], alpha),
        )
    # 左上角小方点（取证"标记"意象）
    b = size * 0.055
    d.rounded_rectangle([size * 0.155, size * 0.155, size * 0.155 + b, size * 0.155 + b],
                        radius=size * 0.012, fill=ACCENT2)
    return img


base = make(S)
sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
base.save(OUT, format="ICO", sizes=sizes)
print(f"已生成 {OUT}  ({OUT.stat().st_size:,} bytes)")

# 同时导出 PNG 预览，便于查看
prev = Path(r"D:\MemLens\work\icon_preview.png")
make(256).save(prev, "PNG")
print(f"预览 {prev}")
