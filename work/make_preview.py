# -*- coding: utf-8 -*-
"""生成 1920×1080 预览图，便于在对话中检查视觉效果。"""
from pathlib import Path

from PIL import Image

src = Path(r"C:\Users\WZH\Desktop\MemLens_wallpaper_4K.png")
im = Image.open(src).convert("RGB")
print("原图:", im.size)
prev = im.resize((1920, 1080), Image.LANCZOS)
p = Path(r"D:\MemLens\work\wallpaper_preview.png")
prev.save(p, "PNG", optimize=True)
print("预览:", p, p.stat().st_size, "bytes")

# 另外裁四块局部放大，检查 hex/网格/角标细节
crops = {
    "左上（光晕+hex+角标）": (0, 0, 1280, 720),
    "右下（暗紫光晕+hex）": (2560, 1440, 3840, 2160),
    "中央（必须干净）": (960, 540, 2880, 1620),
}
for name, box in crops.items():
    c = im.crop(box).resize((960, 540), Image.LANCZOS)
    q = Path(rf"D:\MemLens\work\crop_{list(crops).index(name)}.png")
    c.save(q, "PNG", optimize=True)
    print(f"{name}: {q} ({q.stat().st_size:,} B)")
