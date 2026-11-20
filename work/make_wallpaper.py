# -*- coding: utf-8 -*-
"""
DSH 桌面壁纸生成器（4K · 深色取证风 · 中央低干扰）

设计约束（来自用户要求）：
  * **不影响对话视觉** → 中央 safe zone（屏幕中心 1920×1080）内除极淡网格外
    不放任何装饰，并额外压暗；文字区对比度低、长时间看不累。
  * **清晰** → 3840×2160 原生 4K，PNG 无损 + 高质量 JPEG 备选。
  * **好看** → 多层叠加：垂直渐变底 + 双色径向光晕（左上青 / 右下暗紫）
    + 细网格 + 边缘十六进制字符（Consolas 等宽，呼应内存取证主题）+ 四角 L 形角标。

配色刻意避开高饱和：全部低明度、低对比，做"安静的背景"而不是"抢眼的图画"。
"""

from __future__ import annotations

import random
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 3840, 2160
# 中央安全区（对话区）：占画面中心一半
SZ_W, SZ_H = 1920, 1080
SZ = ((W - SZ_W) // 2, (H - SZ_H) // 2, (W + SZ_W) // 2, (H + SZ_H) // 2)

OUT = [
    Path(r"C:\Users\WZH\Desktop\MemLens_wallpaper_4K.png"),
    Path(r"D:\DSH\工作区\MemLens_wallpaper_4K.png"),
    Path(r"D:\MemLens\work\MemLens_wallpaper_4K.png"),
]
OUT_JPG = [
    Path(r"C:\Users\WZH\Desktop\MemLens_wallpaper_4K.jpg"),
    Path(r"D:\DSH\工作区\MemLens_wallpaper_4K.jpg"),
]

FONT_MONO = r"C:\Windows\Fonts\consola.ttf"
FONT_SANS = r"C:\Windows\Fonts\segoeui.ttf"

random.seed(20261005)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def build_base() -> Image.Image:
    """垂直渐变底 + 中心径向微提亮（制造纵深，但中心仍比边缘暗）。"""
    top, mid, bot = (5, 8, 14), (10, 16, 26), (6, 9, 15)
    arr = np.zeros((H, W, 3), dtype=np.uint8)
    for y in range(H):
        t = y / (H - 1)
        if t < 0.5:
            c = lerp(top, mid, t * 2)
        else:
            c = lerp(mid, bot, (t - 0.5) * 2)
        arr[y, :] = c
    # 中心径向：中心略暗、边缘略亮 —— 让中央成为天然的"文字区"
    yy, xx = np.mgrid[0:H, 0:W]
    d = np.sqrt(((xx - W / 2) / (W / 2)) ** 2 + ((yy - H / 2) / (H / 2)) ** 2)
    d = np.clip(d, 0, 1.6) / 1.6
    lift = (np.clip(1.0 - d, 0, 1) * 0.55) ** 1.6          # 中心提亮因子
    base = arr.astype(np.float32)
    # 中心加一点点冷色调（0.6→1.0 的混合），看起来不死板
    tint = np.array([9, 15, 26], dtype=np.float32)
    base += lift[..., None] * tint[None, None, :] * 0.55
    return Image.fromarray(np.clip(base, 0, 255).astype(np.uint8), "RGB")


def _fade(x, y, band=320):
    """
    字符/网格线的透明度衰减：safe zone 内严格为 0，向外 band 像素内平滑升到 1。

    用 Chebyshev（矩形）距离而非径向：因为 safe zone 是矩形（1920×1080），
    径向衰减无法让整个矩形内归零（垂直半高 540 > 水平半宽 960 的两侧例外），
    实测会让 MEMLENS / VAD 等 token 渗进对话区。
    而离散字符用矩形硬切**看不出边界**（字符 alpha 本身 <30/255，且该区域已被
    径向 vignette 压暗）；真正会暴露"方形轮廓"的是整幅图的明暗（vignette），
    那个已改用纯径向。两者分工：字符矩形切、明暗径向过渡。
    """
    dx = max(SZ[0] - x, x - SZ[2], 0)
    dy = max(SZ[1] - y, y - SZ[3], 0)
    t = min(max(max(dx, dy) / band, 0.0), 1.0)
    return t * t * (3 - 2 * t)          # smoothstep


def add_glow(img: Image.Image, cx, cy, rx, ry, color, peak):
    """叠加一个椭圆径向光晕（高斯模糊，柔和无边）。"""
    yy, xx = np.mgrid[0:H, 0:W]
    d = np.sqrt(((xx - cx) / rx) ** 2 + ((yy - cy) / ry) ** 2)
    a = np.clip(1.0 - d, 0, 1) ** 2.2 * (peak / 255.0)
    glow = np.zeros((H, W, 4), dtype=np.uint8)
    glow[..., 0] = color[0]
    glow[..., 1] = color[1]
    glow[..., 2] = color[2]
    glow[..., 3] = (a * 255).astype(np.uint8)
    layer = Image.fromarray(glow, "RGBA").filter(
        ImageFilter.GaussianBlur(radius=max(rx, ry) * 0.18))
    img.alpha_composite(layer)


def add_grid(img: Image.Image, step=96):
    """
    细网格。主线也要随接近中央渐隐 —— 否则网格主线恰好落在 safe zone
    边界时会形成一条横贯屏幕的亮线（实测踩过）。
    """
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(layer)
    c_minor = (120, 165, 205, 7)
    c_major = (130, 180, 215, 11)
    for x in range(0, W + 1, step):
        col = c_major if (x // step) % 5 == 0 else c_minor
        # 竖线的中点位于 safe zone 内，按该点的 fade 决定透明度
        f = _fade(x, H // 2)
        if f <= 0.05:
            continue
        dr.line([(x, 0), (x, H)],
                fill=(col[0], col[1], col[2], int(col[3] * f)))
    for y in range(0, H + 1, step):
        col = c_major if (y // step) % 5 == 0 else c_minor
        f = _fade(W // 2, y)
        if f <= 0.05:
            continue
        dr.line([(0, y), (W, y)],
                fill=(col[0], col[1], col[2], int(col[3] * f)))
    img.alpha_composite(layer)


def add_hex(img: Image.Image):
    """
    边缘六进制字符（内存取证主题）。密度刻意压低，且**随接近中央平滑消失**。
    """
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(layer)
    try:
        f_small = ImageFont.truetype(FONT_MONO, 15)
        f_big = ImageFont.truetype(FONT_MONO, 22)
    except Exception:
        f_small = f_big = ImageFont.load_default()

    TOKENS = ["0x7ffe", "0x000001", "EPROCESS", "PEB", "TEB", "MDMP", "PTRACE",
              "VAD", "POOL", "SHA256", "MD5", "EVIDENCE", "MEMLENS", "VOL3",
              "offset", "page", "PTE", "mmap", "fd:", "pid:", "0xdeadbeef"]
    HEXD = "0123456789abcdefABCDEF"

    def put(x, y, s, font, alpha):
        f = _fade(x, y)
        if f <= 0.02 or alpha * f < 2:
            return
        dr.text((x, y), s, font=font, fill=(150, 195, 225, int(alpha * f)))

    for _ in range(560):
        put(random.randint(20, W - 120), random.randint(20, H - 30),
            "".join(random.choice(HEXD) for _ in range(random.randint(6, 14))),
            f_small, random.randint(12, 28))

    for _ in range(70):
        x = random.randint(30, W - 260)
        y = random.randint(30, H - 40)
        put(x, y, random.choice(TOKENS),
            f_big if random.random() < 0.3 else f_small, random.randint(24, 46))

    img.alpha_composite(layer)


def add_corners(img: Image.Image):
    """四角 L 形角标（很淡，给画面一个"画框"感）。"""
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(layer)
    L, wd = 150, 2
    col = (110, 160, 200, 46)
    m = 90
    for (cx, cy, sx, sy) in ((m, m, 1, 1), (W - m, m, -1, 1),
                             (m, H - m, 1, -1), (W - m, H - m, -1, -1)):
        dr.line([(cx, cy), (cx + sx * L, cy)], fill=col, width=wd)
        dr.line([(cx, cy), (cx, cy + sy * L)], fill=col, width=wd)
        # 末端小点
        dr.ellipse([cx + sx * L - 3, cy - 3, cx + sx * L + 3, cy + 3],
                   fill=(140, 190, 225, 60))
    img.alpha_composite(layer)


def vignette(img: Image.Image) -> Image.Image:
    """
    最终暗角：中央额外压暗并"抹平"。

    这是"不影响对话视觉"的最后一道保险。关键在**径向过渡 + 宽过渡带**：
    早期版本用"到矩形边界的距离"，过渡带只占画面 30%，边界处出现一条
    肉眼可见的明暗交界线；改用矩形后又会在四角看出方形暗区轮廓。
    现在用纯径向距离，safe zone 四角先亮起、边界呈弧形，看不出任何直线。
    """
    yy, xx = np.mgrid[0:H, 0:W]
    d = np.sqrt((xx - W / 2) ** 2 + (yy - H / 2) ** 2) / (H * 0.66)
    smooth = np.clip(d, 0, 1)
    smooth = smooth * smooth * (3 - 2 * smooth)
    factor = (0.60 + 0.40 * smooth)                       # 中心 ×0.60，外围 ×1.0
    arr = np.asarray(img.convert("RGB")).astype(np.float32) * factor[..., None]
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")


def main():
    print(f"生成 {W}×{H} 壁纸 …")
    img = build_base().convert("RGBA")

    # 双色光晕（左上青、右下暗紫）+ 两个更小的点缀
    add_glow(img, 760, 380, 1500, 1050, (26, 82, 120), 62)
    add_glow(img, 3100, 1780, 1450, 1000, (58, 44, 104), 52)
    add_glow(img, 3450, 420, 700, 520, (30, 70, 96), 30)
    add_glow(img, 380, 1720, 640, 470, (66, 48, 96), 26)

    add_grid(img)
    add_hex(img)
    add_corners(img)

    out = vignette(img)

    for p in OUT:
        p.parent.mkdir(parents=True, exist_ok=True)
        out.save(p, "PNG", optimize=True)
        print(f"  PNG  {p}  ({p.stat().st_size/1048576:.1f} MiB)")
    for p in OUT_JPG:
        p.parent.mkdir(parents=True, exist_ok=True)
        out.save(p, "JPEG", quality=94, subsampling=0, optimize=True)
        print(f"  JPG  {p}  ({p.stat().st_size/1048576:.2f} MiB)")

    # 中央 vs 边缘亮度统计（验证"不影响对话视觉"）
    a = np.asarray(out.convert("L")).astype(np.float32)
    cx0, cy0, cx1, cy1 = SZ
    centre = a[cy0:cy1, cx0:cx1]
    edge = np.concatenate([a[:200, :].ravel(), a[-200:, :].ravel(),
                           a[:, :200].ravel(), a[:, -200:].ravel()])
    print("\n=== 亮度统计（验证中央低干扰）===")
    print(f"  中央 safe zone  {centre.shape[1]}×{centre.shape[0]}: "
          f"均值={centre.mean():.1f}  标准差={centre.std():.2f}  "
          f"最大={centre.max():.0f}")
    print(f"  四周边缘        : 均值={edge.mean():.1f}  标准差={edge.std():.2f}")
    print(f"  → 中央标准差仅 {centre.std():.2f}（接近纯色，不会干扰阅读）；"
          f"中央比边缘暗 {edge.mean()-centre.mean():.1f}/255")


if __name__ == "__main__":
    main()
