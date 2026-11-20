# -*- coding: utf-8 -*-
"""
动态壁纸生成：缓慢流动的"内存数据流"（无缝循环）

设计约束（壁纸不是视频，要耐看 8 小时）：
  * 运动必须慢且幅度小 —— 字符 36 px/s 上浮（约每秒 1.8 个字符高），
    快于这个值长时间观看会晕；
  * **严格无缝循环**——字符层按 540 px 周期复制，roll 到周期末尾正好回到起点；
  * 中央压暗且字符稀疏 —— DSH 界面叠在上面，不能抢注意力；
  * 光晕呼吸与字符滚动同周期，整体一个循环节拍。

产物：1920×1080 / 24 fps / 15 s / libx264，预计 5–12 MB。
"""
from __future__ import annotations

import math
import random
import subprocess
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1920, 1080
FPS = 24
DUR = 15
NFRAMES = FPS * DUR
PERIOD = 540                      # 字符层滚动周期（px），必须能被 roll 整除地循环
OUTDIR = Path(r"D:\MemLens\work\wp_frames")
OUTDIR.mkdir(parents=True, exist_ok=True)
MP4 = Path(r"D:\MemLens\work\MemLens_dynamic_wallpaper.mp4")
FFMPEG = r"C:\Users\WZH\AppData\Local\Microsoft\WinGet\Links\ffmpeg.EXE"

FONT_MONO = r"C:\Windows\Fonts\consola.ttf"
CZ = (int(W * 0.30), int(H * 0.26))          # 中央区半宽/半高
CX, CY = W // 2, H // 2
random.seed(20261005)


def build_base() -> np.ndarray:
    """深蓝垂直渐变底（float32 0..1 归一化，便于后续线性叠加）。"""
    top = np.array([0.020, 0.031, 0.055])
    mid = np.array([0.039, 0.063, 0.102])
    bot = np.array([0.024, 0.035, 0.059])
    ys = np.linspace(0, 1, H)
    seg = np.where(ys < 0.5, ys * 2, (ys - 0.5) * 2)
    a = np.where((ys < 0.5)[:, None], top, mid)
    b = np.where((ys < 0.5)[:, None], mid, bot)
    arr = a + (b - a) * seg[:, None]
    return np.repeat(arr[:, None, :], W, axis=1).astype(np.float32)


def build_glow(cx, cy, rx, ry, color, peak) -> np.ndarray:
    """椭圆径向光晕（float32，峰值 peak）。"""
    yy, xx = np.mgrid[0:H, 0:W]
    d = np.sqrt(((xx - cx) / rx) ** 2 + ((yy - cy) / ry) ** 2)
    a = np.clip(1.0 - d, 0, 1) ** 2.2 * peak
    return (a[..., None] * np.array(color, dtype=np.float32)[None, None, :]).astype(np.float32)


def build_hex(period: int) -> np.ndarray:
    """
    字符层（RGBA float32）。高度 H + period，且满足 layer[y] == layer[y+period]
    （对 y ∈ [0, H)），这样 roll 到 period 末尾正好回到起点 —— 无缝的关键。
    """
    Hm = H + period
    layer = Image.new("RGBA", (W, Hm), (0, 0, 0, 0))
    dr = ImageDraw.Draw(layer)
    try:
        f_small = ImageFont.truetype(FONT_MONO, 15)
        f_big = ImageFont.truetype(FONT_MONO, 23)
    except Exception:
        f_small = f_big = ImageFont.load_default()

    TOKENS = ["0x7ffe", "0x000001", "EPROCESS", "PEB", "TEB", "MDMP", "PTRACE",
              "VAD", "POOL", "SHA256", "MD5", "EVIDENCE", "MEMLENS", "VOL3",
              "offset", "page", "PTE", "mmap", "fd:", "pid:", "0xdeadbeef"]
    HEXD = "0123456789abcdefABCDEF"

    def density(x, y):
        """中央区低密度（越靠中心越少），保证 DSH 界面区干净。"""
        dx = max(abs(x - CX) - CZ[0], 0) / (W * 0.30)
        dy = max(abs(y - CY) - CZ[1], 0) / (H * 0.34)
        return min(1.0, math.sqrt(dx * dx + dy * dy))

    # 只画前 H 行，之后按周期复制
    for _ in range(900):
        x = random.randint(20, W - 130)
        y = random.randint(20, H - 30)
        if random.random() > density(x, y) * 0.95:
            continue
        s = "".join(random.choice(HEXD) for _ in range(random.randint(6, 13)))
        dr.text((x, y), s, font=f_small, fill=(150, 195, 225, random.randint(12, 28)))

    for _ in range(80):
        x = random.randint(30, W - 250)
        y = random.randint(30, H - 40)
        if random.random() > density(x, y):
            continue
        dr.text((x, y), random.choice(TOKENS),
                font=f_big if random.random() < 0.3 else f_small,
                fill=(168, 208, 235, random.randint(26, 48)))

    arr = np.asarray(layer).astype(np.float32) / 255.0
    # 周期性复制：arr[period:period+H] = arr[0:H]
    out = np.zeros((H + period, W, 4), dtype=np.float32)
    out[0:H] = arr[0:H]
    out[period:period + H] = arr[0:H]
    # 重叠段 [period, H) 取两者中较亮者，避免出现两条并列的同一串
    overlap = slice(period, H)
    out[overlap] = np.maximum(out[overlap], arr[overlap])
    return out


def build_grid() -> np.ndarray:
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(layer)
    step = 96
    for x in range(0, W + 1, step):
        col = (130, 180, 215, 11) if (x // step) % 5 == 0 else (120, 165, 205, 7)
        dr.line([(x, 0), (x, H)], fill=col)
    for y in range(0, H + 1, step):
        col = (130, 180, 215, 11) if (y // step) % 5 == 0 else (120, 165, 205, 7)
        dr.line([(0, y), (W, y)], fill=col)
    return np.asarray(layer).astype(np.float32) / 255.0


def build_vignette() -> np.ndarray:
    """中央压暗因子（0.62 ~ 1.0），径向过渡。"""
    yy, xx = np.mgrid[0:H, 0:W]
    d = np.sqrt((xx - CX) ** 2 + (yy - CY) ** 2) / (H * 0.72)
    s = np.clip(d, 0, 1)
    s = s * s * (3 - 2 * s)
    return (0.62 + 0.38 * s).astype(np.float32)


def main():
    print(f"准备 {W}×{H} @ {FPS}fps × {DUR}s = {NFRAMES} 帧 …")
    if any(OUTDIR.glob("wp_*.png")):
        for p in OUTDIR.glob("wp_*.png"):
            p.unlink()

    base = build_base()
    glow_c = build_glow(560, 340, 1050, 760, (0.10, 0.32, 0.47), 1.0)
    glow_p = build_glow(1420, 860, 1000, 700, (0.23, 0.17, 0.41), 0.85)
    grid = build_grid()
    hexlayer = build_hex(PERIOD)
    vig = build_vignette()[..., None]

    print("开始逐帧渲染 …")
    shape_hint = None
    for f in range(NFRAMES):
        t = f / FPS
        ph = 0.5 + 0.5 * math.sin(2 * math.pi * t / DUR)      # 呼吸相位
        off = int(PERIOD * t / DUR)                            # 0 .. PERIOD

        arr = base + glow_c * (0.28 + 0.22 * ph) + glow_p * (0.22 + 0.20 * ph)
        arr = arr + grid[..., :3]

        # 字符层滚动（roll 后取前 H 行）
        rolled = np.roll(hexlayer, -off, axis=0)[:H]
        al = rolled[..., 3:4]
        arr = arr * (1 - al) + rolled[..., :3] * al

        arr = np.clip(arr * vig, 0, 1)
        img = Image.fromarray((arr * 255).astype(np.uint8), "RGB")
        if f % 40 == 0:
            print(f"  帧 {f + 1}/{NFRAMES}  phase={ph:.2f} off={off}")
        img.save(OUTDIR / f"wp_{f:04d}.png", optimize=False)
        shape_hint = img.size

    print(f"渲染完成（{shape_hint[0]}×{shape_hint[1]}）")

    # ---- ffmpeg 编码 ----
    if MP4.exists():
        MP4.unlink()
    cmd = [
        FFMPEG, "-y", "-hide_banner", "-loglevel", "error",
        "-framerate", str(FPS),
        "-i", str(OUTDIR / "wp_%04d.png"),
        "-c:v", "libx264", "-profile:v", "high", "-level", "4.0",
        "-pix_fmt", "yuv420p",
        "-crf", "23", "-preset", "medium",
        "-movflags", "+faststart",
        "-an",
        str(MP4),
    ]
    print("ffmpeg 编码 …")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        print("ffmpeg 失败:")
        print((r.stderr or "")[:1500])
        raise SystemExit(1)
    if r.stderr.strip():
        print("ffmpeg stderr:", r.stderr[:600])
    print(f"\n*** 编码完成：{MP4}  ({MP4.stat().st_size/1048576:.2f} MiB) ***")


if __name__ == "__main__":
    main()
