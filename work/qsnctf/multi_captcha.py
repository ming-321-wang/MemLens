# -*- coding: utf-8 -*-
"""一次取多张验证码，逐个去线+分割+大号渲染，挑最清晰的一张。"""
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, r"D:\MemLens")
WORK = Path(r"D:\MemLens\work\qsnctf")
WORK.mkdir(parents=True, exist_ok=True)

PY = r"D:\MemLens\.venv\Scripts\python.exe"
N = 5


def dist(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b))


def dominant_ink(px, W, H):
    """逐图自动取墨色：取频次最高的"非白非灰"颜色（不同验证码配色不同，不能硬编码）。"""
    from collections import Counter
    c = Counter()
    for y in range(0, H, 2):
        for x in range(0, W, 2):
            c[px[x, y]] += 1

    def colored(p):
        r, g, b = p
        if r > 225 and g > 225 and b > 225:
            return False          # 背景
        return (max(p) - min(p)) > 25 or max(p) < 170   # 有彩度 或 明显暗

    cands = [p for p, n in c.items() if colored(p) and n >= 30]
    if not cands:
        return (0, 0, 0)
    # 选出现最多的
    return max(cands, key=lambda p: c[p])


def clean_ink(px, W, H, text):
    ink = [[False] * W for _ in range(H)]
    for y in range(H):
        for x in range(W):
            if dist(px[x, y], text) < 14000:
                ink[y][x] = True
    # 去水平长段
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
    # 去垂直长段
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
    return ink


def segments(col, W):
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
    return [(a, b) for a, b in segs if b - a >= 5]


for i in range(1, N + 1):
    code_id = str(uuid.uuid4())
    png = WORK / f"cap{i}.png"
    subprocess.run([
        "powershell", "-NoProfile", "-Command",
        f"$s=$null; Invoke-WebRequest -Uri 'https://www.qsnctf.com/' -UseBasicParsing -TimeoutSec 30 -SessionVariable s | Out-Null; "
        f"Invoke-WebRequest -Uri 'https://www.qsnctf.com/api/captcha/{code_id}' -UseBasicParsing -TimeoutSec 30 "
        f"-WebSession $s -Headers @{{Referer='https://www.qsnctf.com/'}} -OutFile '{png}'"
    ], capture_output=True, timeout=120)
    if not png.exists():
        print(f"[{i}] fetch failed")
        continue
    (WORK / f"code{i}.txt").write_text(code_id)
    print(f"[{i}] codeId={code_id[:8]}… size={png.stat().st_size}")

from PIL import Image

for i in range(1, N + 1):
    png = WORK / f"cap{i}.png"
    if not png.exists():
        continue
    im = Image.open(png).convert("RGB")
    W, H = im.size
    px = im.load()
    text = dominant_ink(px, W, H)
    ink = clean_ink(px, W, H, text)
    col = [sum(1 for y in range(H) if ink[y][x]) for x in range(W)]
    segs = segments(col, W)
    npix = sum(sum(r) for r in ink)
    print(f"\n########## #{i}: {len(segs)} segs, ink={npix}, color={text} ##########")
    if len(segs) != 4:
        print(f"  (段数不是 4，合并/拆分如下:) {segs}")
    for k, (a, b) in enumerate(segs):
        cw, ch = b - a + 1, H
        rows = 20
        scale = rows / ch
        ow = max(4, int(cw * scale))
        print(f"  --- 段{k+1} x={a}-{b} w={cw} ---")
        for r in range(rows):
            line = ""
            for c in range(ow):
                hit = False
                for dy in range(max(1, H // rows + 1)):
                    for dx in range(max(1, cw // ow + 1)):
                        xx = min(W - 1, a + int(c / scale) + dx)
                        yy = min(H - 1, int(r / scale) + dy)
                        if ink[yy][xx]:
                            hit = True
                            break
                    if hit:
                        break
                line += "#" if hit else " "
            print("   " + line)
