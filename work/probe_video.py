# -*- coding: utf-8 -*-
"""探测视频编码能力：ffmpeg CLI / OpenCV / imageio-ffmpeg。"""
import shutil
import subprocess
from pathlib import Path

print("=== ffmpeg CLI ===")
for name in ("ffmpeg", "ffmpeg.exe"):
    p = shutil.which(name)
    print(f"  {name}: {p}")
# 常见安装位置
for p in (r"C:\ffmpeg\bin\ffmpeg.exe", r"D:\ffmpeg\bin\ffmpeg.exe",
          r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
          r"D:\CTF工具\ffmpeg\bin\ffmpeg.exe"):
    print(f"  {p}: {'存在' if Path(p).exists() else '无'}")

print("\n=== Python 库 ===")
for mod in ("cv2", "imageio", "imageio_ffmpeg", "numpy", "PIL", "moviepy"):
    try:
        m = __import__(mod)
        v = getattr(m, "__version__", "?")
        print(f"  {mod:<16} OK   {v}")
        if mod == "imageio_ffmpeg":
            try:
                print(f"      exe: {m.get_ffmpeg_exe()}")
            except Exception as e:
                print(f"      get_ffmpeg_exe 失败: {e}")
    except Exception as e:
        print(f"  {mod:<16} MISS ({type(e).__name__})")

print("\n=== DSH 内部是否带 ffmpeg ===")
dsh = Path(r"C:\Users\WZH\AppData\Roaming\dsh-desktop")
for pat in ("**/ffmpeg*.exe", "**/ffmpeg"):
    for f in list(dsh.glob(pat))[:5]:
        print(f"  {f} ({f.stat().st_size/1048576:.1f} MiB)")
print("  (搜索完成)")
