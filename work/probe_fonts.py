# -*- coding: utf-8 -*-
"""探测可用字体（等宽字体对"取证/代码"风格壁纸很关键）。"""
from pathlib import Path

from PIL import ImageFont

CANDS = [
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\consolab.ttf",
    r"C:\Windows\Fonts\Consola.ttf",
    r"C:\Windows\Fonts\cour.ttf",
    r"C:\Windows\Fonts\lucon.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\segui.ttf",
    r"C:\Windows\Fonts\msjh.ttc",
    r"C:\Windows\Fonts\simsun.ttc",
    r"C:\Python313\Lib\site-packages\matplotlib\mpl-data\fonts\ttf\DejaVuSansMono.ttf",
]
print("=== 字体探测 ===")
ok = []
for p in CANDS:
    f = Path(p)
    if f.exists():
        try:
            ft = ImageFont.truetype(str(f), 20)
            bbox = ft.getbbox("0A")
            print(f"  OK   {f}")
            print(f"        name={ft.getname()}  '0A' bbox={bbox}")
            ok.append(str(f))
        except Exception as e:
            print(f"  FAIL {f}  {e}")
    else:
        print(f"  MISS {f}")
print(f"\n可用 {len(ok)} 个")

print("\n=== 桌面目录 ===")
for d in (Path(r"C:\Users\WZH\Desktop"), Path(r"C:\Users\Public\Desktop"),
          Path(r"D:\DSH\工作区")):
    print(f"  {d}  exists={d.exists()}")
