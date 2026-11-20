"""memfrag 用 --force 强跑 vol3，看真实表现（定位"探测到但用不了"的断链）。"""
import subprocess
from pathlib import Path

ROOT = Path(r"D:\MemLens")
PY = ROOT / ".venv" / "Scripts" / "python.exe"

targets = [
    ROOT / "work/attachments/scan/1090_solarsec_202603/dumped_4053_[23d1000-253e000].bin",
    ROOT / "work/attachments/scan/1090_solarsec_202603/dumped_4053_[400000-4f4000].bin",
    ROOT / "samples/synthetic_raw.img",
]

for p in targets:
    if not p.exists():
        continue
    print("=" * 78)
    print(f"# {p.name} ({p.stat().st_size:,} B)  --force")
    print("=" * 78)
    for plugin in ("windows.pslist", "banners.Banners", "layerwriter.layers"):
        r = subprocess.run(
            [str(PY), "-X", "utf8", "-m", "memlens.cli", "analyze", str(p),
             "--engine", "vol3", "--plugins", plugin, "--no-cache", "--force",
             "--case-name", f"force-{p.stem[:20]}-{plugin.split('.')[-1]}"],
            capture_output=True, text=True, encoding="utf-8", timeout=1800,
            cwd=str(ROOT),
        )
        out = (r.stdout or "") + (r.stderr or "")
        # 打印实质性内容：状态行、错误摘要
        for line in out.splitlines():
            s = line.strip()
            if any(k in s for k in ("[1/5]", "[4/5]", "[5/5]", "✔", "✘",
                                    "unsupported", "Unable", "ERROR", "Error",
                                    "无法", "失败", "层", "layer", "行数")):
                print("   " + s[:170])
        print(f"   [exit={r.returncode}]")
    print()
