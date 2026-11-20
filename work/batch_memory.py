"""内存域真实样本验证（修正 CLI 参数：用 --plugins 而非不存在的 --preset）。"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"D:\MemLens")
PY = ROOT / ".venv" / "Scripts" / "python.exe"

samples = []
scan = ROOT / "work" / "attachments" / "scan"
for ex in scan.iterdir():
    if not ex.is_dir():
        continue
    for p in ex.rglob("dumped_4053_*.bin"):
        samples.append((p, "真实 bash 进程内存段"))
for s in ("synthetic_raw.img",):
    p = ROOT / "samples" / s
    if p.exists():
        samples.append((p, "合成 Windows 镜像"))

# windows-quick 对应的插件清单
QUICK = "windows.pslist,windows.psscan,windows.netstat,windows.pstree"

for p, kind in samples:
    print("=" * 78)
    print(f"# {p.name}  ({p.stat().st_size:,} B)  [{kind}]")
    print("=" * 78)
    r = subprocess.run(
        [str(PY), "-X", "utf8", "-m", "memlens.cli", "analyze", str(p),
         "--engine", "vol3", "--plugins", QUICK, "--no-cache",
         "--case-name", f"memtest-{p.stem[:30]}"],
        capture_output=True, text=True, encoding="utf-8", timeout=1800,
        cwd=str(ROOT),
    )
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if any(k in line for k in ("[1/5]", "[2/5]", "[3/5]", "[4/5]", "[5/5]",
                                   "将执行", "案件 ID", "✔", "✘", "跳过",
                                   "错误", "Error", "error", "阶段", "unsupported",
                                   "不支持", "无法")):
            print("   " + line[:160])
    print(f"   [exit={r.returncode}]")
    print()

sys.path.insert(0, str(ROOT))
from memlens.storage.db import DataStore
store = DataStore(ROOT / "work" / "memlens.db")
print("=" * 78)
print("内存域结果汇总")
print("=" * 78)
for c in store.list_cases():
    if not c["name"].startswith("memtest-"):
        continue
    arts = store.list_artifacts(c["case_id"])
    ok = [a for a in arts if a["status"] == "ok"]
    recs = sum(a["row_count"] for a in arts)
    print(f"{c['name'][:38]:<40} 产物={len(arts):>2} ok={len(ok):>2} 记录={recs:>5}")
    for a in arts:
        if a["status"] != "ok":
            print(f"     {a['status']:<8} {a['plugin']:<28} {str(a['error'])[:80]}")
store.close()
