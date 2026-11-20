# -*- coding: utf-8 -*-
"""严格对照：找出 TestDLL 真正区别于良性系统文件的结构特征。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.engines.static import profile_file

MAL = r"D:\MemLens\work\attachments\512_512_可疑文件\TestDLL.dll"
BENIGN = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\calc.exe",
    r"C:\Windows\System32\mmc.exe",
    r"C:\Windows\System32\cmd.exe",
]


def facts(path):
    p = profile_file(path)
    pe = p.pe
    if not pe:
        return None
    fns = {f for imp in pe.imports for f in imp["functions"]}
    return {
        "file": Path(path).name,
        "size": p.size,
        "bits": pe.bits,
        "dll": pe.is_dll,
        "secs": [s["name"] for s in pe.sections],
        "wx": [s["name"] for s in pe.sections if s["is_wx"]],
        "max_sec_size": max((s["rsize"] for s in pe.sections), default=0),
        "imports": len(fns),
        "dlls": sorted({imp["dll"].lower() for imp in pe.imports}),
        "exports": len(pe.exports),
        "tls": len(pe.tls_callbacks),
        "signed": pe.digital_signature,
        "packed": pe.is_packed_suspect,
        "entropy": p.entropy,
        "fns": fns,
        "text_ratio": (max((s["rsize"] for s in pe.sections if s["name"] in (".text",)), default=0) / p.size),
    }


rows = [facts(MAL)] + [facts(b) for b in BENIGN if Path(b).exists()]
rows = [r for r in rows if r]

print("=== 规模与标志 ===")
print(f"{'file':<14}{'size':>10}{'bit':>5}{'DLL':>5}{'imp':>5}{'exp':>5}{'TLS':>5}{'WX':>4}{'签名':>5}{'.text占比':>10}")
for r in rows:
    print(f"{r['file']:<14}{r['size']:>10,}{r['bits']:>5}{str(r['dll']):>5}{r['imports']:>5}"
          f"{r['exports']:>5}{r['tls']:>5}{len(r['wx']):>4}{str(r['signed']):>5}{r['text_ratio']:>10.2%}")

print("\n=== 节区名 ===")
for r in rows:
    print(f"  {r['file']:<14} {r['secs']}")
    if r["wx"]:
        print(f"  {'':<14} WX={r['wx']}")

print("\n=== 导入 DLL ===")
for r in rows:
    print(f"  {r['file']:<14} {r['dlls']}")

mal_fns = rows[0]["fns"]
print(f"\n=== TestDLL 独有 API（benign 全都没有的）===")
allbenign = set()
for r in rows[1:]:
    allbenign |= r["fns"]
uniq = sorted(mal_fns - allbenign)
print(f"共 {len(uniq)} 个:")
for i in range(0, len(uniq), 3):
    print("   " + "  ".join(x.ljust(32) for x in uniq[i:i + 3]))

print(f"\n=== TestDLL 与 benign 的共有 API 数 ===")
print(f"  共有: {len(mal_fns & allbenign)}")
print(f"  TestDLL 独有: {len(uniq)}")
print(f"  benign 有而 TestDLL 无: {len(allbenign - mal_fns)}")
