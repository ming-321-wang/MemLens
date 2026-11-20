# -*- coding: utf-8 -*-
"""用本机真实文件验证静态分析引擎（不建案件，直接验证解析能力）。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from memlens.engines.static import StaticEngine, profile_file, profile_to_records

engine = StaticEngine()
print("=" * 78)
print("引擎自检：", engine.available())
print("插件清单：")
for p in engine.list_plugins():
    print(f"  {p.name:<20} {p.display:<16} kind={p.kind.value}")
print("=" * 78)

SAMPLES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\drivers\ntfs.sys",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\mmc.exe",
    r"C:\Windows\SysWOW64\kernel32.dll",   # 32 位
    r"C:\Windows\System32\DriverStore\FileRepository\ntfs.inf_amd64_xxx\ntfs.sys",
]

import glob
g = glob.glob(r"C:\Windows\System32\DriverStore\FileRepository\ntfs*\ntfs.sys")
if g:
    SAMPLES.append(g[0])

plugin_by_name = {p.name: p for p in engine.list_plugins()}

for path in SAMPLES:
    if not Path(path).exists():
        print(f"\n[跳过] 不存在：{path}")
        continue

    print(f"\n{'#' * 78}\n# {path}\n{'#' * 78}")
    try:
        prof = profile_file(path)
    except Exception as exc:
        print(f"  ✘ 画像失败：{exc}")
        continue

    # 画像
    print(f"  类型={prof.file_type}  大小={prof.size:,}  熵={prof.entropy}  语言={prof.language or '-'}")
    print(f"  sha256={prof.sha256[:16]}…  md5={prof.md5}")
    if prof.notes:
        for n in prof.notes:
            print(f"  ⚠ {n}")
    if prof.pe:
        pe = prof.pe
        print(f"  PE: {pe.bits}bit {pe.machine} {pe.subsystem} DLL={pe.is_dll} driver={pe.is_driver} "
              f"linker={pe.linker_version} ts={pe.timestamp_iso}")
        print(f"      入口=0x{pe.entry_point:x} 基址=0x{pe.image_base:x} 签名={pe.digital_signature} "
              f"节={len(pe.sections)} 导入DLL={len(pe.imports)} 导出={len(pe.exports)} "
              f"TLS回调={len(pe.tls_callbacks)} 加壳={pe.is_packed_suspect}/{pe.packer_hint or '-'}")
        # 敏感导入
        sens = []
        for imp in pe.imports:
            for fn in imp["functions"]:
                for cat, apis in __import__("memlens.engines.static", fromlist=["SENSITIVE_APIS"]).SENSITIVE_APIS.items():
                    if fn in apis:
                        sens.append(f"{fn}({cat})")
        if sens:
            print(f"      敏感 API：{', '.join(sorted(set(sens))[:8])}")

    # 四个维度的记录数
    for name in ("static.profile", "static.pe", "static.strings", "static.packer"):
        try:
            recs = list(engine.analyze_file(path, plugin_by_name[name]))
            print(f"  [{name}] -> {len(recs)} 条记录")
        except Exception as exc:
            print(f"  [{name}] ✘ {exc}")

print("\n完成")
