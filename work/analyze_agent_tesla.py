# -*- coding: utf-8 -*-
"""尝试用常见样本包密码解开 Agent Tesla.zip，并用 MemLens 分析。"""
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, r"D:\MemLens")

ZP = Path(r"D:\MemLens/work/attachments/web_samples/agent_tesla/Agent Tesla.zip")
EXDIR = Path(r"D:\MemLens/work/attachments/web_samples/agent_tesla")
PASSWORDS = ["infected", "virus", "malware", "password", "1234", "",
             "agenttesla", "sample", "malwarebytes"]

extracted = None
if not ZP.exists():
    print("zip 不存在")
    raise SystemExit(1)

print(f"zip: {ZP} ({ZP.stat().st_size:,} B)")
try:
    zf = zipfile.ZipFile(ZP)
    names = zf.namelist()
    print(f"  条目 {len(names)}: {names}")
    for n in names:
        zi = zf.getinfo(n)
        print(f"    flag_bits=0x{zi.flag_bits:04x} compress_type={zi.compress_type} "
              f"size={zi.file_size:,} 加密={'是' if zi.flag_bits & 0x1 else '否'}")
except Exception as e:
    print("读取失败:", e)
    raise SystemExit(1)

for pw in PASSWORDS:
    for n in names:
        try:
            data = zf.read(n)
        except RuntimeError:
            continue
        except Exception:
            continue
        dest = EXDIR / Path(n).name
        dest.write_bytes(data)
        print(f"\n*** 密码 {pw!r} 解开 {n} → {dest} ({len(data):,} B) ***")
        extracted = dest
        break
    if extracted:
        break

if not extracted:
    print("\n常见密码都不对。zip 用了 AES/传统加密。")
    print("→ 这个 zip 本身仍是有价值的证据：MemLens 应识别出「加密压缩包」")
    raise SystemExit(0)

# ---- 用 MemLens 分析这个真实恶意样本 ----
from memlens.engines.static import StaticEngine, profile_file
from memlens.engines.pe import parse_pe

print("\n" + "=" * 74)
print("MemLens 分析 Agent Tesla 样本")
print("=" * 74)
prof = profile_file(str(extracted))
print(f"类型: {prof.file_type}  大小: {prof.size:,}  熵: {prof.entropy}")
print(f"MD5/SHA256: {prof.md5} / {prof.sha256}")
if prof.pe:
    pe = prof.pe
    print(f"PE: {pe.bits}bit {pe.machine}  DLL={pe.is_dll}  签名={pe.digital_signature}")
    print(f"节区: {[s['name'] for s in pe.sections]}")
    print(f"加壳嫌疑: {pe.is_packed_suspect}  标记: {pe.packer_hint}")
    print(f"导入 {len(pe.imports)} 个 DLL:")
    for imp in pe.imports:
        print(f"   {imp['dll']:<20} {imp['count']} 函数: "
              + ", ".join(imp['functions'][:14]))
    if pe.tls_callbacks:
        print(f"TLS 回调: {pe.tls_callbacks}")
print(f"\n画像提醒: {prof.notes}")
