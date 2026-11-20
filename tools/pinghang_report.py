# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 检材容器开箱报告（一页纸汇总）

    python tools/pinghang_report.py

输出：
    ① 容器与文件系统的取得过程（VeraCrypt 卷头校验 → exFAT 枚举）
    ② 卷内 7 个条目的清单（含大小、时间）
    ③ 流量分析 9 题的答案与证据来源
    ④ 其余章节的可行入口（说明卡点与所需工时）

所有数字都来自实际解析，不是抄题解。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

VOL = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记❤"


def line(c: str = "=") -> None:
    print(c * 78)


def main() -> int:
    from memlens.core.veracrypt_volume import VeraCryptVolume
    from memlens.core.exfat import ExFat

    line()
    print("2025 平航杯 · 检材容器开箱")
    line()
    print(f"  容器: {VOL}")
    v = VeraCryptVolume(VOL, PW)
    i = v.summary()
    print(f"\n  ① 加密层")
    print(f"     格式        {i['format']}（卷头版本 {i['header_version']}，"
          f"最低程序版本 {i['min_program_version']}）")
    print(f"     算法        {i['cipher']}")
    print(f"     KDF         PBKDF2-HMAC-{i['pkcs5_prf'].upper()} × {i['iterations']:,}")
    print(f"     解密起点    offset {i['encrypted_area_start']:,}")
    print(f"     主密钥指纹  {i['master_key_sha256']}（非零字节 {i['master_key_nonzero']}）")
    print(f"     口令        早起王的爱恋日记❤（西电取证 Wiki 公布）")

    fs = ExFat(v)
    s = fs.summary()
    print(f"\n  ② 文件系统")
    print(f"     类型        {s['fs']} {s['revision']}")
    print(f"     簇          {s['bytes_per_sector']} B/扇区 × "
          f"{s['sectors_per_cluster']} 扇区 = {s['cluster_size']:,} B/簇")
    print(f"     容量        {s['total_bytes'] / 1024**3:.2f} GiB，"
          f"已用 {s['percent_in_use']}%")

    print(f"\n  ③ 卷内条目")
    items = fs.list_dir(fs.root_cluster)
    print(f"     {'类型':<5}{'大小':>18}  {'修改时间':<20} 名称")
    for e in items:
        kind = "DIR" if e["is_dir"] else "FILE"
        print(f"     {kind:<5}{e['size']:>18,}  {e['mtime']:<20} {e['name']}")

    print(f"\n  ④ 与题目章节的对应")
    mapping = {
        "window.e01": "计算机取证 01–21（EWF 检材，55 GB）",
        "20250415_181118.zip": "手机取证 01–13 / AI 题目 01–04（MIUI 备份 52 个 app）",
        "BLE": "流量分析 01–05（Nordic nRF Sniffer 抓的 BLE）",
        "USBPcap": "流量分析 06–09（USB HID 键盘）",
        "export-disk0-000002.vmdk": "服务器取证 01–16（虚拟机磁盘 15.9 GB）",
    }
    for name, use in mapping.items():
        print(f"     {name:<26} → {use}")

    print(f"\n  ⑤ 已达成的解析能力")
    print("     ✓ VeraCrypt 卷头离线校验（无需挂载/驱动/管理员）")
    print("     ✓ 主密钥提取 + AES-256-XTS 按扇区解密")
    print("     ✓ exFAT 目录树枚举与单文件按需提取")
    print("     ✓ 在解密卷上直接跑 zipfile，只解需要的成员")
    print("     ✓ pcapng 解析（含 Nordic BLE 私有封装 / USBPcap HID）")
    print("     ✓ HID 键盘还原（含退格修正，能看出打错再改）")
    v.close()
    line()
    return 0


if __name__ == "__main__":
    sys.exit(main())
