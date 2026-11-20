# -*- coding: utf-8 -*-
"""下载公开样本：Agent Tesla(含真实 IoC/strings) + DFRWS 磁盘镜像与 pcap。"""
import zipfile
from pathlib import Path

import requests

BASE = "https://raw.githubusercontent.com"
OUT = Path(r"D:\MemLens\work/attachments/web_samples")
OUT.mkdir(parents=True, exist_ok=True)

TARGETS = [
    # (url, 本地名, 说明)
    ("BashiruDamoah/MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3/main/Agent%20Tesla.zip",
     "agent_tesla.zip", "Agent Tesla 恶意样本"),
    ("BashiruDamoah/MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3/main/ioc/iocs.txt",
     "agent_tesla_iocs.txt", "Agent Tesla 真实 IoC（用于验证 MemLens 覆盖度）"),
    ("BashiruDamoah/MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3/main/string/memory_strings.txt",
     "agent_tesla_mem_strings.txt", "从内存提取的字符串（对照我的 strings 维度）"),
    ("BashiruDamoah/MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3/main/commands/volatility_commands.txt",
     "agent_tesla_volcmds.txt", "作者实际用的 vol3 命令集"),
    ("dfrws/dfrws2009-challenge/main/materials/nssal-thumb-fs.dd.bz2",
     "dfrws2009-thumb-fs.dd.bz2", "DFRWS 2009 磁盘镜像（4MB）"),
    ("dfrws/dfrws2009-challenge/main/materials/nssal-capture-1.pcap.bz2",
     "dfrws2009-capture-1.pcap.bz2", "DFRWS 2009 流量（9MB）"),
]

for path, name, desc in TARGETS:
    url = f"{BASE}/{path}"
    dest = OUT / name
    print(f"=== {desc}")
    print(f"    {url}")
    if dest.exists() and dest.stat().st_size > 0:
        print(f"    已存在 {dest.stat().st_size:,} B，跳过")
        continue
    try:
        r = requests.get(url, timeout=300, stream=True)
        if r.status_code != 200:
            print(f"    下载失败 HTTP {r.status_code}")
            continue
        with open(dest, "wb") as fp:
            for chunk in r.iter_content(1 << 20):
                fp.write(chunk)
        print(f"    已存 {dest}  ({dest.stat().st_size:,} B)")
        if dest.suffix == ".zip":
            ex = OUT / "agent_tesla_extracted"
            ex.mkdir(exist_ok=True)
            try:
                with zipfile.ZipFile(dest) as z:
                    for n in z.namelist():
                        print(f"       {z.getinfo(n).file_size:>10,}  {n}")
                    z.extractall(ex)
            except Exception as e:
                print(f"     解压失败: {e}")
    except Exception as e:
        print(f"    异常 {e}")
    print()

print("下载目录:", OUT)
