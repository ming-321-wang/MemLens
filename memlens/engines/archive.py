"""
MemLens · 压缩包内容清单分析（zip / apk / jar）

取证/应急里的压缩包本身就是证据：可疑样本常被塞进 zip 分发，APK 里内嵌 `.so`
（本次平台样本 ParlooChecker.apk 就内嵌了 4 个 libparloo.so，合计 1.5 MB）。

本模块做**不解压的内容清单**分析：
  1. 概要：条目数、总解压大小、压缩比、最大项
  2. 分类计数：dex / so / jar / 资源 / 文本 / 证书
  3. **内嵌可执行标记**（.exe .dll .sys .so .dex .elf）
  4. 可疑项：超大项（>10MB）、可疑扩展名、嵌套压缩包
  5. META-INF 签名相关文件（apk/jar 签名完整性线索）

设计：只读 zip 中央目录，不实际解压，因此对"压缩炸弹"与恶意嵌套免疫。
"""

from __future__ import annotations

import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

MAX_ENTRIES = 20000

EXEC_SUFFIX = (".exe", ".dll", ".sys", ".so", ".elf", ".dex", ".oat", ".art",
               ".apk", ".jar", ".com", ".scr")
SUSPICIOUS_SUFFIX = (".ps1", ".vbs", ".bat", ".cmd", ".hta", ".js", ".jse",
                     ".lnk", ".reg", ".scr", ".pif", ".chm", ".sh")
NESTED_SUFFIX = (".zip", ".rar", ".7z", ".tar", ".gz", ".jar", ".apk")


def analyze_archive(path: str) -> Iterator[dict[str, Any]]:
    """把 zip/apk/jar 的内容清单摊平成 records。"""
    p = Path(path)
    name = p.name
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        yield {"文件": name, "项": "压缩包", "结论": "ZIP 结构损坏（可能是伪扩展名或加密头）"}
        return
    except Exception as e:
        yield {"文件": name, "项": "压缩包", "结论": f"无法打开：{type(e).__name__}: {e}"}
        return

    try:
        infos = zf.infolist()[:MAX_ENTRIES]
    except Exception as e:
        yield {"文件": name, "项": "压缩包", "结论": f"读取中央目录失败：{e}"}
        return

    if not infos:
        yield {"文件": name, "项": "压缩包", "结论": "空压缩包"}
        return

    total_raw = 0
    total_cmp = 0
    big: list[tuple[str, int]] = []
    execs: list[tuple[str, int]] = []
    suspicious: list[str] = []
    nested: list[str] = []
    meta_inf: list[str] = []
    kinds = Counter()

    for zi in infos:
        fn = zi.filename
        if zi.is_dir():
            continue
        size = zi.file_size
        csize = zi.compress_size
        total_raw += size
        total_cmp += csize
        ext = Path(fn).suffix.lower()
        kinds[ext or "(无后缀)"] += 1
        if size >= 10 * 1024 * 1024:
            big.append((fn, size))
        if ext in EXEC_SUFFIX:
            execs.append((fn, size))
        if ext in SUSPICIOUS_SUFFIX:
            suspicious.append(fn)
        if ext in NESTED_SUFFIX:
            nested.append(fn)
        if fn.upper().startswith("META-INF/"):
            meta_inf.append(fn)

    yield {
        "文件": name, "项": "压缩包概要",
        "条目数": len([i for i in infos if not i.is_dir()]),
        "解压后总大小": total_raw,
        "压缩后总大小": total_cmp,
        "压缩比": f"{total_cmp / total_raw:.1%}" if total_raw else "-",
        "目录数": len([i for i in infos if i.is_dir()]),
    }

    yield {
        "文件": name, "项": "内容类型分布",
        "分布": ", ".join(f"{k}:{v}" for k, v in kinds.most_common(20)),
    }

    if execs:
        execs.sort(key=lambda x: -x[1])
        yield {
            "文件": name, "项": "⚠ 内嵌可执行",
            "数量": len(execs),
            "清单": ", ".join(f"{fn}({sz:,}B)" for fn, sz in execs[:25]),
        }
        for fn, sz in execs[:10]:
            yield {"文件": name, "项": "内嵌可执行明细", "路径": fn, "大小": sz}
    else:
        yield {"文件": name, "项": "内嵌可执行", "数量": 0, "结论": "未发现 .exe/.dll/.so/.dex 等可执行项"}

    if suspicious:
        yield {"文件": name, "项": "⚠ 可疑扩展名",
               "数量": len(suspicious), "清单": ", ".join(suspicious[:25])}
    if nested:
        yield {"文件": name, "项": "嵌套压缩包", "数量": len(nested),
               "清单": ", ".join(nested[:25])}
    if big:
        yield {"文件": name, "项": "⚠ 超大项(>=10MB)", "数量": len(big),
               "清单": ", ".join(f"{fn}({sz:,}B)" for fn, sz in big[:10])}

    if meta_inf:
        yield {"文件": name, "项": "META-INF（签名/清单）", "数量": len(meta_inf),
               "清单": ", ".join(meta_inf[:25])}

    # APK 专项
    dex = [i for i in infos if i.filename.lower().endswith(".dex")]
    libs = [i for i in infos if i.filename.startswith("lib/")]
    if dex or libs:
        arch = sorted({Path(i.filename).parent.name for i in libs
                       if Path(i.filename).parent.name})
        yield {
            "文件": name, "项": "APK 专项",
            "dex 数": len(dex),
            "native 库数": len(libs),
            "架构": ", ".join(arch),
            "manifest": "有 AndroidManifest.xml" if any(
                i.filename == "AndroidManifest.xml" for i in infos) else "无（可能被混淆）",
        }
