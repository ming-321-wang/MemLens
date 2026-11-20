"""
MemLens · 进程内存段扫描（memfrag 域）

背景：真实赛题里大量证据是**进程内存段**（如 ptrace dumper 产出的 dumped_4053_*.bin），
它们在 vol3 里跑不出进程表（缺内核数据结构）。早期版本把它们探测成 `memfrag` 后
就**彻底走不下去了** —— "探测到了但用不了"。本模块补上这条真实可用的路径：

  1. **内存段元信息**：从文件名解析地址区间（`dumped_PID_[start-end].bin` 形态）
  2. **逐 4KiB 页统计**：零页 / 高熵页 / 可打印密度分布（这是"哪一页藏着东西"的直接判据）
  3. **IoC 扫描**：在段内搜 flag 模式 / 曲线参数 / 密钥特征 / 路径 / URL / IP
  4. **结构识别**：段内偏移处是否存在 PE / ELF / 证书 / SQLite 等映射（内存里的库映像）
  5. **Top 可读字符串**：按长度与"信息量"排序（长的可打印串通常是配置/密钥/URL）

这是"没有内核结构时还能做什么"的答案：**把段当数据取证，而不是当镜像跑 vol3**。
"""

from __future__ import annotations

import hashlib
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

PAGE = 4096

# flag / 凭据模式（CTF + 应急通用，按优先级排列）
IOC_PATTERNS: tuple[tuple[str, bytes], ...] = (
    ("flag{", b"flag{"), ("FLAG{", b"FLAG{"), ("ctf{", b"ctf{"),
    ("solarsec{", b"solarsec{"), ("qsnctf{", b"qsnctf{"),
    ("palu{", b"palu{"), ("666c6167", b"666c6167"),
    ("-----BEGIN", b"-----BEGIN"), ("PRIVATE KEY", b"PRIVATE KEY"),
    ("[Shell]", b"[Shell]"), ("WebShell", b"WebShell"), ("eval(", b"eval("),
    ("/bin/sh", b"/bin/sh"), ("/bin/bash", b"/bin/bash"),
    ("LD_PRELOAD", b"LD_PRELOAD"), ("password=", b"password="),
    ("passwd=", b"passwd="), ("Authorization:", b"Authorization:"),
    ("Set-Cookie", b"Set-Cookie"), ("Cookie:", b"Cookie:"),
)

# 内存里常见的库映像/结构魔数（用于"这段内存里映射了什么"）
MEM_STRUCTS: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF 库映像（libc/ld 等）"),
    (b"MZ", "PE 映像"),
    (b"\xfd7zXZ\x00", "xz 数据块"),
    (b"\x1f\x8b\x08", "gzip 数据块"),
    (b"\x89PNG", "PNG 图像"),
    (b"\xff\xd8\xff", "JPEG 图像"),
    (b"%PDF-", "PDF 数据"),
    (b"SQLite format 3\x00", "SQLite 页"),
    (b"-----BEGIN CERTIFICATE-----", "X.509 证书"),
    (b"-----BEGIN ", "PEM 块"),
)

_RANGE_RE = re.compile(r"\[([0-9a-fA-F]+)-([0-9a-fA-F]+)\]")


def parse_range(name: str) -> tuple[int, int] | None:
    """从 `dumped_4053_[23d1000-253e000].bin` 形态解析虚拟地址区间。"""
    m = _RANGE_RE.search(name)
    if not m:
        return None
    try:
        return int(m.group(1), 16), int(m.group(2), 16)
    except ValueError:
        return None


def _page_profile(blob: bytes) -> dict[str, Any]:
    """逐页画像：零页 / 高熵页 / 可打印密度。"""
    pages = len(blob) // PAGE
    zero, hot, dense = 0, 0, 0
    ent_vals: list[float] = []
    for i in range(pages):
        pg = blob[i * PAGE:(i + 1) * PAGE]
        if not pg.strip(b"\x00"):
            zero += 1
            continue
        c = Counter(pg)
        ent = 0.0
        for v in c.values():
            p = v / PAGE
            ent -= p * (p and _log2(p))
        ent_vals.append(ent)
        if ent > 7.0:
            hot += 1
        pr = sum(1 for b in pg if 32 <= b < 127)
        if pr / PAGE > 0.5:
            dense += 1
    return {
        "总页数": pages,
        "零页": zero,
        "高熵页(>7.0)": hot,
        "高可打印密度页(>50%)": dense,
        "平均熵": round(sum(ent_vals) / len(ent_vals), 3) if ent_vals else 0.0,
    }


def _log2(x: float) -> float:
    import math
    return math.log2(x)


def _top_strings(blob: bytes, limit: int = 25, minlen: int = 10) -> list[tuple[int, str]]:
    """
    提取长可打印串（含段内偏移），按"信息量"排序。

    去重策略（真实样本踩到）：环境变量串（LS_COLORS/dircolors）会在同一进程里
    被复制到多个偏移，若不去重，Top 20 会被同一串刷屏，真正有价值的内容被挤掉。
    因此按**内容前 40 字符**去重，只保留首次出现。
    """
    out: list[tuple[int, str]] = []
    cur = bytearray()
    start = 0
    seen: set[str] = set()
    i, n = 0, len(blob)
    while i < n:
        b = blob[i]
        if 32 <= b < 127 or b == 9:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                s = cur.decode("latin1", "replace")
                key = s[:40]
                if key not in seen:
                    seen.add(key)
                    out.append((start, s))
            cur = bytearray()
        i += 1
    if len(cur) >= minlen:
        s = cur.decode("latin1", "replace")
        if s[:40] not in seen:
            out.append((start, s))

    # 信息量加权：含 URL/凭据/路径特征的前置，其余按长度
    def score(item: tuple[int, str]) -> tuple[int, int]:
        s = item[1]
        bonus = 0
        for k in ("http", "://", "pass", "key", "secret", "token", "flag",
                  "USER", "HOME", "PATH", "PWD", "SSH", "cookie", "auth"):
            if k in s or k in s.lower():
                bonus += 1
        return (bonus, len(s))

    out.sort(key=score, reverse=True)
    return out[:limit]


def analyze_memfrag(path: str) -> Iterator[dict[str, Any]]:
    """把进程内存段分析结果摊平成 records。"""
    p = Path(path)
    name = p.name
    size = p.stat().st_size
    with open(path, "rb") as fp:
        blob = fp.read()

    # 1. 段元信息
    rng = parse_range(name)
    meta = {
        "文件": name, "项": "内存段元信息", "大小": size,
        "SHA-256": hashlib.sha256(blob).hexdigest(),
        "页数(4KiB)": size // PAGE,
    }
    if rng:
        meta["虚拟地址区间"] = f"0x{rng[0]:x}-0x{rng[1]:x}"
        meta["区间大小"] = f"0x{rng[1] - rng[0]:x}"
        meta["文件名区间与实际大小一致"] = (rng[1] - rng[0]) == size
    yield meta

    # 2. 页画像
    prof = _page_profile(blob)
    yield {"文件": name, "项": "页画像", **prof}

    # 3. 结构魔数（内存里映射了什么）
    structs: dict[str, list[int]] = {}
    for magic, desc in MEM_STRUCTS:
        offsets = []
        pos = 0
        while True:
            k = blob.find(magic, pos)
            if k < 0:
                break
            offsets.append(k)
            pos = k + 1
            if len(offsets) >= 20:
                break
        if offsets:
            structs[desc] = offsets
    if structs:
        for desc, offs in structs.items():
            yield {
                "文件": name, "项": "段内映射结构", "结构": desc,
                "出现次数": len(offsets),
                "偏移": ", ".join(f"0x{o:x}" for o in offs[:12]),
            }
    else:
        yield {"文件": name, "项": "段内映射结构", "结论": "未识别到常见库映像/数据块魔数"}

    # 4. IoC 扫描
    hits = []
    for label, pat in IOC_PATTERNS:
        pos = 0
        cnt = 0
        first = None
        while cnt < 5:
            k = blob.find(pat, pos)
            if k < 0:
                break
            if first is None:
                first = k
            cnt += 1
            pos = k + 1
        if cnt:
            hits.append((label, pat, cnt, first))
    if hits:
        for label, pat, cnt, off in hits:
            ctx = ""
            if off is not None:
                ctx = blob[off:off + 160].split(b"\x00")[0][:120].decode("latin1", "replace")
            yield {
                "文件": name, "项": "IoC 命中", "模式": label,
                "次数": cnt, "首次偏移": f"0x{off:x}" if off is not None else "",
                "上下文": ctx,
            }
    else:
        yield {"文件": name, "项": "IoC 命中", "结论": "未命中已知 flag/凭据/命令模式"}

    # 5. Top 可读字符串
    tops = _top_strings(blob, limit=20)
    if tops:
        yield {"文件": name, "项": "Top 可读字符串", "数量": len(tops),
               "明细": " || ".join(f"0x{o:x}:{s[:60]}" for o, s in tops[:10])}
        for o, s in tops[:8]:
            yield {"文件": name, "项": "长字符串明细", "偏移": f"0x{o:x}",
                   "长度": len(s), "内容": s[:400]}
