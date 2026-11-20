# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 加固 APK 深挖（fix2_sign.apk）

## 这个样本特殊性

它是**梆梆加固（libSecShell）**的壳，且加固把 AndroidManifest.xml 也处理过，
标准 `RES_XML_TYPE(0x0003)` 解析拿不到字符串池。所以换个思路：

  · 应用名在 **resources.arsc** 的字符串池里（壳一般不加密资源表）
  · 回连 IP/端口虽然常在解密后的 dex 里，但**壳的配置字符串**、
    assets 里的配置文件、以及 so 里的明文常量常常漏出来
  · 安装方式（"怎么被装上的"）答案在**手机侧数据**里，
    不在 APK 里 —— 需要看浏览器下载记录 / 短信 / 微信收到的链接

## 本脚本做的事

1. 扫所有成员的可打印 ASCII 串（含 so / arsc / assets），按类别归类
2. 从 resources.arsc 解析字符串池，找应用名（label）
3. 从 so / assets / 任意成员里正则捞 IPv4、域名、端口
4. 列出 so 与 assets 清单（加固壳的运行时特征）
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
import zipfile
from pathlib import Path

P = Path(r"D:\MemLens\work\pinghang")
APK = P / "fix2_sign.apk"


def arsc_strings(data: bytes) -> list[str]:
    """解析 resources.arsc 里的全局字符串池。"""
    out: list[str] = []
    if len(data) < 12:
        return out
    typ, hsize, size = struct.unpack_from("<HHI", data, 0)
    if typ != 0x0002:                    # RES_TABLE_TYPE
        return out
    pos = hsize
    while pos + 8 <= len(data):
        ctype, chs, csz = struct.unpack_from("<HHI", data, pos)
        if csz < 8 or pos + csz > len(data):
            break
        if ctype == 0x0001:              # 全局字符串池
            body = data[pos + chs:pos + csz]
            if len(body) >= 28:
                scount, style_count, flags, sstart, _ = struct.unpack_from(
                    "<IIIII", body, 0)
                utf8 = bool(flags & 0x100)
                offs = struct.unpack_from("<%dI" % scount, body, 28) if scount else ()
                base = 28 + 4 * scount + 4 * style_count
                for off in offs:
                    p2 = base + off
                    if p2 >= len(body):
                        continue
                    try:
                        if utf8:
                            n = body[p2]
                            p2 += 2 if (n & 0x80) else 1
                            n = body[p2]
                            if n & 0x80:
                                n = ((n & 0x7F) << 8) | body[p2 + 1]
                                p2 += 1
                            p2 += 1
                            out.append(body[p2:p2 + n].decode("utf-8", "replace"))
                        else:
                            n = struct.unpack_from("<H", body, p2)[0]
                            p2 += 2
                            if n & 0x8000:
                                n2 = struct.unpack_from("<H", body, p2)[0]
                                n = ((n & 0x7FFF) << 16) | n2
                                p2 += 2
                            out.append(body[p2:p2 + n * 2].decode("utf-16-le", "replace"))
                    except Exception:
                        continue
            break
        pos += csz
    return out


def strings_in(data: bytes, minlen: int = 4) -> list[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group(0).decode("ascii", "replace"))
    # UTF-16LE 也扫一遍（so / 配置文件里常见）
    try:
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
            out.append(m.group(0).decode("utf-16-le", "replace"))
    except Exception:
        pass
    return out


IPV4 = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                    r"(?:com|cn|net|org|io|xyz|top|cc|me|info|ru|tk|ml|ga))\b", re.I)


def main() -> int:
    raw = APK.read_bytes()
    print("=" * 76)
    print("fix2_sign.apk 深挖（梆梆加固壳）")
    print("=" * 76)
    print(f"  大小 {len(raw):,} 字节   MD5 {hashlib.md5(raw).hexdigest()}")
    print(f"  SHA256 {hashlib.sha256(raw).hexdigest()}")

    with zipfile.ZipFile(APK) as z:
        names = z.namelist()
        members = {n: (z.read(n) if not n.endswith("/") else b"") for n in names}

    print(f"\n  成员 {len(names)} 个")
    so = [n for n in names if n.endswith(".so")]
    dex = [n for n in names if n.endswith(".dex")]
    assets = [n for n in names if n.startswith("assets/")]
    print(f"    .so   {len(so)} 个: {so[:8]}")
    print(f"    .dex  {len(dex)} 个: {dex}")
    print(f"    assets {len(assets)} 个: {assets[:10]}")

    # ── 应用名（resources.arsc）
    print("\n" + "-" * 76)
    print("应用名候选（resources.arsc 字符串池）")
    print("-" * 76)
    arsc = members.get("resources.arsc", b"")
    ast = arsc_strings(arsc)
    print(f"  arsc 字符串 {len(ast)} 条")
    CN = re.compile(r"^[\u4e00-\u9fa5][\u4e00-\u9fa5A-Za-z0-9 _\-]{0,18}$")
    cand = [s for s in ast if CN.match(s)]
    for s in cand[:30]:
        print(f"    {s!r}")
    # 同时看 manifest 里声明的 label 名
    print("\n  strings.xml 里的 app_name：")
    for n, d in members.items():
        if n == "resources.arsc":
            continue
        if "app_name" in " ".join(ast):
            break
    if "app_name" in ast:
        i = ast.index("app_name")
        print(f"    找到 app_name 键，邻近值：{ast[max(0,i-3):i+3]}")

    # ── IP / 域名 / 端口
    print("\n" + "-" * 76)
    print("网络指标（扫全部成员，含 so / assets）")
    print("-" * 76)
    ips: dict[str, set[str]] = {}
    doms: dict[str, set[str]] = {}
    for n, d in members.items():
        if not d:
            continue
        for s in strings_in(d):
            for m in IPV4.finditer(s):
                ip = m.group(1)
                if ip.startswith(("0.", "127.", "255.", "1.1.1.1", "8.8.8.8")):
                    continue
                ips.setdefault(ip, set()).add(n)
            for m in DOMAIN.finditer(s):
                dom = m.group(1).lower()
                if any(k in dom for k in ("android.com", "googleapis", "schemas.android",
                                          "apache.org", "w3.org", "json.org", "slf4j",
                                          "kotlin", "jetbrains", "bouncycastle")):
                    continue
                doms.setdefault(dom, set()).add(n)
    print(f"  IPv4（{len(ips)}）：")
    for ip, srcs in sorted(ips.items()):
        print(f"    {ip:<18} ← {sorted(srcs)[:3]}")
    print(f"\n  域名（{len(doms)}）：")
    for d, srcs in sorted(doms.items()):
        print(f"    {d:<34} ← {sorted(srcs)[:2]}")

    # ── 壳配置 strings
    print("\n" + "-" * 76)
    print("壳/配置相关明文（so 与 assets）")
    print("-" * 76)
    KEY = ("SecShell", "jiagu", "appkey", "app_key", "appid", "channel",
           "http://", "https://", "socket", "camera", "upload", "cmd",
           "shell", "boot", "persist")
    hits = set()
    for n in so + assets:
        d = members.get(n, b"")
        for s in strings_in(d, 6):
            low = s.lower()
            for k in KEY:
                if k.lower() in low and len(s) < 140:
                    hits.add((n, s))
                    break
    for n, s in sorted(hits)[:40]:
        print(f"    [{n}] {s}")

    # ── 持久化：查 manifest 是否有 BOOT / 无障碍 / 设备管理器
    print("\n" + "-" * 76)
    print("持久化迹象")
    print("-" * 76)
    PER = ("BOOT_COMPLETED", "RECEIVE_BOOT", "BIND_ACCESSIBILITY_SERVICE",
           "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW", "FOREGROUND_SERVICE",
           "WAKE_LOCK", "REQUEST_IGNORE_BATTERY")
    seen = set()
    for n, d in members.items():
        if not d:
            continue
        for k in PER:
            if k.encode() in d:
                seen.add(k)
    if seen:
        for k in sorted(seen):
            print(f"    ★ {k}")
    else:
        print("    未在明文成员中发现（壳加密，需脱壳后看 manifest）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
