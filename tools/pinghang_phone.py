# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 手机取证 01–13（基于已提取的备份材料）

材料来源全部是**从 VeraCrypt 容器里实际取出的文件**：
    work/pinghang/descript.xml     MIUI 备份描述
    work/pinghang/Puzzle_Game.apk  拼图游戏（Flag1 / 大学）
    work/pinghang/fix2_sign.apk    可疑木马（安装方式 / 加固 / IP / 摄像头）
    work/pinghang/qidm             83 字节的小文件

技术要点：
  · APK 里的 AndroidManifest.xml 是 **二进制 AXML**，不能当文本读。
    它开头的字符串池（string pool）里，所有字符串都是明文——只要把池子抽出来，
    package 名、权限、receiver/service 名就都到手了，不必完整还原 XML 树。
  · 加固/混淆的判断靠特征串（libjiagu / libDexHelper / libmobisec …）。
  · IP:端口 直接从 dex 的字符串池里正则捞。
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import sys
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

P = Path(r"D:\MemLens\work\pinghang")
CST = timezone(timedelta(hours=8))


# ---------------------------------------------------------------- AXML
def axml_strings(data: bytes) -> list[str]:
    """从二进制 AXML 的字符串池里抽出所有字符串（UTF-8 与 UTF-16 两种编码都支持）。"""
    if len(data) < 8:
        return []
    try:
        typ, hsize, size = struct.unpack_from("<HHI", data, 0)
    except struct.error:
        return []
    if typ != 0x0003:                       # RES_XML_TYPE
        return []
    # 跳过文件头，找 RES_STRING_POOL_TYPE(0x0001)
    pos = hsize
    out: list[str] = []
    while pos + 8 <= len(data):
        ctype, chs, csz = struct.unpack_from("<HHI", data, pos)
        if csz == 0 or pos + csz > len(data):
            break
        if ctype == 0x0001:
            body = data[pos + chs:pos + csz]
            if len(body) < 28:
                break
            scount, style_count, flags, sstart, _stystart = \
                struct.unpack_from("<IIIII", body, 0)
            utf8 = bool(flags & 0x100)
            offs = struct.unpack_from("<%dI" % scount, body, 28) if scount else ()
            base = 28 + 4 * scount + 4 * style_count
            for off in offs:
                p2 = base + off
                if p2 >= len(body):
                    continue
                try:
                    if utf8:
                        # UTF-16 长度 + UTF-8 长度（各 1~2 字节，高位为 1 表示双字节）
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


def dex_strings(data: bytes) -> list[str]:
    """抽 DEX 的字符串池（header 里 string_ids 指向 uleb128 长度 + MUTF-8）。"""
    if len(data) < 0x70 or data[:3] != b"dex":
        return []
    try:
        n_str = struct.unpack_from("<I", data, 0x38)[0]
        off_str = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return []
    if n_str > 200000 or off_str >= len(data):
        return []
    out: list[str] = []
    for i in range(min(n_str, 200000)):
        try:
            soff = struct.unpack_from("<I", data, off_str + i * 4)[0]
        except struct.error:
            break
        if soff >= len(data):
            continue
        p = soff
        # uleb128 长度
        ln = 0
        shift = 0
        while p < len(data):
            b = data[p]
            p += 1
            ln |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        raw = data[p:p + ln]
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        try:
            out.append(raw.decode("utf-8", "replace"))
        except Exception:
            continue
    return out


# ---------------------------------------------------------------- 工具
def all_strings(files: dict[str, bytes]) -> list[str]:
    """汇总一个 APK/materials 里所有可读字符串（AXML 池 + dex 池 + 原文）。"""
    out: list[str] = []
    for name, data in files.items():
        if name.endswith(".xml"):
            out.extend(axml_strings(data))
        elif name.endswith(".dex"):
            out.extend(dex_strings(data))
        else:
            # 其它文件直接扫可打印 ASCII 串
            out.extend(re.findall(rb"[\x20-\x7e]{6,}", data))
            out = [s.decode("ascii", "replace") if isinstance(s, bytes) else s
                   for s in out]
    return out


def read_apk(path: Path) -> dict[str, bytes]:
    out = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            try:
                out[n] = z.read(n)
            except Exception:
                pass
    return out


# ---------------------------------------------------------------- 题目
def q01() -> None:
    print("=" * 76)
    print("01 该检材的备份提取时间")
    print("=" * 76)
    x = (P / "descript.xml").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"<date>(\d+)</date>", x)
    dev = re.search(r"<device>([^<]+)</device>", x)
    ver = re.search(r"<miuiVersion>([^<]+)</miuiVersion>", x)
    size = re.search(r"<size>(\d+)</size>", x)
    if m:
        ms = int(m.group(1))
        dt_utc = datetime.fromtimestamp(ms / 1000, timezone.utc)
        dt_cst = dt_utc.astimezone(CST)
        print(f"  <date> = {ms}  （毫秒时间戳）")
        print(f"  UTC    = {dt_utc:%Y-%m-%d %H:%M:%S}")
        print(f"  UTC+8  = {dt_cst:%Y-%m-%d %H:%M:%S}   ← 北京时间")
    print(f"  机型 device = {dev.group(1) if dev else '?'}")
    print(f"  MIUI 版本  = {ver.group(1) if ver else '?'}")
    if size:
        print(f"  备份总大小 = {int(size.group(1)) / 1024**3:.2f} GiB")
    # 统计 app 数量
    pkgs = re.findall(r"<packageName>([^<]+)</packageName>", x)
    print(f"  备份应用条目 = {len(pkgs)} 个")


def q02_03() -> None:
    print("\n" + "=" * 76)
    print("02–03 Puzzle_Game：Flag1 / 最终拼成的大学")
    print("=" * 76)
    apk = P / "Puzzle_Game.apk"
    files = read_apk(apk)
    print(f"  APK 成员 {len(files)} 个，总 {sum(len(v) for v in files.values()):,} 字节")
    print(f"  MD5 = {hashlib.md5(apk.read_bytes()).hexdigest()}")

    # Flag1：直接在字符串池 / 资源里找 flag{...} 之类
    pat = re.compile(r"(flag|ctf|FLAG|CTF)[\{_\-]?[A-Za-z0-9_\-]{2,}\}?", re.I)
    hits = set()
    for name, data in files.items():
        for s in axml_strings(data) if name.endswith(".xml") else []:
            for mm in pat.finditer(s):
                hits.add(mm.group(0))
        for mm in pat.finditer(data.decode("latin-1", "ignore")):
            t = mm.group(0)
            if len(t) > 6:
                hits.add(t)
    print(f"\n  含 flag 字样的字符串 {len(hits)} 个：")
    for h in sorted(hits)[:25]:
        print(f"    {h[:100]}")

    # 图片资源里的大学线索：找文件名
    imgs = [n for n in files if re.search(r"\.(png|jpg|jpeg|webp)$", n, re.I)]
    print(f"\n  图片资源 {len(imgs)} 个，名字含校名关键词的：")
    UNI = ("univ", "school", "college", "大学", "xidian", "xdu", "tsinghua",
           "peking", "zhejiang", "fudan", "hust", "bupt")
    for n in imgs:
        if any(k in n.lower() for k in UNI):
            print(f"    {n}")

    # 拼接逻辑：找拼图相关的类名/资源
    print(f"\n  dex 里含 puzzle/tile/piece 的字符串：")
    seen = set()
    for name, data in files.items():
        if not name.endswith(".dex"):
            continue
        for s in dex_strings(data):
            if re.search(r"(puzzle|tile|piece|jigsaw|split|qipan)", s, re.I):
                if s not in seen:
                    seen.add(s)
                    if len(seen) <= 20:
                        print(f"    {s[:110]}")


def q04_11() -> None:
    print("\n" + "=" * 76)
    print("04–11 fix2_sign.apk：安装方式 / MD5 / 名称 / 加固 / IP / 摄像头 / 持久化")
    print("=" * 76)
    apk = P / "fix2_sign.apk"
    raw = apk.read_bytes()
    files = read_apk(apk)
    print(f"  大小 {len(raw):,} 字节   成员 {len(files)} 个")
    print(f"  MD5 = {hashlib.md5(raw).hexdigest()}")

    strs = all_strings(files)
    allstr = "\n".join(strs)

    # 包名 / 应用名
    mani = files.get("AndroidManifest.xml", b"")
    ms = axml_strings(mani)
    print(f"\n  Manifest 字符串池 {len(ms)} 条，关键项：")
    for s in ms:
        if re.match(r"^com\.[a-z0-9_.]+$", s) and s.count(".") >= 2:
            print(f"    包名候选: {s}")
    # label 应用名（中文或英文短串）
    for s in ms:
        if 1 < len(s) < 24 and not s.startswith(("android.", "com.")) \
                and re.match(r"^[\u4e00-\u9fa5A-Za-z0-9 _\-]+$", s) \
                and s.lower() not in ("android", "true", "false", "utf-8"):
            if re.search(r"[\u4e00-\u9fa5]", s) or s[0].isupper():
                print(f"    可能的应用名: {s!r}")

    print(f"\n  权限（Manifest 池里的 android.permission.*）：")
    for s in ms:
        if s.startswith("android.permission.") or s.startswith("android.hardware."):
            print(f"    {s}")

    print(f"\n  组件（receiver / service / boot 相关）：")
    for s in ms:
        if re.search(r"(BOOT_COMPLETED|receiver|service|Receiver|Service|"
                     r"ACCESSIBILITY|DEVICE_ADMIN|JobService|Alarm)", s):
            print(f"    {s}")

    # 加固特征
    print(f"\n  加固特征：")
    GUARD = {
        "libjiagu": "360 加固", "libjiagu_art": "360 加固",
        "libDexHelper": "梆梆加固", "libSecShell": "梆梆加固",
        "libmobisec": "阿里聚安全", "libsgmain": "阿里聚安全",
        "libshella": "腾讯乐固", "libshellx": "腾讯乐固",
        "libtup": "腾讯乐固", "libnesec": "网易易盾",
        "libexec.so": "爱加密", "ijiami": "爱加密",
        "libbaiduprotect": "百度加固", "libnqshield": "网秦",
        "libkwscmm": "几维安全", "kiwisec": "几维安全",
        "libapktoolplus": "APKProtect", "libchaosvmp": "娜迦加固",
    }
    found_guard = set()
    for name, data in files.items():
        low = name.lower()
        for k, v in GUARD.items():
            if k.lower() in low:
                found_guard.add((v, name))
        try:
            txt = data.decode("latin-1", "ignore").lower()
            for k, v in GUARD.items():
                if k.lower() in txt:
                    found_guard.add((v, f"{name}:内容"))
        except Exception:
            pass
    if found_guard:
        for v, src in sorted(found_guard):
            print(f"    ★ {v}   （{src}）")
    else:
        print("    未命中常见加固特征")

    # IP:端口
    print(f"\n  IP:端口：")
    ips = set()
    for s in strs:
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b", s):
            ip = m.group(1)
            if ip.startswith(("0.", "127.", "255.")) or ip == "1.1.1.1":
                continue
            octs = [int(x) for x in ip.split(".")]
            if any(o > 255 for o in octs):
                continue
            ips.add((ip, m.group(2) or ""))
    for ip, port in sorted(ips):
        print(f"    {ip}{':' + port if port else ''}")

    # URL
    print(f"\n  URL / 域名：")
    urls = set()
    for s in strs:
        for m in re.finditer(r"https?://[^\s\"'<>]{4,120}", s):
            urls.add(m.group(0))
    for u in sorted(urls)[:20]:
        print(f"    {u}")

    # 摄像头 / 持久化 API
    print(f"\n  摄像头与持久化相关 API：")
    keys = ("Camera", "camera", "setPreviewCallback", "takePicture",
            "MediaRecorder", "AudioRecord", "BOOT_COMPLETED", "WakeLock",
            "AlarmManager", "JobScheduler", "AccessibilityService",
            "DevicePolicyManager", "ForegroundService", "START_STICKY",
            "uploadFile", "HttpURLConnection", "OkHttp", "socket")
    hitk = set()
    for s in strs:
        for k in keys:
            if k in s:
                hitk.add((k, s[:100]))
    for k, s in sorted(hitk)[:30]:
        print(f"    [{k}] {s}")

    # 回连类名（reverseshell2 是 MIUI 备份里点名的）
    print(f"\n  可疑类名（shell / reverse / rat / payload）：")
    for s in sorted(set(strs)):
        if re.search(r"(reverseshell|shell|payload|rat|backdoor|beacon)", s, re.I) \
                and s.startswith(("L", "com.")) and len(s) < 120:
            print(f"    {s}")
            if len(s) > 200:
                break


def q12_13() -> None:
    print("\n" + "=" * 76)
    print("12–13 身份证归属地 / IMEI")
    print("=" * 76)
    print("  ⚠ 这两题的原始数据在 app 备份（.bak）内部，")
    print("    需要解出 联系人/短信/设置 那几包才能拿到身份证号与 IMEI。")
    print("    当前已提取的是 APK 与 descript.xml，未含这两项。")
    print("    可行入口：从容器里取 设置(com.android.settings).bak / "
          "联系人(com.android.contacts).bak")


def main() -> int:
    q01()
    q02_03()
    q04_11()
    q12_13()
    return 0


if __name__ == "__main__":
    sys.exit(main())
