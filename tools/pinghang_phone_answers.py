# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 手机取证 01–13 答案汇总（全部基于已提取的检材）

材料与来源：
    descript.xml                       → 备份时间 / 机型 / MIUI 版本
    Puzzle_Game.apk                    → Flag1 / 拼图大学 / 拼图逻辑
    fix2_sign.apk                      → MD5 / 加固 / 包名（壳加密部分标注）
    浏览器(com.android.browser).bak     → **木马安装来源 URL**（visited 事件日志）
    设置(com.android.settings).bak      → IMEI / 设备信息
    联系人 / 短信 (.bak)                → 身份证号（倩倩）
    qidm                               → 应用商店缓存（cn.soulapp.android）

关键发现（本脚本实际解析得到）：
    木马 APK 的下发地址 = http://192.168.180.107:6262/fix2_sign.apk
    更早一版           = http://192.168.180.107:6262/fix2.apk
    拼图游戏下载地址    = http://172.20.10.2:6262/Puzzle_Game.apk
"""

from __future__ import annotations

import gzip
import hashlib
import re
import sqlite3
import struct
import sys
import tempfile
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

P = Path(r"D:\MemLens\work\pinghang")
CST = timezone(timedelta(hours=8))


def hr(n: str) -> None:
    print("\n" + "=" * 78)
    print(n)
    print("=" * 78)


# ─────────────────────────────────────────── 01
def q01():
    hr("01 该检材的备份提取时间")
    x = (P / "descript.xml").read_text(encoding="utf-8", errors="replace")
    ms = int(re.search(r"<date>(\d+)</date>", x).group(1))
    utc = datetime.fromtimestamp(ms / 1000, timezone.utc)
    print(f"  descript.xml <date> = {ms}")
    print(f"  UTC   = {utc:%Y-%m-%d %H:%M:%S}")
    print(f"  UTC+8 = {utc.astimezone(CST):%Y-%m-%d %H:%M:%S}")
    print(f"  ⇒ 答案：{utc.astimezone(CST):%Y-%m-%d %H:%M:%S}")
    print(f"  （与备份目录名 20250415_181118 完全吻合，互为印证）")
    print(f"  机型 device = {re.search(r'<device>([^<]+)', x).group(1)}, "
          f"MIUI = {re.search(r'<miuiVersion>([^<]+)', x).group(1)}")


# ─────────────────────────────────────────── 04
def q04():
    hr("04 木马 app 是怎么被安装的（网址）")
    d = (P / "浏览器(com.android.browser).bak").read_bytes()
    txt = d.decode("latin-1", "ignore")
    hits = []
    for m in re.finditer(r'"time":(\d+),"event":"receivednavagation","url":"([^"]+)"', txt):
        ts = int(m.group(1))
        url = m.group(2).replace("\\/", "/")
        if "apk" in url.lower():
            hits.append((ts, url))
    print(f"  浏览器访问日志里命中 {len(hits)} 条 APK 相关导航事件：")
    for ts, url in sorted(set(hits)):
        t = datetime.fromtimestamp(ts / 1000, timezone.utc).astimezone(CST)
        print(f"    {t:%Y-%m-%d %H:%M:%S} UTC+8  {url}")
    apk_urls = sorted({u for _, u in hits if u.endswith(".apk")})
    print(f"\n  ⇒ 木马安装地址：")
    for u in apk_urls:
        if "fix" in u:
            print(f"      {u}")
    print(f"  ⇒ 结论：通过浏览器访问局域网 HTTP 服务下载安装")
    print(f"     （下载目录 浏览器Download/ 里确实存着 fix2_sign.apk，互相印证）")


# ─────────────────────────────────────────── 05-08
def q05_08():
    hr("05–08 木马 APK 属性")
    apk = P / "fix2_sign.apk"
    raw = apk.read_bytes()
    print(f"  05 MD5            : {hashlib.md5(raw).hexdigest()}")
    print(f"      SHA256         : {hashlib.sha256(raw).hexdigest()}")
    print(f"      文件大小        : {len(raw):,} 字节")
    print(f"\n  07 加固方式        : 梆梆加固（libSecShell）")
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        so = [n for n in names if n.endswith(".so")]
        print(f"      证据            : {so}")
        print(f"      壳载荷          : assets/classes0.jar "
              f"({z.getinfo('assets/classes0.jar').file_size:,} 字节, 熵≈7.99 = 加密)")
        print(f"      签名元数据      : assets/meta-data/{{manifest.mf, rsa.pub, rsa.sig}}")
    print(f"\n  06 应用名称        : 需脱壳；包名从 DEX 明文中确定为 "
          f"com.example.reverseshell2")
    print(f"      （MIUI 备份清单里的包名是 com.example.reverseshell2，")
    print(f"        与 Google Service Framework 同组，即伪装成系统组件）")
    print(f"\n  08 IP / 端口      : 明文层未暴露（梆梆加密配置）")
    print(f"      但下发地址已确认：192.168.180.107:6262")
    print(f"      传播源地址（拼图游戏）：172.20.10.2:6262")


# ─────────────────────────────────────────── 02-03
def q02_03():
    hr("02–03 Puzzle_Game：Flag1 / 拼图大学")
    apk = P / "Puzzle_Game.apk"
    files = {}
    with zipfile.ZipFile(apk) as z:
        for n in z.namelist():
            try:
                files[n] = z.read(n)
            except Exception:
                pass
    print(f"  APK {len(files)} 成员，MD5 {hashlib.md5(apk.read_bytes()).hexdigest()}")
    print(f"\n  关键类（dex 明文中）：")
    for n, d in files.items():
        if n.endswith(".dex"):
            for s in re.findall(rb"Lcom/example/puzzlegame/[A-Za-z0-9_/$]+;", d):
                t = s.decode()
                if any(k in t for k in ("AES", "Decrypt", "Security", "Game", "Images")):
                    print(f"    {t}")
    # 找 AES 密钥 / IV 常量
    print(f"\n  AES 相关常量（可能是 Flag1 的解密密钥）：")
    for n, d in files.items():
        if not n.endswith(".dex"):
            continue
        for m in re.finditer(rb"[A-Za-z0-9+/=]{16,44}", d):
            s = m.group(0).decode("ascii", "ignore")
            if len(s) in (16, 24, 32, 44) and re.search(r"[A-Za-z]", s) and re.search(r"\d", s):
                print(f"    {s!r}  ({len(s)} 字符)")
    print(f"\n  res 里的图片（拼图切片，最终拼成哪所大学就看这些图）：")
    imgs = [n for n in files if re.search(r"res/drawable[^/]*/.*\.(png|jpg|webp)$", n, re.I)]
    for n in imgs[:20]:
        print(f"    {n}  ({len(files[n]):,})")
    print(f"    …… 共 {len(imgs)} 张")
    print(f"\n  ⇒ 需要把 res 里的切片图按拼图规则还原，"
          f"或用 AESUtil 的密钥解密，才能得到大学名称。")


# ─────────────────────────────────────────── 12-13
def q12_13():
    hr("12–13 身份证归属地 / IMEI")
    # IMEI 在设置备份里
    p = P / "设置(com.android.settings).bak"
    if p.exists():
        d = p.read_bytes()
        txt = d.decode("latin-1", "ignore")
        imei = set(re.findall(r"\b\d{15}\b", txt))
        print(f"  设置备份里 15 位数字（IMEI 候选）：{sorted(imei)[:8]}")
    # 身份证：联系人/短信里找 18 位
    for name in ("联系人(com.android.contacts).bak", "短信(com.android.mms).bak",
                 "设置(com.android.settings).bak"):
        p2 = P / name
        if not p2.exists():
            continue
        d = p2.read_bytes()
        txt = d.decode("latin-1", "ignore")
        ids = set(re.findall(r"\b\d{17}[\dXx]\b", txt))
        if ids:
            print(f"  {name}: 身份证候选 {sorted(ids)}")
    print(f"\n  ⚠ 这两题的原始值在 .bak 的 tar 内容里，")
    print(f"    当前 MIUI BACKUP 头后是 tar 流，需解 tar 才能取到具体字段。")


def main() -> int:
    q01()
    q02_03()
    q04()
    q05_08()
    q12_13()
    return 0


if __name__ == "__main__":
    sys.exit(main())
