# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 流量分析 01–09 逐题作答（基于 BLE 抓包）

抓包来自 Nordic nRF Sniffer（linktype 272 私有封装）。
每题都给出「判定过程 + 证据报文」，不是只给结论。

题目：
  01 侦查人员用哪个接口抓到蓝牙数据包
  02 起早王伪装成倩倩耳机的设备，原始设备名
  03 该设备改名成耳机前后的 MAC 地址
  04 首次捕获到该设备改名自身名称的 UTC+0 时间
  05 起早王手机向倩倩电脑广播发射的制造商数据
  06 起早王的真名
  07 起早王对倩倩电脑执行了几条 cmd 命令
  08 倩倩电脑中影子账户的账户名和密码
  09 起早王对倩倩电脑执行的最后一条命令
"""

from __future__ import annotations

import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.pinghang_traffic import parse_pcapng, parse_ad              # noqa: E402
from tools.pinghang_ble import parse_nordic, ts_to_utc                # noqa: E402

P = Path(r"D:\MemLens\work\pinghang")
BLE = P / "BLE"
USB = P / "USBPcap"


def hr(t: str) -> None:
    print("\n" + "=" * 76)
    print(t)
    print("=" * 76)


def load_ble():
    secs, ifaces, pkts = parse_pcapng(BLE)
    tsres = ifaces[0]["options"].get(9, "")
    rows = []
    for pk in pkts:
        b = parse_nordic(pk["data"])
        if not b:
            continue
        b["ts"] = ts_to_utc(pk["ts_raw"], tsres)
        b["ts_raw"] = pk["ts_raw"]
        b["ad"] = parse_ad(b.get("adv_data") or b"")
        rows.append(b)
    return secs, ifaces, rows


def ad_get(ad, *types):
    for t, v in ad:
        if t in types:
            return v
    return None


def ad_name(ad) -> str:
    v = ad_get(ad, 0x08, 0x09)
    return v.decode("utf-8", "replace") if v else ""


# ─────────────────────────────────────────────────────── 01
def q01(secs, ifaces):
    hr("01 侦查人员用哪个接口抓到蓝牙数据包")
    f = ifaces[0]
    print(f"  pcapng 接口描述块（IDB）:")
    print(f"    if_name     = {f['name']}")
    print(f"    if_description = {f['desc']}")
    print(f"    if_os       = {f['os']}")
    print(f"    linktype    = {f['linktype']}")
    print(f"\n  ⇒ 答案：{f['name']}（{f['desc']}）")
    print("     说明：nRF Sniffer for Bluetooth LE 通过串口抓 BLE，")
    print("           COM3 即该嗅探器占用的串口接口。")


# ─────────────────────────────────────────────────────── 02-04
def q0204(rows):
    hr("02–04 伪装耳机：原始名称 / 改名前后 MAC / 首次改名 UTC 时间")

    # 汇总每个地址出现过的名称序列
    seq: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for r in rows:
        a = r.get("addr") or ""
        nm = ad_name(r["ad"])
        if not a:
            continue
        seq[a].append((r["ts"], r["ts_raw"], nm))

    candidates = []
    for a, lst in seq.items():
        names = []
        for _ts, _tr, nm in lst:
            if nm and (not names or names[-1] != nm):
                names.append(nm)
        uniq = set(n for n in names if n)
        if len(uniq) >= 2:
            candidates.append((a, names, uniq, lst))

    print("  出现过多于一个名称的地址：")
    for a, names, uniq, lst in sorted(candidates, key=lambda x: -len(x[3]))[:12]:
        dt = lst[-1][0]
        print(f"    {a}  包数 {len(lst):>5}  最后时刻 {dt}")
        for i, n in enumerate(names[:8]):
            mark = "原始" if i == 0 else "改为"
            print(f"        {mark}: {n!r}")

    # 找"耳机类"名称
    HEADSET = ("QC35", "QC3", "AirPods", "Bose", "耳机", "Headphone", "WH-1000",
               "FreeBuds", "Buds", "SoundCore", "LE-")
    print("\n  与耳机相关的地址：")
    for a, lst in seq.items():
        names = {ad_name(r["ad"]) for r in lst if ad_name(r["ad"])}
        if any(any(h in n for h in HEADSET) for n in names):
            base = sorted(names)
            print(f"    {a}   包数 {len(lst):>5}   名称 {base}")

    # 同前缀不同后缀（Flipper 改名的典型特征）
    print("\n  同一 OUI/前缀下出现多个相邻地址（改名换址的痕迹）：")
    by_prefix = defaultdict(list)
    for a in seq:
        parts = a.split(":")
        by_prefix[":".join(parts[:3])].append(a)
    for pre, addrs in by_prefix.items():
        if len(addrs) > 1:
            for a in sorted(addrs):
                names = {ad_name(r["ad"]) for r in seq[a] if ad_name(r["ad"])}
                if names:
                    print(f"    {pre}…  {a}  名称 {sorted(names)[:4]}")
    return seq


# ─────────────────────────────────────────────────────── 05
def q05(rows):
    hr("05 起早王手机向倩倩电脑广播的制造商数据")
    mfr: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        v = ad_get(r["ad"], 0xFF)
        a = r.get("addr") or ""
        if v and a:
            mfr[a][v] += 1
    print("  含厂商自定义数据(0xFF)的地址：")
    for a, c in sorted(mfr.items(), key=lambda kv: -sum(kv[1].values()))[:10]:
        names = {ad_name(r["ad"]) for r in rows
                 if (r.get("addr") == a) and ad_name(r["ad"])}
        print(f"    {a}  名称 {sorted(names)}")
        for v, n in c.most_common(3):
            cid = struct.unpack("<H", v[:2])[0] if len(v) >= 2 else 0
            print(f"        ×{n:<5} cid=0x{cid:04X}  payload={v[2:].hex()}")


# ─────────────────────────────────────────────────────── 06-09 (USBPcap)
def q0609():
    hr("06–09 键盘/USB 抓包（起早王真名、cmd 命令、影子账户）")
    secs, ifaces, pkts = parse_pcapng(USB)
    print(f"  USBPcap 包数 {len(pkts):,}   接口 {ifaces[0]['name']}")
    # USBPcap 头：headerLen(2) irpId(8) status(4) function(2) info(1) bus(2)
    #           device(2) endpoint(1) transfer(1) dataLength(4)
    keystrokes = []
    for pk in pkts:
        d = pk["data"]
        if len(d) < 27:
            continue
        hlen = struct.unpack_from("<H", d, 0)[0]
        status, function = struct.unpack_from("<IH", d, 10)
        info = d[16]
        bus, dev, ep, transfer = struct.unpack_from("<HHBB", d, 17)
        dlen = struct.unpack_from("<I", d, 22)[0]
        payload = d[hlen:]
        if transfer == 2 and dlen == 8 and len(payload) >= 8 and status == 0:
            keystrokes.append((pk["ts_raw"], payload[:8], bus, dev))
    print(f"  疑似键盘报告 {len(keystrokes)} 个")

    # HID 键码 → 字符
    MAP = {
        0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
        0x0A: 'g', 0x0B: 'h', 0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
        0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
        0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
        0x1C: 'y', 0x1D: 'z', 0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4',
        0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
        0x28: '\n', 0x2C: ' ', 0x2D: '-', 0x2E: '=', 0x2F: '[', 0x30: ']',
        0x31: '\\', 0x33: ';', 0x34: "'", 0x35: '`', 0x36: ',', 0x37: '.',
        0x38: '/', 0x4F: '>', 0x50: '<', 0x51: '?', 0x52: '"', 0x4B: '\t',
    }
    SHIFT = {0x1E: '!', 0x1F: '@', 0x20: '#', 0x21: '$', 0x22: '%', 0x23: '^',
             0x24: '&', 0x25: '*', 0x26: '(', 0x27: ')'}
    text = []
    prev = b"\x00" * 8
    for _ts, rep, _b, _d in keystrokes:
        mod, *keys = rep
        for k in keys:
            if k == 0:
                continue
            ch = MAP.get(k)
            if ch is None:
                continue
            if mod & 0x22 and k in SHIFT:
                ch = SHIFT[k]
            elif mod & 0x22 and ch.isalpha():
                ch = ch.upper()
            text.append(ch)
        prev = rep
    raw = "".join(text)
    print(f"  还原字符数 {len(raw)}")
    print("\n  ---- 解码文本（前 1800 字）----")
    print(raw[:1800])
    return raw, keystrokes


def main() -> int:
    secs, ifaces, rows = load_ble()
    q01(secs, ifaces)
    q0204(rows)
    q05(rows)
    q0609()
    return 0


if __name__ == "__main__":
    sys.exit(main())
