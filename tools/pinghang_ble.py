# -*- coding: utf-8 -*-
r"""
2025 平航杯 · BLE 流量解析（Nordic nRF Sniffer 私有封装）

## 关键：linktype 272 不是标准 BLE

`BLE` 这个 pcapng 的接口描述是 **"nRF Sniffer for Bluetooth LE COM3"**，
linktype=272。这不是标准的 Bluetooth_LE_LL(256)，而是
**Nordic 的私有封装**（Wireshark 由 packet-nordic_ble.c 解析）。

每个捕获包 = 8 字节 Nordic 头 + 负载：

    +0   board id
    +1..2 负载长度（小端）
    +3   协议版本
    +4..5 包计数器（小端）
    +6    包 ID
    +7..  负载

负载第一个字节是 **flags**：

    bit0-1  方向（0x01 M→S / 0x02 S→M）
    bit2    加密
    bit3    丢包
    bit4-7  广播类型（0=ADV_IND, 1=ADV_DIRECT_IND, 2=ADV_NONCONN_IND,
                       3=SCAN_REQ, 4=SCAN_RSP, 5=CONNECT_IND, 6=ADV_SCAN_IND,
                       7=ADV_EXT_IND）

      ⇒ ADV 类型在高 4 位，`flags >> 4`

flags 之后是标准 BLE LL 包：2 字节头（PDU类型低4位 + 长度/标志），
然后是负载；广播信道负载 = 广播地址(6，小端) + AdvData。
"""

from __future__ import annotations

import datetime
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.pinghang_traffic import parse_pcapng, parse_ad, AD_TYPES   # noqa: E402

P = Path(r"D:\MemLens\work\pinghang")
BLE = P / "BLE"

ADV = {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",
       4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND", 7: "ADV_EXT_IND"}


#: nRF Sniffer 头部固定长度（实测反推验证：
#:   caplen - (2 + LL长度 + 3字节CRC) == 21，且偏移 17..20 恰为
#:   广播接入地址 0x8E89BED6（线上字节序 d6 be 89 8e））
NORDIC_HDR = 21
ACC_ADDR = b"\xd6\xbe\x89\x8e"


def parse_nordic(pkt: bytes) -> dict | None:
    """解 Nordic 私有封装：21 字节头 + BLE 链路层包（含 3 字节 CRC）。"""
    if len(pkt) < NORDIC_HDR + 2:
        return None
    out = {
        "board": pkt[0],
        "plen": struct.unpack_from("<H", pkt, 1)[0],
        "proto": pkt[3],
        "counter": struct.unpack_from("<H", pkt, 4)[0],
        "pid": pkt[6],
        "flags": pkt[7],
        "channel": pkt[8],
    }
    # 尽量用接入地址定位 LL 包起点（CONNECT_IND 的接入地址不同，退回头长度）
    start = NORDIC_HDR
    i = pkt.find(ACC_ADDR, 8, 40)
    if i >= 0:
        start = i + 4
    ll = pkt[start:]
    if len(ll) < 2:
        return out
    pdu_type = ll[0] & 0x0F
    ln = ll[1] & 0x3F
    out["pdu_ll"] = pdu_type
    out["pdu"] = ADV.get(pdu_type, f"PDU_{pdu_type}")
    out["ll_start"] = start
    out["ll_len"] = ln

    # ★ 地址/AD 的切分点不能想当然地写死为 6 字节。
    #   实测发现部分 ADV_IND 的 AdvData **少了一个字节**，
    #   按固定 6 字节切会让 AD 结构整体错位 1 字节，
    #   解出来的名称就成了 'LE-YANG`QC\x135 Ei' 这种乱码（实测踩过）。
    #
    #   稳妥做法：在 5/6/7 三种可能的地址长度里，
    #   选**AD 结构能完整走通**（长度字段自洽、类型合法、以 0 结尾）的那一种。
    def _ad_ok(d: bytes) -> bool:
        i = 0
        n_items = 0
        while i < len(d):
            ln2 = d[i]
            if ln2 == 0:
                return True                       # 正常终止（填充）
            if i + 1 + ln2 > len(d):
                return False                      # 越界 → 不对
            t2 = d[i + 1]
            if t2 == 0 or t2 == 0xFF and ln2 < 2:
                return False
            n_items += 1
            i += 1 + ln2
        return n_items > 0

    body = ll[2:2 + ln]
    best = None
    if pdu_type in (0, 1, 2, 4, 6):
        for alen in (6, 5, 7):
            if len(body) > alen and _ad_ok(body[alen:]):
                best = alen
                break
        if best is None:
            best = 6
        out["addr"] = ":".join(f"{b:02X}" for b in reversed(body[:best]))
        out["adv_data"] = body[best:]
        out["addr_len"] = best
    elif pdu_type == 5 and len(body) >= 12:
        out["addr"] = ":".join(f"{b:02X}" for b in reversed(body[6:12]))
        out["adv_data"] = body[12:]
        out["addr_len"] = 6
    else:
        out["addr"] = ""
        out["adv_data"] = body
        out["addr_len"] = 0
    return out


def name_of(ad) -> str:
    for t, v in ad:
        if t in (0x08, 0x09):
            return v.decode("utf-8", "replace")
    return ""


def mfr_of(ad):
    for t, v in ad:
        if t == 0xFF and len(v) >= 2:
            cid = struct.unpack("<H", v[:2])[0]
            return cid, v[2:]
    return None, b""


def main() -> int:
    secs, ifaces, pkts = parse_pcapng(BLE)
    tsres = ifaces[0]["options"].get(9, "")
    print(f"包数 {len(pkts):,}  接口 {ifaces[0]['name']}  "
          f"({ifaces[0]['desc']})")

    devs: dict[str, dict] = {}
    names_timeline: list[tuple[str, str, str, bytes]] = []
    pdu_counter = Counter()
    mfr_counter: dict[str, Counter] = defaultdict(Counter)
    no_addr = 0

    for pk in pkts:
        b = parse_nordic(pk["data"])
        if not b:
            continue
        pdu_counter[b["pdu"]] += 1
        addr = b.get("addr") or ""
        if not addr:
            no_addr += 1
            continue
        ad = parse_ad(b.get("adv_data") or b"")
        nm = name_of(ad)
        cid, mdata = mfr_of(ad)
        d = devs.setdefault(addr, {"n": 0, "names": set(), "first": None,
                                   "last": None, "mfr": Counter()})
        d["n"] += 1
        ts = ts_to_utc(pk["ts_raw"], tsres)
        if d["first"] is None:
            d["first"] = ts
        d["last"] = ts
        if nm:
            d["names"].add(nm)
            names_timeline.append((ts, addr, nm, b.get("adv_data", b"")))
        if cid is not None:
            d["mfr"][(cid, mdata.hex())] += 1
            mfr_counter[addr][(cid, mdata.hex())] += 1

    print(f"\nPDU 类型分布: {dict(pdu_counter)}")
    print(f"无地址包: {no_addr}")
    print(f"\n设备数: {len(devs)}")

    # 有名字的设备
    print("\n" + "=" * 74)
    print("带名称的设备（按包数排序）")
    print("=" * 74)
    named = [(a, d) for a, d in devs.items() if d["names"]]
    for a, d in sorted(named, key=lambda kv: -kv[1]["n"]):
        print(f"  {a}  包 {d['n']:>5}  名称 {sorted(d['names'])}")
        print(f"      {d['first']} → {d['last']}")

    # 名称变更（伪装设备的关键线索）
    print("\n" + "=" * 74)
    print("★ 名称变更事件（同一地址出现多个名称 = 改名伪装）")
    print("=" * 74)
    for a, d in sorted(named, key=lambda kv: -kv[1]["n"]):
        if len(d["names"]) > 1:
            print(f"  {a}")
            print(f"      出现过的名称: {sorted(d['names'])}")
            seen = []
            for ts, ad2, nm, _ in names_timeline:
                if ad2 == a and (not seen or seen[-1][2] != nm):
                    seen.append((ts, ad2, nm))
            for i, (ts, _, nm) in enumerate(seen):
                mark = "原始" if i == 0 else "改为"
                print(f"      {mark}: {nm!r}   首次出现 {ts} UTC")

    # 厂商自定义数据
    print("\n" + "=" * 74)
    print("厂商自定义数据（0xFF）")
    print("=" * 74)
    for a, cnt in sorted(mfr_counter.items(), key=lambda kv: -sum(kv[1].values()))[:8]:
        tops = cnt.most_common(3)
        nm = sorted(devs[a]["names"]) if devs[a]["names"] else []
        print(f"  {a}  名称={nm}")
        for (cid, hexd), c in tops:
            print(f"      cid=0x{cid:04X}  ×{c}  {hexd[:80]}")

    return 0


def ts_to_utc(ts: int, tsres: str = "") -> str:
    try:
        resol = int(tsres, 0) if tsres else 6
    except Exception:
        resol = 6
    try:
        dt = datetime.datetime.fromtimestamp(ts / 10 ** resol, datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)


if __name__ == "__main__":
    sys.exit(main())
