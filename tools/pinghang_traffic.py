# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 流量分析（BLE / USBPcap pcapng）

## pcapng 结构

    块 = 类型(4) 总长(4) 内容 总长(4)
    SHB(0x0A0D0D0A)  字节序魔数 + 版本 + section 长度 + 选项
    IDB(0x00000001)  链路类型(2) 保留(2) snaplen(4) + 选项   ← 接口名在这里
    EPB(0x00000006)  接口ID(4) 高位时间戳(4) 低位时间戳(4) 捕获长度(4) 原始长度(4) 数据

## 蓝牙低功耗链路层（Linktype 256 = LE LL with pseudo-header）

每包前面 4 字节伪头部：direction/addrtype(1) channel(1) rssi 符号(1) rssi(1)
随后是 2 字节 LL 头：PDU 类型(低 4 位) + 标志，然后是长度与负载。

广播信道 PDU：
    0 ADV_IND   1 ADV_DIRECT_IND   2 ADV_NONCONN_IND   3 SCAN_REQ
    4 SCAN_RSP  5 CONNECT_IND      6 ADV_SCAN_IND
负载 = AdvertiserAddress(6, 小端) + AdvData(0..31)

AdvData 是 AD 结构序列：长度(1) 类型(1) 数据(长度-1)
    0x01 Flags   0x08/0x09 短/完整本地名   0xFF 厂商自定义数据
"""

from __future__ import annotations

import datetime
import struct
import sys
from pathlib import Path

P = Path(r"D:\MemLens\work\pinghang")

LINKTYPE_NAMES = {
    0: "NULL", 1: "Ethernet", 105: "IEEE802.11", 127: "802.11+radiotap",
    220: "USB_LINUX", 249: "USBPcap", 251: "Bluetooth_LE_LL",
    256: "Bluetooth_LE_LL_with_PHDR", 272: "Bluetooth_BREDR_BB",
}

AD_TYPES = {
    0x01: "Flags", 0x02: "16-bit UUID 列表(不完整)", 0x03: "16-bit UUID 列表",
    0x04: "32-bit UUID 列表(不完整)", 0x05: "32-bit UUID 列表",
    0x06: "128-bit UUID 列表(不完整)", 0x07: "128-bit UUID 列表",
    0x08: "短本地名", 0x09: "完整本地名", 0x0A: "TX 功率",
    0x0D: "Class of Device", 0x15: "128-bit UUID(服务)",
    0x16: "Service Data", 0x19: "外观", 0xFF: "厂商自定义数据",
}


# ---------------------------------------------------------------- pcapng
def parse_pcapng(path: Path):
    data = path.read_bytes()
    pos = 0
    sections: list[dict] = []
    interfaces: list[dict] = []
    packets: list[dict] = []
    iface = 0
    while pos + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, pos)
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 0x0A0D0D0A:
            magic = body[:4]
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            vmaj, vmin = struct.unpack_from(endian + "HH", body, 4)
            sections.append({"endian": endian, "version": f"{vmaj}.{vmin}",
                             "options": _opts(body, 12, endian)})
        elif btype == 0x00000001:
            linktype, _res, snap = struct.unpack_from("<HHI", body, 0)
            opts = _opts(body, 8, "<")
            interfaces.append({"linktype": linktype, "snaplen": snap,
                               "options": opts,
                               "name": opts.get(2, ""), "desc": opts.get(3, ""),
                               "os": opts.get(12, "")})
        elif btype == 0x00000006:
            iface, ts_hi, ts_lo, caplen, origlen = struct.unpack_from("<IIIII", body, 0)
            ts = (ts_hi << 32) | ts_lo
            pkt = body[20:20 + caplen]
            packets.append({"iface": iface, "ts_raw": ts, "caplen": caplen,
                            "origlen": origlen, "data": pkt})
        iface = iface
        pos += blen
    return sections, interfaces, packets


def _opts(body: bytes, start: int, endian: str = "<") -> dict:
    out: dict = {}
    i = start
    while i + 4 <= len(body):
        code, ln = struct.unpack_from(endian + "HH", body, i)
        if code == 0:
            break
        val = body[i + 4:i + 4 + ln]
        out[code] = val.decode("utf-8", "replace").rstrip("\x00")
        i += 4 + ln + ((4 - ln % 4) % 4)
    return out


def ts_to_utc(ts: int, iface_tsresol: str = "") -> str:
    """默认时间戳单位是微秒；if_tsresol 选项可改成纳秒等。"""
    try:
        resol = 6
        if iface_tsresol:
            resol = int(iface_tsresol, 0) if isinstance(iface_tsresol, str) else 6
        sec = ts / (10 ** resol)
        return datetime.datetime.utcfromtimestamp(sec).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)


# ---------------------------------------------------------------- BLE
ADV_TYPES = {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND",
             3: "SCAN_REQ", 4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND"}


def parse_ble_ll(pkt: bytes) -> dict | None:
    """解析 LE LL with pseudo-header 的一个包。"""
    if len(pkt) < 6:
        return None
    # 伪头部 4 字节：bit0 方向；随后 2 字节 LL 头
    ll = pkt[4:]
    if len(ll) < 2:
        return None
    pdu_type = ll[0] & 0x0F
    txadd = (ll[1] >> 6) & 1 if len(ll) > 1 else 0
    length = ll[1] & 0x3F if pdu_type >= 3 else (ll[1] & 0x3F)
    # 实际长度字段：对于 ADV_* 在 ll[1] 的低 6 位
    payload = ll[2:2 + (ll[1] & 0x3F)]
    adv_addr = ""
    adv_data = b""
    if pdu_type in (0, 1, 2, 4, 6) and len(payload) >= 6:
        adv_addr = ":".join(f"{b:02X}" for b in reversed(payload[:6]))
        adv_data = payload[6:]
    elif pdu_type == 5 and len(payload) >= 12:
        adv_addr = ":".join(f"{b:02X}" for b in reversed(payload[6:12]))
    return {"pdu": ADV_TYPES.get(pdu_type, f"PDU_{pdu_type}"),
            "pdu_type": pdu_type, "txadd": txadd,
            "addr": adv_addr, "data": adv_data,
            "rssi": struct.unpack("b", pkt[3:4])[0] if len(pkt) > 3 else None}


def parse_ad(data: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i < len(data):
        ln = data[i]
        if ln == 0 or i + 1 + ln > len(data):
            break
        typ = data[i + 1]
        out.append((typ, data[i + 2:i + 1 + ln]))
        i += 1 + ln
    return out


def name_of(ad: list[tuple[int, bytes]]) -> str:
    for t, v in ad:
        if t in (0x08, 0x09):
            return v.decode("utf-8", "replace")
    return ""


def mfr_of(ad: list[tuple[int, bytes]]) -> str:
    for t, v in ad:
        if t == 0xFF:
            cid = struct.unpack("<H", v[:2])[0] if len(v) >= 2 else 0
            return f"cid=0x{cid:04X} data={v[2:].hex()}"
    return ""


def main() -> int:
    for name in ("BLE", "USBPcap"):
        p = P / name
        if not p.is_file():
            print(f"缺少 {p}")
            continue
        secs, ifaces, pkts = parse_pcapng(p)
        print("=" * 74)
        print(f"{name}  —— {len(pkts):,} 个包")
        print("=" * 74)
        for i, s in enumerate(secs):
            print(f"  SHB[{i}] 版本 {s['version']}")
            for k, v in s["options"].items():
                label = {1: "注释", 2: "硬件", 3: "操作系统", 4: "用户程序"}.get(k, f"opt{k}")
                print(f"      {label}: {v}")
        for i, f in enumerate(ifaces):
            lt = f["linktype"]
            print(f"  IDB[{i}] linktype={lt} ({LINKTYPE_NAMES.get(lt,'?')}) "
                  f"snaplen={f['snaplen']}")
            if f["name"]:
                print(f"      ★ 接口名: {f['name']}")
            if f["desc"]:
                print(f"      描述: {f['desc']}")
            if f["os"]:
                print(f"      系统: {f['os']}")
            for k, v in f["options"].items():
                if k not in (2, 3, 12):
                    print(f"      opt{k}: {v}")

        if ifaces and ifaces[0]["linktype"] == 256:
            solve_ble(pkts, ifaces)
        print()
    return 0


def solve_ble(pkts: list[dict], ifaces: list[dict]) -> None:
    print("\n" + "-" * 74)
    print("BLE 广播分析")
    print("-" * 74)
    names: dict[str, str] = {}
    addrs: dict[str, int] = {}
    name_changes: list[tuple[str, str, str]] = []
    mfr_seen: dict[str, tuple[str, str]] = {}

    for pk in pkts:
        b = parse_ble_ll(pk["data"] - None if False else pk["data"])
        if not b or not b["addr"]:
            continue
        ad = parse_ad(b["data"])
        nm = name_of(ad)
        mf = mfr_of(ad)
        addr = b["addr"]
        addrs[addr] = addrs.get(addr, 0) + 1
        ts = ts_to_utc(pk["ts_raw"], ifaces[0]["options"].get(9, ""))
        if nm:
            if addr in names and names[addr] != nm:
                name_changes.append((ts, addr, f"{names[addr]} → {nm}"))
            names[addr] = nm
        if mf:
            mfr_seen[addr] = (ts, mf)

    print(f"\n  设备（按广播地址）：{len(addrs)} 个")
    for a, n in sorted(addrs.items(), key=lambda kv: -kv[1]):
        print(f"    {a}  包数 {n:>5}   名称 {names.get(a,'(无)')!r}")

    print(f"\n  名称变更事件（{len(name_changes)} 次）：")
    for ts, a, ch in name_changes:
        print(f"    {ts} UTC   {a}   {ch}")

    print(f"\n  厂商自定义数据：")
    for a, (ts, mf) in mfr_seen.items():
        print(f"    {a}  {ts} UTC  {mf}")


if __name__ == "__main__":
    sys.exit(main())
