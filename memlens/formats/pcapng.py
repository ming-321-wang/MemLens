r"""
MemLens · pcapng 容器 + BLE 链路层 + USB HID 键盘

## pcapng 块结构

    块 = 类型(4) 总长(4) 内容 总长(4)

    SHB (0x0A0D0D0A)  字节序魔数 + 版本 + section 长度 + 选项
    IDB (0x00000001)  链路类型(2) 保留(2) snaplen(4) + 选项  ← 接口名在这里
    EPB (0x00000006)  接口ID(4) 高位时间戳(4) 低位时间戳(4) 捕获长(4) 原始长(4) 数据

选项格式：码(2) 长度(2) 值(长度)，长度按 4 字节对齐；码 0 表示选项结束。
常用选项：2=if_name, 3=if_description, 9=if_tsresol, 12=if_os。

## BLE 链路层

标准 LE LL（linktype 256/257）：

    LL 头 2 字节 = PDU 类型(低4位) + 长度(低6位)
    广播类 PDU 负载 = 广播地址(6，小端) + AdvData

**Nordic nRF Sniffer 私有封装（linktype 272）**：
`nRF Sniffer for Bluetooth LE` 抓的包带 21 字节私有头，
其后是 4 字节广播接入地址（线上字节序 D6 BE 89 8E = 0x8E89BED6），
再往后才是 LL 包（末尾 3 字节是 CRC）。
按标准 BLE 解会得到满屏乱码且**不报错** —— 这是最容易浪费时间的坑。

## AdvData（AD 结构）

    长度(1) 类型(1) 数据(长度-1)，长度 0 表示填充结束

    0x01 Flags   0x08/0x09 短名/完整本地名   0xFF 厂商自定义数据   0x16 服务数据
"""

from __future__ import annotations

import datetime
import struct
from typing import Any, Iterator

# ─────────────────────────────────────────────────────────── 链路类型
LINKTYPE_NAMES: dict[int, str] = {
    0: "NULL", 1: "Ethernet", 101: "RAW", 105: "IEEE802.11",
    113: "LINUX_SLL", 127: "IEEE802_11_RADIOTAP", 220: "USB_LINUX",
    249: "USBPcap", 251: "Bluetooth_LE_LL",
    256: "Bluetooth_LE_LL_with_PHDR", 272: "Bluetooth_BREDR_BB",
}

#: Nordic 私有封装的头长度（实测反推：caplen - (2+LL长度+3字节CRC) == 21）
NORDIC_HDR = 21

#: BLE 广播接入地址（线上字节序）
ACC_ADDR = b"\xd6\xbe\x89\x8e"

#: LE LL 广播类 PDU
ADV_PDU = {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND",
           3: "SCAN_REQ", 4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND",
           7: "ADV_EXT_IND"}

AD_TYPES: dict[int, str] = {
    0x01: "Flags", 0x02: "16-bit UUID 列表(不完整)", 0x03: "16-bit UUID 列表",
    0x04: "32-bit UUID 列表(不完整)", 0x05: "32-bit UUID 列表",
    0x06: "128-bit UUID 列表(不完整)", 0x07: "128-bit UUID 列表",
    0x08: "短本地名", 0x09: "完整本地名", 0x0A: "TX 功率",
    0x0D: "Class of Device", 0x16: "服务数据", 0x19: "外观",
    0xFF: "厂商自定义数据",
}


# ─────────────────────────────────────────────────────────── 基础工具
def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def parse_options(body: bytes, start: int, endian: str = "<") -> dict[int, Any]:
    """解析 pcapng 块选项区。"""
    out: dict[int, Any] = {}
    i = start
    while i + 4 <= len(body):
        code, ln = struct.unpack_from(endian + "HH", body, i)
        if code == 0:
            break
        val = body[i + 4:i + 4 + ln]
        out[code] = val.decode("utf-8", "replace").rstrip("\x00") if code in (2, 3, 12) else val
        i += 4 + ln + ((4 - ln % 4) % 4)
    return out


def ts_to_utc(ts: int, tsres: str = "") -> str:
    """时间戳 → UTC 字符串。默认单位微秒；if_tsresol(选项码 9) 可改。"""
    resol = 6
    if tsres:
        try:
            resol = int(str(tsres), 0)
        except ValueError:
            resol = 6
    try:
        dt = datetime.datetime.fromtimestamp(ts / 10 ** resol, datetime.timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (OverflowError, OSError, ValueError):
        return str(ts)


# ─────────────────────────────────────────────────────────── pcapng
class PcapngFile:
    """
    pcapng 解析器。

    一次读全文件（pcapng 通常不大）；超大文件请用 `stream=True` 走逐块模式。
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.sections: list[dict[str, Any]] = []
        self.interfaces: list[dict[str, Any]] = []
        self.packets: list[dict[str, Any]] = []
        self._parse()

    # ------------------------------------------------------------ 解析
    def _parse(self) -> None:
        data = open(self.path, "rb").read()
        pos = 0
        n = len(data)
        while pos + 12 <= n:
            btype, blen = struct.unpack_from("<II", data, pos)
            if blen < 12 or pos + blen > n:
                break
            body = data[pos + 8:pos + blen - 4]
            if btype == 0x0A0D0D0A:                 # SHB
                magic = body[:4]
                endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
                vmaj, vmin = struct.unpack_from(endian + "HH", body, 4)
                self.sections.append({"endian": endian,
                                      "version": f"{vmaj}.{vmin}",
                                      "options": parse_options(body, 12, endian)})
            elif btype == 0x00000001:               # IDB
                linktype, _res, snap = struct.unpack_from("<HHI", body, 0)
                opts = parse_options(body, 8, "<")
                self.interfaces.append({
                    "linktype": linktype,
                    "linktype_name": LINKTYPE_NAMES.get(linktype, f"linktype_{linktype}"),
                    "snaplen": snap,
                    "name": opts.get(2, ""),
                    "description": opts.get(3, ""),
                    "os": opts.get(12, ""),
                    "tsresol": opts.get(9, ""),
                    "options": opts,
                })
            elif btype == 0x00000006:               # EPB
                iface, hi, lo, caplen, origlen = struct.unpack_from("<IIIII", body, 0)
                ts = (hi << 32) | lo
                self.packets.append({"iface": iface, "ts_raw": ts,
                                     "caplen": caplen, "origlen": origlen,
                                     "data": body[20:20 + caplen]})
            pos += blen

    # ------------------------------------------------------------ 接口
    def iface(self, index: int) -> dict[str, Any]:
        if 0 <= index < len(self.interfaces):
            return self.interfaces[index]
        return {"linktype": 0, "linktype_name": "?", "name": "", "description": "",
                "os": "", "tsresol": ""}

    def summary(self) -> dict[str, Any]:
        return {
            "file": self.path,
            "sections": len(self.sections),
            "interfaces": [
                {"name": f.get("name", ""), "description": f.get("description", ""),
                 "linktype": f.get("linktype"), "linktype_name": f.get("linktype_name"),
                 "os": f.get("os", "")}
                for f in self.interfaces],
            "packets": len(self.packets),
        }


# ─────────────────────────────────────────────────────────── BLE
def parse_ad(data: bytes) -> list[tuple[int, bytes]]:
    """拆 AD 结构序列。"""
    out: list[tuple[int, bytes]] = []
    i = 0
    n = len(data)
    while i < n:
        ln = data[i]
        if ln == 0:
            break
        if i + 1 + ln > n:
            break
        out.append((data[i + 1], data[i + 2:i + 1 + ln]))
        i += 1 + ln
    return out


def ad_name(ad: list[tuple[int, bytes]]) -> str:
    """取设备名（短名/全名），只接受可打印 ASCII（过滤错位产生的乱码）。"""
    for t, v in ad:
        if t in (0x08, 0x09):
            try:
                s = v.decode("utf-8")
            except UnicodeDecodeError:
                return ""
            if s and all(32 <= ord(c) < 127 for c in s):
                return s
    return ""


def ad_manufacturer(ad: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """取厂商自定义数据（Company ID + payload）。"""
    for t, v in ad:
        if t == 0xFF and len(v) >= 2:
            return struct.unpack("<H", v[:2])[0], v[2:]
    return 0, b""


def _ad_self_consistent(d: bytes) -> bool:
    """AD 序列能否自洽走完（长度不越界、类型合法）。"""
    i = 0
    items = 0
    while i < len(d):
        ln = d[i]
        if ln == 0:
            return True
        if i + 1 + ln > len(d):
            return False
        t = d[i + 1]
        if t == 0 or (t == 0xFF and ln < 2):
            return False
        items += 1
        i += 1 + ln
    return items > 0


def parse_ble_packet(pkt: bytes, linktype: int) -> dict[str, Any] | None:
    """
    解析一个 BLE 包。

    Args:
        pkt: 原始包
        linktype: 256/257 = 标准 LE LL；272 = Nordic 私有封装
    """
    out: dict[str, Any] = {}
    if linktype == 272:
        if len(pkt) < NORDIC_HDR + 2:
            return None
        out.update({
            "board": pkt[0],
            "payload_len": struct.unpack_from("<H", pkt, 1)[0],
            "proto": pkt[3],
            "counter": struct.unpack_from("<H", pkt, 4)[0],
            "packet_id": pkt[6],
            "flags": pkt[7],
            "channel": pkt[8],
        })
        start = NORDIC_HDR
        i = pkt.find(ACC_ADDR, 8, 40)
        if i >= 0:
            start = i + 4
        ll = pkt[start:]
    else:
        if linktype == 257:          # with PHDR：前 4 字节是伪头
            if len(pkt) < 6:
                return None
            ll = pkt[4:]
        else:
            if len(pkt) < 2:
                return None
            ll = pkt
        out["rssi"] = struct.unpack("b", pkt[3:4])[0] if len(pkt) > 3 else None

    if len(ll) < 2:
        return out
    pdu_type = ll[0] & 0x0F
    ln = ll[1] & 0x3F
    body = ll[2:2 + ln]
    out["pdu_type"] = pdu_type
    out["pdu"] = ADV_PDU.get(pdu_type, f"PDU_{pdu_type}")
    out["ll_length"] = ln

    if pdu_type in (0, 1, 2, 4, 6) and len(body) >= 6:
        # ★ 广播地址长度**不能写死 6**：部分包的 AdvData 少一字节，
        #   写死会让 AD 结构整体错位 1 字节，设备名解成乱码。
        #   正解：挑一个能让 AD 序列自洽走完的长度。
        alen = 6
        for cand in (6, 5, 7):
            if len(body) > cand and _ad_self_consistent(body[cand:]):
                alen = cand
                break
        out["addr"] = ":".join(f"{b:02X}" for b in reversed(body[:alen]))
        out["adv_data"] = body[alen:]
        out["addr_len"] = alen
    elif pdu_type == 5 and len(body) >= 12:
        out["addr"] = ":".join(f"{b:02X}" for b in reversed(body[6:12]))
        out["adv_data"] = body[12:]
    else:
        out["addr"] = ""
        out["adv_data"] = body
    return out


def bluetooth_records(path: str) -> Iterator[dict[str, Any]]:
    """
    从 pcapng 里产出 BLE 设备表（每个广播地址一行）。

    字段：地址 / 包数 / 首个名称 / 全部名称 / 首个与最后出现时间 / 厂商数据
    """
    pf = PcapngFile(path)
    if not pf.interfaces:
        return
    lt = pf.interfaces[0]["linktype"]
    tsres = pf.interfaces[0].get("tsresol", "")
    devices: dict[str, dict[str, Any]] = {}
    for pk in pf.packets:
        b = parse_ble_packet(pk["data"], lt)
        if not b:
            continue
        addr = b.get("addr") or ""
        if not addr:
            continue
        d = devices.setdefault(addr, {
            "地址": addr, "包数": 0, "名称集合": set(),
            "首个名称": "", "最后名称": "", "厂商数据": set(),
            "首次出现": "", "最后出现": "", "PDU类型": set(),
        })
        d["包数"] += 1
        d["PDU类型"].add(b.get("pdu", ""))
        ts = ts_to_utc(pk["ts_raw"], tsres)
        if not d["首次出现"]:
            d["首次出现"] = ts
        d["最后出现"] = ts
        ad = parse_ad(b.get("adv_data") or b"")
        nm = ad_name(ad)
        if nm:
            d["名称集合"].add(nm)
            if not d["首个名称"]:
                d["首个名称"] = nm
            d["最后名称"] = nm
        cid, payload = ad_manufacturer(ad)
        if cid:
            d["厂商数据"].add(f"0x{cid:04X}:{payload.hex()}")
    for d in devices.values():
        yield {
            "地址": d["地址"], "包数": d["包数"],
            "首个名称": d["首个名称"], "最后名称": d["最后名称"],
            "全部名称": " | ".join(sorted(d["名称集合"])),
            "厂商数据": " | ".join(sorted(d["厂商数据"])),
            "首次出现(UTC)": d["首次出现"], "最后出现(UTC)": d["最后出现"],
            "PDU类型": " | ".join(sorted(x for x in d["PDU类型"] if x)),
        }


def ble_rename_events(path: str) -> Iterator[dict[str, Any]]:
    """
    产出「同一地址出现多个设备名」的改名事件 —— 蓝牙伪装的核心线索。

    顺带给出**改名时刻的 UTC 时间**，这是此类题目最常问的那一栏。
    """
    pf = PcapngFile(path)
    if not pf.interfaces:
        return
    lt = pf.interfaces[0]["linktype"]
    tsres = pf.interfaces[0].get("tsresol", "")
    seq: dict[str, list[tuple[str, str]]] = {}
    for pk in pf.packets:
        b = parse_ble_packet(pk["data"], lt)
        if not b:
            continue
        addr = b.get("addr") or ""
        if not addr:
            continue
        nm = ad_name(parse_ad(b.get("adv_data") or b""))
        if not nm:
            continue
        lst = seq.setdefault(addr, [])
        if not lst or lst[-1][1] != nm:
            lst.append((ts_to_utc(pk["ts_raw"], tsres), nm))
    for addr, lst in seq.items():
        names = []
        for _ts, nm in lst:
            if nm not in names:
                names.append(nm)
        if len(names) < 2:
            continue
        first = lst[0]
        renamed = next(((ts, nm) for ts, nm in lst if nm == names[1]), ("", ""))
        yield {
            "地址": addr,
            "原始名称": names[0],
            "改后名称": names[1],
            "全部名称": " | ".join(names),
            "首次出现(UTC)": first[0],
            "改名时刻(UTC)": renamed[0],
            "改名次数": len(names) - 1,
        }


# ─────────────────────────────────────────────────────────── USB HID
#: HID Usage ID → 字符
HID_KEYS: dict[int, str] = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f",
    0x0A: "g", 0x0B: "h", 0x0C: "i", 0x0D: "j", 0x0E: "k", 0x0F: "l",
    0x10: "m", 0x11: "n", 0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r",
    0x16: "s", 0x17: "t", 0x18: "u", 0x19: "v", 0x1A: "w", 0x1B: "x",
    0x1C: "y", 0x1D: "z",
    0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6",
    0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x29: "\x1b", 0x2A: "\b", 0x2B: "\t", 0x2C: " ",
    0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\", 0x32: "#",
    0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
    0x39: "CapsLock",
    0x4F: "\x1b[C", 0x50: "\x1b[D", 0x51: "\x1b[B", 0x52: "\x1b[A",
}

HID_SHIFTED: dict[str, str] = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&",
    "8": "*", "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}",
    "\\": "|", ";": ":", "'": '"', "`": "~", ",": "<", ".": ">", "/": "?",
}

HID_SHIFT_MASK = 0x22        # 左 Shift(0x02) | 右 Shift(0x20)

#: 不产生字符的键
HID_NONCHAR = {"CapsLock"}


def usbpcp_packets(path: str) -> Iterator[dict[str, Any]]:
    """解析 USBPcap 头，产出逐包记录。"""
    pf = PcapngFile(path)
    for pk in pf.packets:
        d = pk["data"]
        if len(d) < 28:
            continue
        hlen = _u16(d, 0)
        status = _u32(d, 10)
        bus, dev = struct.unpack_from("<HH", d, 17)
        ep = d[21]
        xfer = d[22]
        dlen = _u32(d, 23)
        yield {
            "ts_raw": pk["ts_raw"], "status": status, "bus": bus, "device": dev,
            "endpoint": ep, "transfer": xfer, "data_len": dlen,
            "payload": d[hlen:hlen + dlen],
        }


def hid_records(path: str) -> dict[str, Any]:
    """
    从 USBPcap 还原键盘输入。

    返回 {"text": 还原文本, "events": 事件列表, "stats": 统计}

    ★ 报告布局：本例是 37 字节复合 HID，**第 0 字节是 Report ID**，
      真正的 boot 协议报告在 [1]=修饰键 / [3:9]=按键码。
      按标准 8 字节布局解会得到一堆无效键码。
    """
    events: list[dict[str, Any]] = []
    text: list[str] = []
    prev: tuple | None = None
    for p in usbpcp_packets(path):
        if p["status"] != 0 or p["transfer"] != 1 or not (p["endpoint"] & 0x80):
            continue
        pl = p["payload"]
        if len(pl) < 10 or pl[0] != 0x01:
            continue
        mod = pl[1]
        keys = [k for k in pl[3:9] if k]
        sig = (mod, tuple(keys))
        if sig == prev:
            continue
        prev = sig
        for k in keys:
            ch = HID_KEYS.get(k)
            if ch is None:
                events.append({"ts_raw": p["ts_raw"], "key": k, "char": ""})
                continue
            if mod & HID_SHIFT_MASK:
                ch = HID_SHIFTED.get(ch, ch.upper() if ch.isalpha() else ch)
            if ch == "\b":
                if text:
                    text.pop()
                events.append({"ts_raw": p["ts_raw"], "key": k, "char": "<DEL>"})
                continue
            if ch == "\n":
                events.append({"ts_raw": p["ts_raw"], "key": k, "char": "<RET>"})
                text.append("\n")
                continue
            if ch == " ":
                events.append({"ts_raw": p["ts_raw"], "key": k, "char": "<SPACE>"})
                text.append(" ")
                continue
            if ch in HID_NONCHAR or ch.startswith("\x1b["):
                # ★ CapsLock 之类不产生字符，必须跳过，
                #   否则 abcdefghijkImn 会变成 abcdefghijkCapsLockiCapsLockmn
                events.append({"ts_raw": p["ts_raw"], "key": k, "char": ""})
                continue
            events.append({"ts_raw": p["ts_raw"], "key": k, "char": ch})
            text.append(ch)
    s = "".join(text)
    return {
        "text": s,
        "events": events,
        "stats": {
            "按键事件数": len(events),
            "字符数": len(s),
            "退格次数": sum(1 for e in events if e["char"] == "<DEL>"),
            "回车次数": sum(1 for e in events if e["char"] == "<RET>"),
            "行数": s.count("\n"),
        },
    }
