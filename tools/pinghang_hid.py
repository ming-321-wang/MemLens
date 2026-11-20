# -*- coding: utf-8 -*-
r"""
2025 平航杯 · USBPcap 键盘还原（自实现，不依赖 Wireshark）

## 设备判定

USBPcap 抓包里有几路流量，靠 (bus, dev, endpoint, transfer, dataLen) 区分：

    bus=2 dev=3 ep=0x81 xfer=1 dlen=7    → 鼠标（报告 7 字节，含按键/位移）
    bus=2 dev=4 ep=0x81 xfer=1 dlen=37   → **复合 HID，键盘**（见下）
    bus=2 dev=4 ep=0x00 xfer=2 dlen=10   → 键盘 LED 输出报告

## 键盘报告布局（实测反推）

37 字节的输入报告里，第 0 个字节是 **Report ID = 0x01**，
其后 8 字节才是标准 boot 协议的键盘报告：

    [0]      Report ID (0x01)
    [1]      修饰键位图（bit1=左Shift, bit5=右Shift …）
    [2]      保留
    [3..8]   6 个按键码（HID Usage ID）

按这个布局解出来的字符可读；按 [0]=修饰 解出来全是乱码 ——
一开始就是踩了这个偏移的坑。

## 为什么不能只看按键码

真实输入里包含**退格**（<DEL>）与**回车**（<RET>），还有打错再删掉重打的情况。
所以必须先按时间序把「键序列」还原出来，再看哪里被删掉——
这正是本题"真名"能从 `wwang qi zhao` + 4 个退格 + `qi zao wang` 推出来的原因。
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.pinghang_traffic import parse_pcapng          # noqa: E402

P = Path(r"D:\MemLens\work\pinghang")
USB = P / "USBPcap"

#: HID Usage ID → 字符（第 7 章 Keyboard/Keypad 页）
NORMAL = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
    0x0A: 'g', 0x0B: 'h', 0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
    0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
    0x1C: 'y', 0x1D: 'z',
    0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6',
    0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n', 0x29: '\x1b', 0x2A: '\b', 0x2B: '\t', 0x2C: ' ',
    0x2D: '-', 0x2E: '=', 0x2F: '[', 0x30: ']', 0x31: '\\',
    0x32: '#', 0x33: ';', 0x34: "'", 0x35: '`', 0x36: ',',
    0x37: '.', 0x38: '/', 0x39: 'CapsLock',
    0x4F: '\x1b[ C', 0x50: '\x1b[ D', 0x51: '\x1b[ B', 0x52: '\x1b[ A',
}

SHIFTED = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^',
    '7': '&', '8': '*', '9': '(', '0': ')', '-': '_', '=': '+',
    '[': '{', ']': '}', '\\': '|', ';': ':', "'": '"', '`': '~',
    ',': '<', '.': '>', '/': '?',
}

SHIFT_MASK = 0x22          # 左 Shift(0x02) | 右 Shift(0x20)


def packets():
    secs, ifaces, pkts = parse_pcapng(USB)
    out = []
    for pk in pkts:
        d = pk["data"]
        if len(d) < 28:
            continue
        hlen = struct.unpack_from("<H", d, 0)[0]
        status = struct.unpack_from("<I", d, 10)[0]
        bus, dev = struct.unpack_from("<HH", d, 17)
        ep = d[21]
        xfer = d[22]
        dlen = struct.unpack_from("<I", d, 23)[0]
        out.append({"ts": pk["ts_raw"], "status": status, "bus": bus,
                    "dev": dev, "ep": ep, "xfer": xfer, "dlen": dlen,
                    "payload": d[hlen:hlen + dlen]})
    out.sort(key=lambda r: r["ts"])
    return out


def decode(pkts) -> tuple[str, list[dict]]:
    """还原键盘输入文本 + 完整事件序列。"""
    text: list[str] = []
    events: list[dict] = []
    prev: tuple | None = None
    for p in pkts:
        if p["status"] != 0 or p["xfer"] != 1 or not (p["ep"] & 0x80):
            continue
        pl = p["payload"]
        # 键盘报告：37 字节且首字节为 Report ID 0x01
        if len(pl) < 10 or pl[0] != 0x01:
            continue
        mod = pl[1]
        keys = [k for k in pl[3:9] if k]
        sig = (mod, tuple(keys))
        if sig == prev:
            continue
        prev = sig
        for k in keys:
            ch = NORMAL.get(k)
            if ch is None:
                events.append({"ts": p["ts"], "raw": k, "ch": ""})
                continue
            if mod & SHIFT_MASK:
                ch = SHIFTED.get(ch, ch.upper() if ch.isalpha() else ch)
            # 退格要作用到已输出文本上
            if ch == '\b':
                if text:
                    text.pop()
                events.append({"ts": p["ts"], "raw": k, "ch": "<DEL>"})
                continue
            if ch == '\n':
                events.append({"ts": p["ts"], "raw": k, "ch": "<RET>"})
                text.append('\n')
                continue
            if ch == ' ':
                events.append({"ts": p["ts"], "raw": k, "ch": "<SPACE>"})
                text.append(' ')
                continue
            # ★ CapsLock / 方向键等**不产生字符**的键要跳过，
            #   否则会把 "CapsLock" 这串字面量塞进还原文本里，
            #   把 abcdefghijkImn 变成 abcdefghijkCapsLockiCapsLockmn（实测踩过）。
            if ch in ("CapsLock",) or ch.startswith('\x1b['):
                events.append({"ts": p["ts"], "raw": k, "ch": ""})
                continue
            events.append({"ts": p["ts"], "raw": k, "ch": ch})
            text.append(ch)
    return "".join(text), events


def answer(pkts, text, events) -> None:
    """按题号输出流量分析 06–09 的答案与依据。"""
    print("\n" + "=" * 76)
    print("流量分析 06–09 逐题作答")
    print("=" * 76)

    # 06 真名：找 "zhao"/"wang" 附近，以及被退格修正的片段
    print("\n06 起早王的真名")
    hit = ""
    for kw in ("qi zao wang", "qi\x08", "zao wang"):
        i = text.find(kw)
        if i >= 0:
            hit = text[max(0, i - 30):i + 30]
            break
    # 退格事件定位
    del_idx = [i for i, e in enumerate(events) if e["ch"] == "<DEL>"]
    ctx = ""
    if del_idx:
        a = max(0, del_idx[0] - 14)
        b = min(len(events), del_idx[-1] + 8)
        ctx = "".join(e["ch"] if len(e["ch"]) == 1 else f"<{e['ch'].strip('<>')}>"
                      for e in events[a:b])
    print(f"    含拼音片段: {hit!r}")
    print(f"    退格段还原: {ctx!r}")
    print("    ⇒ 先打 wwang qi zhao，退格 4 次删掉 zhao，再打 qi zao wang")
    print("    ⇒ 真名：wang qi zhao（王启昭）")

    # 07 命令条数
    print("\n07 起早王对倩倩电脑执行的 cmd 命令条数")
    i = text.find("cmd")
    seg = text[i + 3:] if i >= 0 else ""
    cmds = [ln.strip() for ln in seg.split("\n") if ln.strip()]
    cmds = [c for c in cmds if any(k in c.lower() for k in
                                  ("whoami", "net ", "rundll32"))]
    for n, c in enumerate(cmds, 1):
        print(f"    {n}. {c}")
    print(f"    ⇒ 共 {len(cmds)} 条")

    # 08 影子账户
    print("\n08 影子账户（账户名 / 密码）")
    import re
    m = re.search(r"net user\s+(\S+)\s+(\S+)\s+/add", text)
    if m:
        print(f"    ⇒ 账户名：{m.group(1)}")
        print(f"    ⇒ 密码　：{m.group(2)}")

    # 09 最后一条
    print("\n09 最后一条命令")
    if cmds:
        print(f"    ⇒ {cmds[-1]}")


def main() -> int:
    pkts = packets()
    text, events = decode(pkts)
    print(f"USBPcap 包 {len(pkts):,}   解析出按键事件 {len(events):,}")
    print("\n" + "=" * 76)
    print("还原文本")
    print("=" * 76)
    print(text)
    print("\n" + "=" * 76)
    print("关键片段")
    print("=" * 76)
    for kw in ("net user", "qianqianwoaini", "rundll32", "whoami",
               "localgroup", "/add", "/del"):
        i = text.find(kw)
        if i >= 0:
            print(f"\n  [{kw}] @ {i}")
            print("   ", repr(text[max(0, i - 40):i + 120]))
    answer(pkts, text, events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
