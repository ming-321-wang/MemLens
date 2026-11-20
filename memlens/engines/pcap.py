"""
MemLens · 网络流量包分析（pcap / pcapng）

覆盖用户需求清单中的"流量包"。这是**轻量级**分析器：不依赖 scapy/dpkt，
只解析经典 pcap 与 pcapng 的帧结构，直接给出应急/CTF 场景最需要的几类信息：

  1. 全局头：版本、snaplen、linktype
  2. 会话与端点：Top 通信对、Top 外部 IP、端口分布
  3. 协议分布：EtherType / IP 协议 / TCP 标志
  4. DNS：查询名 Top N（C2 域名/恶意域名线索）
  5. HTTP：Host / User-Agent / URI Top N（明文凭据与攻击痕迹）
  6. 可疑特征：ICMP 隧道、大包、异常端口、明文 flag 模式

设计取舍：
  * 只解析到"能回答 CTF/应急问题"的深度，不做全协议重组（那需要 tshark/scapy）；
  * 大文件用逐帧流式解析，内存占用恒定；
  * 结果全部进 records，与其它域共用检测/报告链路。
"""

from __future__ import annotations

import struct
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

MAX_PACKETS = 2_000_000          # 保护性上限

LINKTYPE_HF = {                  # linktype -> 每帧前导长度（0 表示无）
    0: 4,    # NULL/loopback：4 字节 AF 值
    1: 14,   # Ethernet：14 字节
    12: 0,   # RAW IP
    101: 0,  # RAW IP
    113: 16,  # LINUX_SLL
    276: 20,  # LINUX_SLL2
}

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "VLAN"}
IP_PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE", 50: "ESP", 132: "SCTP"}
TCP_FLAGS = {0x02: "SYN", 0x10: "ACK", 0x08: "PSH", 0x04: "RST", 0x01: "FIN",
             0x20: "URG", 0x40: "ECE", 0x80: "CWR"}

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NETBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MYSQL", 3389: "RDP",
    5432: "POSTGRES", 5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT",
    9200: "ELASTIC", 27017: "MONGODB",
}

# CTF/应急常见 flag 形态（与 QuickCheck 保持一致的思路）
FLAG_PATTERNS = [
    b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"solarsec{", b"qsnctf{",
    b"palu{", b"666c6167", b"ZmxhZ",
]


def _ipv4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def parse_pcap(path: str, max_packets: int = MAX_PACKETS) -> dict[str, Any]:
    """解析经典 pcap，返回统计摘要 + 明细列表。"""
    size = Path(path).stat().st_size
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return {"error": "文件不足 24 字节（非法 pcap）"}
        magic = head[:4]
        endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
        vmaj, vmin = struct.unpack_from(endian + "HH", head, 4)
        snaplen, network = struct.unpack_from(endian + "II", head, 16)
        tsdiv = 1_000_000_000 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1_000_000

        stats: dict[str, Any] = {
            "format": "pcap",
            "version": f"{vmaj}.{vmin}",
            "snaplen": snaplen,
            "linktype": network,
            "file_size": size,
            "packets": 0,
            "bytes": 0,
            "first_ts": None,
            "last_ts": None,
            "err_proto": Counter(),
            "ip_proto": Counter(),
            "tcp_flag": Counter(),
            "conv": Counter(),
            "ext_ip": Counter(),
            "ports": Counter(),
            "dns_q": Counter(),
            "http_host": Counter(),
            "http_ua": Counter(),
            "http_uri": Counter(),
            "flag_hits": [],
            "streams": {},          # TCP 流还原：双向键 -> payload 缓冲（每流 ≤16KB）
            "big_pkts": [],
            "truncated": 0,
            "errors": 0,
        }
        # linktype → 是否已由下方分支处理（预剥离不再使用，避免二次错位）
        i = 0
        while i < max_packets:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_s, ts_u, incl, orig = struct.unpack(endian + "IIII", ph)
            if incl > snaplen + 65535 or orig > snaplen + 65535 or incl > 262144:
                stats["errors"] += 1
                break
            data = f.read(incl)
            if len(data) < incl:
                stats["truncated"] += 1
                break
            ts = ts_s + ts_u / tsdiv
            if stats["first_ts"] is None:
                stats["first_ts"] = ts
            stats["last_ts"] = ts
            stats["packets"] = i + 1
            stats["bytes"] += orig
            if len(data) >= 40 * 1024:
                stats["big_pkts"].append((ts, orig))

            body = data
            # ---- 链路层：按 linktype 剥离前置头（**不要**先统一剥，否则会二次错位）----
            if network == 0:                      # NULL/loopback：4 字节 AF 值
                if len(body) >= 4:
                    af = struct.unpack("<I", body[:4])[0]
                    body = body[4:]
            elif network == 1:                    # Ethernet：14 字节
                if len(body) >= 14:
                    et = struct.unpack(">H", body[12:14])[0]
                    stats["err_proto"][ETHERTYPES.get(et, f"0x{et:04x}")] += 1
                    if et == 0x8100 and len(body) >= 18:   # VLAN：协议再往后 4 字节
                        et = struct.unpack(">H", body[16:18])[0]
                        body = body[4:]
                    body = body[14:]
                else:
                    i += 1
                    continue
            elif network == 113:                  # LINUX_SLL：16 字节，协议在偏移 14
                if len(body) >= 16:
                    et = struct.unpack(">H", body[14:16])[0]
                    stats["err_proto"][ETHERTYPES.get(et, f"0x{et:04x}")] += 1
                    body = body[16:]
                else:
                    i += 1
                    continue
            elif network == 276:                  # LINUX_SLL2：20 字节，协议在偏移 0
                if len(body) >= 20:
                    et = struct.unpack(">H", body[0:2])[0]
                    stats["err_proto"][ETHERTYPES.get(et, f"0x{et:04x}")] += 1
                    body = body[20:]
                else:
                    i += 1
                    continue
            elif network in (12, 101):            # RAW IP：无前置头
                if len(body) >= 20:
                    ver = body[0] >> 4
                    et = 0x0800 if ver == 4 else (0x86DD if ver == 6 else 0)
                    stats["err_proto"][ETHERTYPES.get(et, f"0x{et:04x}")] += 1
            # IPv4
            if len(body) >= 20 and (body[0] >> 4) == 4:
                ihl = (body[0] & 0x0F) * 4
                total_len = struct.unpack(">H", body[2:4])[0]
                proto = body[9]
                src = _ipv4(body[12:16])
                dst = _ipv4(body[16:20])
                stats["ip_proto"][IP_PROTOS.get(proto, str(proto))] += 1
                stats["conv"][f"{src} → {dst}"] += 1
                stats["ext_ip"][dst] += 1
                l4 = body[ihl:total_len] if total_len and total_len <= len(body) else body[ihl:]
                if proto == 6 and len(l4) >= 20:
                    sport, dport = struct.unpack(">HH", l4[:4])
                    doff = (l4[12] >> 4) * 4
                    flags = l4[13]
                    stats["ports"][f"{dport}/{COMMON_PORTS.get(dport,'')}"] += 1
                    fl = [v for k, v in TCP_FLAGS.items() if flags & k]
                    if fl:
                        stats["tcp_flag"]["+".join(fl)] += 1
                    # TCP 流 payload 收集（双向合并；每流 ≤16KB，流数 ≤5000 防爆）
                    if doff <= len(l4) and len(stats["streams"]) < 5000:
                        payload = l4[doff:]
                        if payload:
                            a, b = sorted([f"{src}:{sport}", f"{dst}:{dport}"])
                            sk = f"{a}⇄{b}"
                            buf = stats["streams"].setdefault(sk, bytearray())
                            if len(buf) < 16384:
                                buf += payload[:16384 - len(buf)]
                    if dport == 80 or sport == 80:
                        payload = l4[doff:]
                        _http_stats(payload, stats)
                elif proto == 17 and len(l4) >= 8:
                    sport, dport = struct.unpack(">HH", l4[:4])
                    stats["ports"][f"{dport}/{COMMON_PORTS.get(dport,'')}"] += 1
                    if dport == 53 or sport == 53:
                        _dns_stats(l4[8:], stats)
            # flag 模式扫描（只扫前 200 字节，控制开销；按片段去重）
            snippet = data[:200]
            for pat in FLAG_PATTERNS:
                idx = snippet.find(pat)
                if idx < 0:
                    continue
                frag = snippet[idx:idx + 80].split(b"\x00")[0]
                key = frag[:60]
                if any(h["fragment"] == key.decode("latin1", "replace")
                       for h in stats["flag_hits"]):
                    continue
                stats["flag_hits"].append({
                    "ts": round(ts, 3),
                    "pattern": pat.decode("latin1"),
                    "fragment": key.decode("latin1", "replace"),
                })
            i += 1
    return stats


def _dns_stats(p: bytes, stats: dict) -> None:
    if not p or p[:3] not in (b"GET", b"POS", b"PUT", b"HEA", b"DEL", b"OPT", b"TRA", b"PAT"):
        return
    try:
        text = p.split(b"\r\n\r\n")[0].decode("latin1", "replace")
    except Exception:
        return
    lines = text.split("\r\n")
    if lines and lines[0]:
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            stats["http_uri"][parts[1][:120]] += 1
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith("host:"):
            stats["http_host"][ln.split(":", 1)[1].strip()[:120]] += 1
        elif low.startswith("user-agent:"):
            stats["http_ua"][ln.split(":", 1)[1].strip()[:150]] += 1


def _dns_names(p: bytes, stats: dict) -> None:
    """极简 DNS 解析：跳过 12 字节头部，按 label 长度读查询名。"""
    if len(p) < 13:
        return
    labels = []
    i = 12
    while i < len(p):
        l = p[i]
        if l == 0:
            break
        if l >= 64 or i + 1 + l > len(p):
            break
        labels.append(p[i + 1:i + 1 + l])
        i += 1 + l
    if labels:
        name = b".".join(labels).decode("latin1", "replace")
        if name and len(name) > 3:
            stats["dns_q"][name[:150]] += 1


def _dns_stats(p: bytes, stats: dict) -> None:
    _dns_names(p, stats)


def parse_pcapng(path: str, max_packets: int = MAX_PACKETS) -> dict[str, Any]:
    """
    pcapng 解析（当前只做**块级统计**：块类型/数量/接口数）。

    说明：完整 pcapng 报文解析需要处理 EPB/SPB/PB/ISB 多代格式与接口链路类型映射，
    本期先给出"文件是否合法 + 块构成 + 是否有 Simple Packet Block"这些判据；
    需要逐包内容时建议导出为经典 pcap 再走 parse_pcap()。
    """
    blocks = Counter()
    ifaces = 0
    epb = 0
    with open(path, "rb") as f:
        pos = 0
        size = Path(path).stat().st_size
        while pos + 12 <= size:
            f.seek(pos)
            hdr = f.read(12)
            if len(hdr) < 12:
                break
            btype, blen = struct.unpack_from("<II", hdr, 0)
            if blen < 12 or pos + blen > size:
                blocks[f"非法块(0x{btype:08x},len={blen})"] += 1
                break
            blocks[f"0x{btype:08x}"] += 1
            if btype == 0x00000001:            # IDB
                ifaces += 1
            elif btype == 0x00000006:          # EPB
                epb += 1
            pos += blen
    return {
        "format": "pcapng",
        "file_size": Path(path).stat().st_size,
        "interfaces": ifaces,
        "enhanced_packet_blocks": epb,
        "block_types": dict(blocks),
        "note": "pcapng 本期只做块级统计；逐包分析请转经典 pcap",
    }


def top(c: Counter, n: int = 10) -> list[tuple[str, int]]:
    return c.most_common(n)


def _stream_text(payload: bytes) -> str:
    """从流 payload 提取可打印 ASCII/UTF-8 连续文本（最长 80 字符）。"""
    try:
        t = payload.decode("utf-8", "replace")
    except Exception:
        t = payload.decode("latin1", "replace")
    run = ""
    best = ""
    for ch in t:
        if 32 <= ord(ch) < 127 or ch in "\r\n\t":
            run += ch
            if len(run) > len(best):
                best = run
        else:
            run = ""
    return best.strip()[:80]


def _find_flag_in(payload: bytes) -> str:
    """在流 payload 里找完整 flag（flag{...} 等，可能跨包拼接）。"""
    for pat in FLAG_PATTERNS:
        i = payload.find(pat)
        if i >= 0:
            seg = payload[i:]
            j = seg.find(b"}")
            if j > 0:
                return seg[:j + 1].decode("latin1", "replace")
    return ""


def analyze_pcap(path: str, max_packets: int = MAX_PACKETS) -> Iterator[dict[str, Any]]:
    """把 pcap 统计摊平成 records（统一 schema：文件/类别/项/值/说明）。

    统一 5 字段可让前端按相同列渲染所有行，不再出现"只有概要、明细被吞"。
    额外做 TCP 流内容还原（双向合并 payload，还原完整 flag / 可打印文本）。
    """
    with open(path, "rb") as f:
        magic = f.read(4)
    name = Path(path).name

    def row(cat: str, item: str, val: Any, note: str = "") -> dict[str, Any]:
        return {"文件": name, "类别": cat, "项": item, "值": str(val), "说明": str(note)}

    if magic == b"\x0a\x0d\x0d\x0a":
        st = parse_pcapng(path)
        yield row("概要", "pcapng 概要",
                  f"接口 {st['interfaces']} · EPB {st['enhanced_packet_blocks']}",
                  st["note"])
        return

    st = parse_pcap(path, max_packets)
    if "error" in st:
        yield row("概要", "解析", st["error"])
        return

    # 概要
    yield row("概要", "pcap 概要",
              f"版本 {st['version']} · {st['packets']} 包 · {st['bytes']} B",
              f"snaplen {st['snaplen']} · linktype {st['linktype']} · "
              f"首包 {round(st['first_ts'] or 0, 3)} · 末包 {round(st['last_ts'] or 0, 3)} · "
              f"截断 {st['truncated']} · 错误 {st['errors']}")

    # 协议（逐项一行）
    for k, v in top(st["err_proto"]):
        yield row("协议", "链路层", k, f"{v} 包")
    for k, v in top(st["ip_proto"]):
        yield row("协议", "IP 协议", k, f"{v} 包")
    for k, v in top(st["tcp_flag"]):
        yield row("协议", "TCP 标志", k, f"{v} 包")

    # 会话 / 主机（逐行）
    for k, v in top(st["conv"]):
        yield row("会话", "会话", k, f"{v} 包")
    for k, v in top(st["ext_ip"]):
        yield row("主机", "目的 IP", k, f"{v} 包")

    # 端口（逐行，带服务名）
    for k, v in top(st["ports"]):
        parts = k.split("/", 1) + [""]
        port, svc = parts[0], (parts[1] if len(parts) > 1 else "")
        yield row("端口", "端口", port or k, f"{v} 包 · 服务 {svc or '?'}")

    # DNS / HTTP（逐行）
    for k, v in top(st["dns_q"]):
        yield row("DNS", "DNS 查询", k, f"{v} 次")
    for k, v in top(st["http_host"]):
        yield row("HTTP", "HTTP Host", k, f"{v} 次")
    for k, v in top(st["http_ua"]):
        yield row("HTTP", "User-Agent", k, f"{v} 次")
    for k, v in top(st["http_uri"]):
        yield row("HTTP", "HTTP 请求", k, f"{v} 次")

    # TCP 流内容还原（双向合并，找完整 flag / 可打印文本）
    for sk, payload in st.get("streams", {}).items():
        flag = _find_flag_in(bytes(payload))
        note = f"{len(payload)}B"
        if flag:
            note += f" · flag: {flag}"
        else:
            txt = _stream_text(bytes(payload))
            if txt:
                note += f" · 文本: {txt}"
        yield row("流", "TCP 流", sk, note)

    # flag 特征（原始扫描，保留）
    for h in st["flag_hits"][:20]:
        yield row("flag", "flag 特征", h["fragment"],
                  f"模式 {h['pattern']} @ {h['ts']}")

    if st["big_pkts"]:
        yield row("概要", "超大包(>40KB)", f"{len(st['big_pkts'])} 个",
                  ", ".join(f"{round(t,1)}s/{n}B" for t, n in st["big_pkts"][:5]))
