# -*- coding: utf-8 -*-
r"""
2025 平航杯 · 流量分析 02–04 定向取证（伪装耳机时间线）

判定思路：
    倩倩的真耳机与起早王的伪装设备会广播**同一个名称** `LE-YANG QC35 II`，
    所以「哪个地址是真、哪个是假」只能靠**时间线**判：

      · 全程连续出现、包数多、名称稳定 → 真耳机
      · 中途才出现、名称从别的值"变成"耳机名、且地址与真耳机不同 → 伪装设备

    题目问"原始设备名称"，就是伪装设备**改名成耳机之前**用的那个名字。
    因此必须按包序取该地址的**首个非空名称**，而不是取出现次数最多的名称。
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.pinghang_traffic import parse_pcapng, parse_ad          # noqa: E402
from tools.pinghang_ble import parse_nordic, ts_to_utc            # noqa: E402

P = Path(r"D:\MemLens\work\pinghang")
TARGET_NAME = "LE-YANG QC35 II"


def load():
    secs, ifaces, pkts = parse_pcapng(P / "BLE")
    tsres = ifaces[0]["options"].get(9, "")
    rows = []
    for pk in pkts:
        b = parse_nordic(pk["data"])
        if not b:
            continue
        b["ts_raw"] = pk["ts_raw"]
        b["ts"] = ts_to_utc(pk["ts_raw"], tsres)
        b["ad"] = parse_ad(b.get("adv_data") or b"")
        rows.append(b)
    rows.sort(key=lambda r: r["ts_raw"])
    return rows


def name_of(ad) -> str:
    for t, v in ad:
        if t in (0x08, 0x09):
            try:
                s = v.decode("utf-8")
            except UnicodeDecodeError:
                return ""
            # 只接受可打印 ASCII，过滤解析错位产生的乱码
            if s and all(32 <= ord(c) < 127 for c in s):
                return s
    return ""


def main() -> int:
    rows = load()
    print(f"总包数 {len(rows):,}")

    # 每个地址：首末时间、包数、名称序列
    per: dict[str, dict] = defaultdict(lambda: {
        "n": 0, "first_ts": None, "first_raw": None, "last_ts": None,
        "names": [], "pdu": set(),
    })
    for r in rows:
        a = r.get("addr") or ""
        if not a:
            continue
        d = per[a]
        d["n"] += 1
        if d["first_raw"] is None:
            d["first_raw"] = r["ts_raw"]
            d["first_ts"] = r["ts"]
        d["last_ts"] = r["ts"]
        d["pdu"].add(r.get("pdu", ""))
        nm = name_of(r["ad"])
        if nm and (not d["names"] or d["names"][-1][1] != nm):
            d["names"].append((r["ts"], nm))

    print("\n" + "=" * 78)
    print(f"广播名称为 {TARGET_NAME!r} 的地址")
    print("=" * 78)
    hits = [(a, d) for a, d in per.items()
            if any(n == TARGET_NAME for _, n in d["names"])]
    hits.sort(key=lambda kv: kv[1]["first_raw"])
    for a, d in hits:
        first_name = d["names"][0][1] if d["names"] else "(无)"
        print(f"\n  地址 {a}")
        print(f"    包数 {d['n']:>5}   首次出现 {d['first_ts']} UTC")
        print(f"    最后出现 {d['last_ts']} UTC")
        print(f"    ★ 该地址的**首个名称** = {first_name!r}")
        print(f"    名称变化前 6 次:")
        for ts, nm in d["names"][:6]:
            print(f"        {ts}  {nm!r}")
        if len(d["names"]) > 6:
            print(f"        …… 共 {len(d['names'])} 次变化")

    print("\n" + "=" * 78)
    print("结论判定")
    print("=" * 78)
    if len(hits) >= 2:
        real, fake = hits[0], hits[1]
        print(f"  真耳机（先出现、全程在线）: {real[0]}  首现 {real[1]['first_ts']}")
        print(f"  伪装设备（后出现、中途改名）: {fake[0]}  首现 {fake[1]['first_ts']}")
        print(f"\n  02 原始设备名称 : {fake[1]['names'][0][1]!r}")
        print(f"  03 改名前后 MAC : {fake[0]}   ← 它一直说自己叫 {TARGET_NAME!r}")
        print(f"                     （与真耳机 {real[0]} 地址不同，是两台设备）")
        for ts, nm in fake[1]["names"]:
            if nm == TARGET_NAME:
                print(f"  04 首次自称耳机名的 UTC+0 时间 : {ts}")
                break

    # 附：所有出现过"设备名"的地址（过滤乱码后）
    print("\n" + "=" * 78)
    print("全部可读设备名（按包数）")
    print("=" * 78)
    named = [(a, d) for a, d in per.items() if d["names"]]
    for a, d in sorted(named, key=lambda kv: -kv[1]["n"])[:20]:
        uniq = []
        for _, n in d["names"]:
            if n not in uniq:
                uniq.append(n)
        print(f"  {a}  包 {d['n']:>5}  名称 {uniq[:4]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
