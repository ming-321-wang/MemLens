r"""
MemLens v1.3 合规基座专项测试（方案对照）

覆盖五项基座：
    ① UTC 归一（时间基准 / 偏移量留存 / 换算留痕）
    ② 中间证据表五必填字段（证据编号 / 发生时间 / 来源偏移 / 原始值哈希 / 通道）
    ③ 规则包（外置阈值 / 版本 / 离线导入 / 回滚 / 校验）
    ④ 审计与保管链（五字段 + 哈希链 + 篡改可检出）
    ⑤ 缺口清单（结构化 / 同根因合并 / 建议补证）

运行：`.venv\Scripts\python.exe tools\test_compliance_base.py`
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASSED = 0
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASSED
    if ok:
        PASSED += 1
        print(f"✅ {name}")
    else:
        FAILED.append(name)
        print(f"❌ {name}　{detail}")


# ══════════════════════════════════════════════════════════════════════
# ① UTC 归一
# ══════════════════════════════════════════════════════════════════════
def test_timebase() -> None:
    from memlens.core import timebase as tb

    print("\n── ① UTC 归一与时间基准 ──")

    # 朴素时间按作业机本地时区处理，且**假设被记录**
    tv = tb.normalize("2026-03-01 10:00:00")
    check("朴素时间可解析", tv.ok, tv.note)
    check("朴素时间带假设标记", tv.assumption == "local", tv.assumption)
    check("朴素时间留痕非空", bool(tv.note), tv.note)

    # ★ 关键回归：日期里的 "-03" 不能被当成时区偏移
    check("日期分隔符不被误判为偏移", tv.assumption == "local", f"got {tv.assumption}")

    # 显式偏移
    tv2 = tb.normalize("2026-03-01T10:00:00+08:00")
    check("显式偏移可解析", tv2.ok)
    check("显式偏移量正确", tv2.offset == 28800, str(tv2.offset))
    check("显式偏移假设正确", tv2.assumption == "explicit_offset", tv2.assumption)

    # UTC 标记
    tv3 = tb.normalize("2026-03-01 10:00:00 UTC")
    check("UTC 名称可解析", tv3.ok and tv3.offset == 0, f"{tv3.offset}")

    # Z 后缀
    tv4 = tb.normalize("2026-03-01T10:00:00Z")
    check("Z 后缀可解析", tv4.ok and tv4.offset == 0, f"{tv4.offset}")

    # Unix 时间戳
    tv5 = tb.normalize(1780000000)
    check("Unix 秒可解析", tv5.ok and tv5.assumption == "epoch_known", tv5.assumption)

    # FILETIME
    tv6 = tb.normalize(133000000000000000)
    check("FILETIME 可解析", tv6.ok, tv6.note)

    # 纪元必须显式声明（浏览器 1601 纪元）
    tv7 = tb.normalize(13300000000000000, epoch="webkit")
    check("WebKit 纪元显式声明生效", tv7.ok and "1601" in tv7.note, tv7.note)

    # 无法解析时不猜
    tv8 = tb.normalize("下周三下午")
    check("无法解析时返回空而非猜测", not tv8.ok)

    # 还原本地时间
    utc = tb.from_utc_iso("2026-03-01T02:00:00Z")
    loc = tb.to_local(utc, 28800)
    check("可按偏移还原本地时间", loc == "2026-03-01 10:00:00", loc)

    # 换算留痕
    line = tb.describe_conversion(tv)
    check("换算留痕含原始值与假设", "原始" in line and "假设" in line, line)


def test_timeline_utc() -> None:
    print("\n── ①b 时间线使用 UTC ──")
    from memlens import timeline as tl

    recs = [
        ({"Name": "a.exe", "CreateTime": "2026-03-01 10:00:00"}, "p1"),
        ({"Name": "b.exe", "CreateTime": "2026-03-01 09:00:00"}, "p2"),
        ({"Name": "c.exe", "CreateTime": 1780000000}, "p3"),
    ]
    evs = tl.build_timeline(recs)
    check("时间线产出事件", len(evs) == 3, str(len(evs)))
    check("事件时间为 aware UTC", all(e.ts is not None and e.ts.tzinfo is not None for e in evs))
    check("事件带时区偏移", all(e.tz_offset is not None for e in evs))
    check("事件带换算假设", all(e.tz_assumption for e in evs))
    check("事件带原始表示", all(e.raw_time for e in evs))
    # 排序：09:00 应排在 10:00 之前
    check("按真实时间排序", evs[0].title.endswith("b.exe"), evs[0].title)
    # 本地时间还原
    check("可还原本地时间", evs[0].to_local() != "")
    # 记录里带 UTC 与本地两列
    r = evs[0].to_record()
    for k in ("ts_utc", "ts_local", "ts_raw", "tz_offset", "tz_assumption"):
        check(f"事件记录含 {k}", k in r)


# ══════════════════════════════════════════════════════════════════════
# ② 中间证据表五必填字段
# ══════════════════════════════════════════════════════════════════════
def test_evidence_fields() -> None:
    print("\n── ② 中间证据表五必填字段 ──")
    from memlens.storage.db import extract_common_fields

    rec = {
        "Name": "cmd.exe", "PID": 1234, "PPID": 100,
        "CreateTime": "2026-03-01 10:00:00",
        "offset": "0x1234", "RemoteAddr": "1.2.3.4:80",
    }
    c = extract_common_fields(rec)
    for k in ("ts_utc", "ts_raw", "tz_offset", "tz_assumption",
              "source_offset", "raw_value_hash"):
        check(f"抽取 {k}", c.get(k) not in (None, ""), str(c.get(k)))

    check("来源偏移正确", c["source_offset"] == "0x1234", str(c["source_offset"]))
    check("PID 抽取正确", c["pid"] == 1234, str(c["pid"]))
    check("远端地址抽取正确", c["remote"] == "1.2.3.4:80", str(c["remote"]))

    # 原始值哈希必须**可复现**（同一输入两次相同）
    c2 = extract_common_fields(rec)
    check("原始值哈希可复现", c["raw_value_hash"] == c2["raw_value_hash"])

    # 不同行哈希不同
    rec2 = dict(rec); rec2["Name"] = "powershell.exe"
    c3 = extract_common_fields(rec2)
    check("不同行哈希不同", c["raw_value_hash"] != c3["raw_value_hash"])


# ══════════════════════════════════════════════════════════════════════
# ③ 规则包
# ══════════════════════════════════════════════════════════════════════
def test_rulepack() -> None:
    print("\n── ③ 规则包（外置阈值 / 版本 / 导入 / 回滚 / 校验） ──")
    from memlens.core import rulepack as rp

    work = tempfile.mkdtemp(prefix="ml-rp-")
    mgr = rp.configure(work)

    cur = rp.current()
    check("默认有生效规则包", cur.version != "", cur.version)
    check("默认规则包含阈值", len(cur.thresholds) > 0)
    check("默认规则包含发布日期", bool(cur.published_at), cur.published_at)
    check("默认规则含变更记录", bool(cur.change_log))

    # 缺项回退
    check("缺项回退到默认值", rp.threshold("不存在的键", 0.42) == 0.42)

    # 导入新版本并激活
    pack = rp.default_pack().to_dict()
    pack["version"] = "9.9.9"
    pack["published_at"] = "2026-11-12"
    pack["thresholds"]["hidden_process.w_pool_only"] = 0.81
    pack["change_log"] = "专项测试：调整池扫描基础分"
    pj = Path(work) / "v999.json"
    pj.write_text(json.dumps(pack, ensure_ascii=False), encoding="utf-8")

    mgr.import_pack(pj, activate=True)
    check("导入后版本切换", rp.current().version == "9.9.9", rp.current().version)
    check("导入后阈值生效", rp.threshold("hidden_process.w_pool_only") == 0.81,
          str(rp.threshold("hidden_process.w_pool_only")))

    # 历史版本可回滚
    mgr.rollback("1.0.0")
    check("回滚到基线版本", rp.current().version == "1.0.0", rp.current().version)
    check("回滚后阈值还原", rp.threshold("hidden_process.w_pool_only") == 0.55,
          str(rp.threshold("hidden_process.w_pool_only")))

    # 校验：缺版本号
    try:
        rp.validate({"thresholds": {}})
        check("缺版本号被拒绝", False, "未抛异常")
    except rp.RulePackError:
        check("缺版本号被拒绝", True)

    # 校验：阈值越界
    problems = rp.validate({"version": "1.0", "published_at": "2026-01-01",
                            "thresholds": {"a.b": 99}})
    check("越界阈值被报告", any("超出" in p for p in problems), str(problems))

    # 校验：缺发布日期
    problems2 = rp.validate({"version": "1.0", "thresholds": {}})
    check("缺发布日期被报告", any("published_at" in p for p in problems2), str(problems2))

    # 白名单外置
    check("白名单来自规则包", len(rp.whitelist_list("system_process")) > 0)
    shutil.rmtree(work, ignore_errors=True)


def test_detector_uses_rulepack() -> None:
    print("\n── ③b 检测器走规则包取阈值 ──")
    from memlens.core import rulepack as rp
    from memlens.detectors import base as det_base

    work = tempfile.mkdtemp(prefix="ml-rpd-")
    rp.configure(work)
    base_w = rp.threshold("hidden_process.w_pool_only")
    check("检测器基线阈值可取", base_w == 0.55, str(base_w))

    # 改规则包 → 检测器跟着变
    pack = rp.default_pack().to_dict()
    pack["version"] = "9.9.9"
    pack["published_at"] = "2026-11-12"
    pack["thresholds"]["hidden_process.w_pool_only"] = 0.88
    pj = Path(work) / "v.json"
    pj.write_text(json.dumps(pack, ensure_ascii=False), encoding="utf-8")
    rp.manager().import_pack(pj, activate=True)

    from memlens.detectors import hidden_process as hp
    check("检测器读取新阈值", hp._T("hidden_process.w_pool_only", 0.55) == 0.88,
          str(hp._T("hidden_process.w_pool_only", 0.55)))

    # 白名单外置
    check("白名单可由规则包提供", len(det_base.system_whitelist()) > 0)
    check("白名单命中判定有效", det_base.is_whitelisted("svchost.exe"))
    shutil.rmtree(work, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# ④ 审计与保管链
# ══════════════════════════════════════════════════════════════════════
def test_audit() -> None:
    print("\n── ④ 审计与保管链 ──")
    from memlens.storage.db import DataStore

    work = tempfile.mkdtemp(prefix="ml-au-")
    s = DataStore(Path(work) / "t.db")
    cid = s.create_case("t", r"D:\MemLens\samples\synthetic_windows.raw")

    r1 = s.add_audit(actor="u1", action="open", target="a", case_id=cid)
    r2 = s.add_audit(actor="u1", action="analyze", target="b", case_id=cid, critical=True)
    check("审计写入成功", bool(r1.get("entry_hash")) and bool(r2.get("entry_hash")))
    check("第二条链上前一条哈希", r2["prev_hash"] == r1["entry_hash"],
          f"{r2['prev_hash'][:12]} vs {r1['entry_hash'][:12]}")

    res = s.verify_audit_chain()
    check("哈希链校验通过", res["ok"], res["detail"])

    # 五字段齐全
    rows = s.list_audit(case_id=cid)
    check("审计五字段齐全", all(r.get("actor") and r.get("action") and r.get("target")
                                and r.get("ts_utc") and r.get("entry_hash") for r in rows))
    check("重点操作被单独标记", any(r.get("critical") for r in rows))

    # ★ 篡改检测
    from sqlalchemy import update
    from memlens.storage import models as M
    with s.engine.begin() as conn:
        conn.execute(update(M.audit_log)
                     .where(M.audit_log.c.audit_id == r1["audit_id"])
                     .values(target="被改过的目标"))
    res2 = s.verify_audit_chain()
    check("篡改后可检出", not res2["ok"], res2["detail"])
    check("断链位置正确", res2["broken_at"] == r1["audit_id"], str(res2["broken_at"]))

    s.close()
    shutil.rmtree(work, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# ⑤ 缺口清单
# ══════════════════════════════════════════════════════════════════════
def test_gaps() -> None:
    print("\n── ⑤ 缺口清单 ──")
    from memlens.storage.db import DataStore
    from memlens.pipeline.deep import _add_gap, _gap_key, _suggest_for

    work = tempfile.mkdtemp(prefix="ml-gap-")
    s = DataStore(Path(work) / "t.db")
    cid = s.create_case("t", r"D:\MemLens\samples\synthetic_windows.raw")

    n = s.add_gaps(cid, [
        {"scope": "dimension", "dimension": "FR-03", "reason": "缺预取文件",
         "impact": "downgrade", "level_cap": "B", "suggestion": "从磁盘侧补"},
        {"scope": "source", "dimension": "pslist", "reason": "符号表缺失",
         "impact": "blocked", "suggestion": "预置 ISF"},
    ])
    check("缺口入库", n == 2, str(n))
    rows = s.list_gaps(cid)
    check("缺口字段齐全", all(r.get("dimension") and r.get("reason") and r.get("suggestion")
                              for r in rows))
    check("缺口可按维度过滤", len(s.list_gaps(cid, dimension="FR-03")) == 1)

    # 同根因合并
    g: list[dict] = []
    _add_gap(g, {"scope": "source", "dimension": "a",
                 "reason": "引擎返回码 1；stderr 末尾：layer_name Progress: 12.30"})
    _add_gap(g, {"scope": "source", "dimension": "b",
                 "reason": "引擎返回码 1；stderr 末尾：layer_name Progress: 45.60"})
    check("同根因合并为一条", len(g) == 1, str(len(g)))
    check("合并后记录受影响数", g[0].get("affected") == 2, str(g[0].get("affected")))

    # 进度噪音归一化
    check("进度噪音被归一", _gap_key("x Progress: 12.3 y") == _gap_key("x Progress: 45.6 y"),
          f"{_gap_key('x Progress: 12.3 y')} vs {_gap_key('x Progress: 45.6 y')}")

    # 建议补证映射
    check("符号表失败有对应建议",
          "符号表" in _suggest_for("symbol table requirement was not fulfilled"),
          _suggest_for("symbol table requirement was not fulfilled"))
    check("MemProcFS 打不开有对应建议",
          "MemProcFS" in _suggest_for("DEVICE: ERROR: Failed opening file"),
          _suggest_for("DEVICE: ERROR: Failed opening file"))

    s.close()
    shutil.rmtree(work, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# ⑥ 报告要件
# ══════════════════════════════════════════════════════════════════════
def test_report_requirements() -> None:
    print("\n── ⑥ 报告要件（规则包版本 / 缺口清单 / 免责三句） ──")
    from memlens.storage.db import DataStore
    from memlens import report as rp

    work = tempfile.mkdtemp(prefix="ml-rep-")
    s = DataStore(Path(work) / "t.db")
    cid = s.create_case("t", r"D:\MemLens\samples\synthetic_windows.raw")
    s.add_gaps(cid, [{"scope": "dimension", "dimension": "FR-03", "reason": "缺源",
                      "impact": "downgrade", "suggestion": "补齐"}])

    md = rp.build_markdown(s, cid)
    check("Markdown 含规则包版本", "规则包版本" in md)
    check("Markdown 含缺口清单章节", "缺口清单" in md)
    check("Markdown 含免责三句", "主机侧未发现痕迹，不等于未使用" in md
          and "不建议作为司法鉴定结论使用" in md)
    check("Markdown 含时间基准说明", "协调世界时" in md)

    html = rp.build_html(s, cid)
    check("HTML 含规则包版本", "规则包版本" in html)
    check("HTML 含缺口清单章节", "缺口清单" in html)
    check("HTML 含免责三句", "主机侧未发现痕迹，不等于未使用" in html)

    s.close()
    shutil.rmtree(work, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
def main() -> int:
    print("=" * 66)
    print("MemLens v1.3 合规基座专项测试")
    print("=" * 66)
    test_timebase()
    test_timeline_utc()
    test_evidence_fields()
    test_rulepack()
    test_detector_uses_rulepack()
    test_audit()
    test_gaps()
    test_report_requirements()
    print("\n" + "=" * 66)
    print(f"通过 {PASSED} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败项：")
        for f in FAILED:
            print("  ❌", f)
        return 1
    print("全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
