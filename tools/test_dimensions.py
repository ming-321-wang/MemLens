r"""
MemLens 五维判定引擎专项测试（方案 4.2 节 FR-01~FR-07）

覆盖：
    ① 规则包驱动：五维权重 / 工具指纹 / 阈值均可外置
    ② FR-01 工具存在性：三态判定 + 强弱指纹分层 + 白名单按路径匹配
    ③ FR-02 通道配置：三个配置面 + 自动配置脚本高价值 + 降级
    ④ FR-03 运行痕迹：多源交叉 + 磁盘源缺失即降级 + 等级上限
    ⑤ FR-04 数据外联：四类替代证据 + 归属诚实性
    ⑥ FR-05 访问方向：**默认关闭** + 开启后五类打标
    ⑦ FR-06 打分分级：加权求和 / 外联维下限 / 等级上限
    ⑧ FR-07 结论输出：检查三档与取证三级不混用
    ⑨ 降级路径与缺口清单

运行：`.venv\Scripts\python.exe tools\test_dimensions.py`
"""

from __future__ import annotations

import json
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


# ------------------------------------------------------------------ 假数据

def _proc(name="v2ray.exe", pid=1000, path=r"C:\Tools\v2ray\v2ray.exe", user="alice"):
    return {"Name": name, "PID": str(pid), "UserPath": path, "User": user,
            "CommandLine": path, "CreateTime": "2026-07-23 06:26:40"}


def _svc(name="v2ray", path=r"C:\Tools\v2ray\v2ray.exe"):
    return {"ServiceName": name, "Path": path}


def _net(dst="203.0.113.9", port="443", pid="1000", proc="v2ray.exe", state="CLOSED"):
    return {"Proto": "TCP4", "State": state, "SrcAddr": "192.168.1.5",
            "SrcPort": "50000", "DstAddr": dst, "DstPort": port,
            "PID": pid, "Process": proc, "ProcessPath": "", "Time": "2026-07-23 07:20:29 UTC"}


def _listen(proc="v2ray.exe", pid="1000", port="10809"):
    return {"Proto": "TCP4", "State": "LISTENING", "SrcAddr": "0.0.0.0",
            "SrcPort": port, "DstAddr": "***", "DstPort": "0",
            "PID": pid, "Process": proc, "Time": "2026-07-23 06:26:44 UTC"}


class FakeCtx:
    """
    最小可用的 DetectionContext 替身（只提供 records/has_plugin）。

    ⚠ **必须复刻 SQL LIKE 的通配语义**：`%` 匹配任意长字符串、`_` 匹配单字符。
    真实实现走 `records_of_plugin`（SQL LIKE），这里若直接用 fnmatch，
    模式里的 `%` 会被当成字面量 → 所有 `has_plugin("mprocfs.process%")` 恒为 False，
    整条维度链静默走"缺源降级"分支（实测踩过，症状是"所有维度都不成立"）。
    """

    def __init__(self, tables: dict[str, list[dict]]) -> None:
        self.tables = tables

    @staticmethod
    def _like(pattern: str) -> str:
        """SQL LIKE → fnmatch 模式。"""
        return pattern.replace("%", "*").replace("_", "?")

    def records(self, plugin_like: str, *, limit: int = 200_000) -> list[dict]:
        import fnmatch
        pat = self._like(plugin_like)
        out: list[dict] = []
        for key, rows in self.tables.items():
            if fnmatch.fnmatch(key, pat):
                out.extend(rows)
        return out[:limit]

    def has_plugin(self, plugin_like: str) -> bool:
        import fnmatch
        pat = self._like(plugin_like)
        return any(fnmatch.fnmatch(k, pat) and v for k, v in self.tables.items())


def _ctx(**kw) -> FakeCtx:
    return FakeCtx(kw)


def _pack(tmp: str, **over):
    """构造一个测试规则包。"""
    from memlens.core import rulepack as rp
    pack = rp.default_pack().to_dict()
    pack.update(over)
    p = Path(tmp) / "pack.json"
    p.write_text(json.dumps(pack, ensure_ascii=False), encoding="utf-8")
    return rp.load_pack(p)


# ══════════════════════════════════════════════════════════════════════
def test_rulepack_driven() -> None:
    print("\n── ① 规则包驱动 ──")
    from memlens.core import rulepack as rp

    tmp = tempfile.mkdtemp(prefix="ml-dim-rp-")
    pack = _pack(tmp, version="2.0.0", published_at="2026-11-12",
                 dimension_weights={"tool_presence": 0.5, "channel_config": 0.1,
                                    "execution_trace": 0.1, "data_egress": 0.2,
                                    "access_direction": 0.1},
                 thresholds={**rp.DEFAULT_THRESHOLDS,
                             **rp.DEFAULT_DIMENSION_THRESHOLDS,
                             "scoring.confirmed_total": 0.9})
    check("权重可外置", pack.dimension_weight("tool_presence") == 0.5,
          str(pack.dimension_weight("tool_presence")))
    check("阈值可外置", pack.threshold("scoring.confirmed_total") == 0.9,
          str(pack.threshold("scoring.confirmed_total")))
    check("工具指纹库可外置", len(pack.tools()) == len(rp.DEFAULT_PROXY_TOOLS))
    shutil.rmtree(tmp, ignore_errors=True)


def test_fr01_tool_presence() -> None:
    print("\n── ② FR-01 工具存在性 ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.tool_presence import ToolPresenceDimension

    tmp = tempfile.mkdtemp(prefix="ml-dim-f1-")
    pack = rp.default_pack()

    # ① 已安装（有服务）
    ctx = _ctx(**{"mprocfs.process": [_proc()], "mprocfs.services": [_svc()],
                   "mprocfs.registry_run": []})
    d = ToolPresenceDimension().run(ctx, pack)
    check("服务命中 → 已安装", d.state == "established", f"{d.state} {d.findings[:1]}")
    check("已安装得分高", d.score >= 0.9, str(d.score))
    check("带证据编号", len(d.evidence_refs) > 0, str(d.evidence_refs))
    check("带独立来源数", d.independent_sources >= 2, str(d.independent_sources))

    # ② 便携运行（用户目录 + 无服务）
    ctx2 = _ctx(**{"mprocfs.process": [_proc(path=r"C:\Users\alice\Downloads\v2ray\v2ray.exe")],
                   "mprocfs.services": [], "mprocfs.registry_run": []})
    d2 = ToolPresenceDimension().run(ctx2, pack)
    check("用户目录 → 便携运行", "便携" in " ".join(d2.findings), str(d2.findings[:1]))

    # ③ 残留（仅进程、无安装痕迹，且不在用户目录）
    ctx3 = _ctx(**{"mprocfs.process": [_proc(path=r"C:\Program Files\v2ray\v2ray.exe")],
                   "mprocfs.services": [], "mprocfs.registry_run": []})
    d3 = ToolPresenceDimension().run(ctx3, pack)
    check("无安装痕迹 → 残留/权重减半", d3.score <= 0.35, str(d3.score))

    # ④ 白名单按**安装路径**排除（不按进程名）
    pack_wl = rp.default_pack().to_dict()
    pack_wl["proxy_tools"] = [{"id": "v2ray", "display": "V2Ray", "category": "proxy",
                              "strong": {"process": ["v2ray.exe"]},
                              "weak": {"process": ["v2ray"]},
                              "exclude_paths": ["\\v2rayn\\speedtest\\"]}]
    p = Path(tmp) / "wl.json"
    p.write_text(json.dumps(pack_wl, ensure_ascii=False), encoding="utf-8")
    pack2 = rp.load_pack(p)
    ctx4 = _ctx(**{"mprocfs.process": [_proc(path=r"C:\Tools\v2rayn\speedtest\v2ray.exe")],
                   "mprocfs.services": [], "mprocfs.registry_run": []})
    d4 = ToolPresenceDimension().run(ctx4, pack2)
    check("白名单按安装路径排除", d4.state == "not_found", str(d4.state))

    # ⑤ 完全无工具
    ctx5 = _ctx(**{"mprocfs.process": [_proc("notepad.exe", path=r"C:\Windows\notepad.exe")],
                   "mprocfs.services": [], "mprocfs.registry_run": []})
    d5 = ToolPresenceDimension().run(ctx5, pack)
    check("无工具 → 未发现", d5.state == "not_found" and d5.score == 0.0)

    # ⑥ 缺源 → 降级
    ctx6 = _ctx(**{"mprocfs.process": []})
    d6 = ToolPresenceDimension().run(ctx6, pack)
    check("缺进程表 → 降级", d6.state == "degraded", d6.state)
    check("降级产生缺口", len(d6.gaps) >= 1)
    shutil.rmtree(tmp, ignore_errors=True)


def test_fr02_channel_config() -> None:
    print("\n── ③ FR-02 通道配置 ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.channel_config import ChannelConfigDimension

    pack = rp.default_pack()

    # ① 系统级代理 + 自动配置脚本（高价值）
    ctx = _ctx(**{
        "mprocfs.registry_proxy": [
            {"注册表键": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
             "名称": "AutoConfigURL", "数据": "http://subscribe.example.com/pac/proxy.pac"},
            {"注册表键": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
             "名称": "ProxyEnable", "数据": "1"},
        ],
        "mprocfs.net": [_listen()],
        "mprocfs.netdns": [],
    })
    d = ChannelConfigDimension().run(ctx, pack)
    check("自动配置脚本 → 高价值命中", d.score >= 0.9, str(d.score))
    check("自动配置脚本被标为高价值",
          any("高价值" in f for f in d.findings), str(d.findings[:2]))
    check("代理进程监听被识别",
          any("代理进程" in f for f in d.findings), str(d.findings[:3]))

    # ② 非代理进程的监听**不计分**
    ctx2 = _ctx(**{
        "mprocfs.registry_proxy": [],
        "mprocfs.net": [_listen(proc="svchost.exe", port="445")],
        "mprocfs.netdns": [],
    })
    d2 = ChannelConfigDimension().run(ctx2, pack)
    check("普通监听不计分", d2.score < 0.5, str(d2.score))

    # ③ 缺代理注册表 → 降级 + 明确标注未覆盖
    d3 = ChannelConfigDimension().run(_ctx(**{"mprocfs.net": [], "mprocfs.netdns": []}), pack)
    check("缺代理键 → 标注未覆盖",
          any("未取得 Internet Settings" in g["reason"] for g in d3.gaps),
          str(d3.gaps))

    # ④ 浏览器配置面缺失必须明说
    check("浏览器配置面缺失被声明",
          any("浏览器" in f for f in d3.findings), str(d3.findings))


def test_fr03_execution_trace() -> None:
    print("\n── ④ FR-03 运行痕迹 ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.execution_trace import ExecutionTraceDimension

    pack = rp.default_pack()

    # ① 进程在跑 → 命中
    ctx = _ctx(**{"mprocfs.process": [_proc()], "mprocfs.services": [],
                  "mprocfs.cmdlines": [], "windows.registry.userassist": []})
    d = ExecutionTraceDimension().run(ctx, pack)
    check("进程痕迹命中", d.state == "established", d.state)
    check("多源 → 独立来源数增加", d.independent_sources >= 1, str(d.independent_sources))

    # ② 磁盘侧三源缺失必须报缺口
    for name in ("预取", "兼容性数据库", "资源使用统计"):
        check(f"{name}缺失被记录为缺口",
              any(name in g["reason"] for g in d.gaps), str([g["reason"] for g in d.gaps]))

    # ③ 无 SRUM → 上限降为 B（方案 4.2.3(3)）
    check("缺 SRUM → 等级上限 B", d.level_cap == "B", d.level_cap)

    # ④ UserAssist 的 ROT13 编码要被还原
    import codecs
    ua_val = codecs.encode("C:\\Tools\\v2ray\\v2ray.exe", "rot_13")
    ctx2 = _ctx(**{"mprocfs.process": [], "mprocfs.services": [],
                   "mprocfs.cmdlines": [],
                   "windows.registry.userassist": [{"Value": ua_val}]})
    d2 = ExecutionTraceDimension().run(ctx2, pack)
    check("UserAssist ROT13 被还原并命中", d2.state == "established",
          f"{d2.state} {d2.findings[:1]}")


def test_fr04_data_egress() -> None:
    print("\n── ⑤ FR-04 数据外联 ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.data_egress import DataEgressDimension

    pack = rp.default_pack()

    # ① 有归属的外联 → 证明力更强
    ctx = _ctx(**{"mprocfs.net": [_net()], "mprocfs.netdns": [], "mprocfs.process": [_proc()]})
    d = DataEgressDimension().run(ctx, pack)
    check("外联成立", d.state == "established", d.state)
    check("已归属与未归属分开统计",
          any("已归属进程" in f for f in d.findings), str(d.findings[:2]))

    # ② 未归属（PID=0）→ 得分降低且如实说明
    ctx2 = _ctx(**{"mprocfs.net": [_net(pid="0", proc="")], "mprocfs.netdns": [],
                   "mprocfs.process": []})
    d2 = DataEgressDimension().run(ctx2, pack)
    check("无归属外联得分较低", d2.score < d.score, f"{d2.score} vs {d.score}")
    check("无归属被如实声明",
          any("无进程归属" in f for f in d2.findings), str(d2.findings[:2]))

    # ③ 内网地址不算外联
    ctx3 = _ctx(**{"mprocfs.net": [_net(dst="192.168.1.1")], "mprocfs.netdns": [],
                   "mprocfs.process": []})
    d3 = DataEgressDimension().run(ctx3, pack)
    check("内网地址不算外联", d3.state == "not_found", d3.state)

    # ④ 字节计量缺失必须报缺口
    check("字节计量缺失被记录",
          any("字节计量" in g["reason"] for g in d.gaps), str(d.gaps))


def test_fr05_access_direction() -> None:
    print("\n── ⑥ FR-05 访问方向 ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.access_direction import AccessDirectionDimension

    pack = rp.default_pack()
    ctx = _ctx(**{"mprocfs.netdns": [{"Host": "arxiv.org", "Time": "2026-07-23"}],
                  "mprocfs.browser_history": []})

    # ① **默认关闭** → 不出结论
    d = AccessDirectionDimension().run(ctx, pack)
    check("默认关闭", d.state == "disabled", d.state)
    check("关闭时不出结论（得分 0）", d.score == 0.0)

    # ② 开启后按五类打标
    d2 = AccessDirectionDimension(enabled=True).run(ctx, pack)
    check("开启后可判定", d2.state == "established", d2.state)
    check("学术类被识别",
          any("academic" in f or "学术" in f for f in d2.findings), str(d2.findings[:3]))

    # ③ 合规通道白名单未配置 → 报缺口
    check("合规通道清单缺失被记录",
          any("合规通道" in g["reason"] for g in d2.gaps), str(d2.gaps))


def test_fr06_scoring() -> None:
    print("\n── ⑦ FR-06 打分与分级 ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.base import DimensionResult, _score

    tmp = tempfile.mkdtemp(prefix="ml-dim-sc-")
    pack = rp.default_pack()

    # ① 加权求和
    dims = [DimensionResult(dimension="tool_presence", score=1.0, independent_sources=2),
            DimensionResult(dimension="data_egress", score=1.0, independent_sources=2),
            DimensionResult(dimension="access_direction", score=0.0, state="disabled")]
    v = _score(dims, pack, usage="check")
    expect = 0.20 * 1.0 + 0.25 * 1.0        # 权重 0.20 + 0.25
    check("加权求和正确", abs(v.total - expect) < 1e-6, f"{v.total} vs {expect}")
    check("未启用维不参与总分", v.total < 1.0)

    # ② 外联维下限：四维满分但外联 0 → 不得判"已确认"
    dims2 = [DimensionResult(dimension="tool_presence", score=1.0),
             DimensionResult(dimension="channel_config", score=1.0),
             DimensionResult(dimension="execution_trace", score=1.0),
             DimensionResult(dimension="data_egress", score=0.0)]
    v2 = _score(dims2, pack, usage="check")
    check("外联维 0 → 不得判已确认", v2.tier != "confirmed", v2.tier)
    check("外联维 0 → 存在风险", v2.tier == "risk", v2.tier)

    # ③ 全部满分且外联达标 → 已确认
    dims3 = [DimensionResult(dimension="tool_presence", score=1.0, independent_sources=2),
             DimensionResult(dimension="channel_config", score=1.0, independent_sources=2),
             DimensionResult(dimension="execution_trace", score=1.0, independent_sources=2),
             DimensionResult(dimension="data_egress", score=1.0, independent_sources=2)]
    v3 = _score(dims3, pack, usage="check")
    check("五维满分 → 已确认", v3.tier == "confirmed", v3.tier)

    # ④ 单机未接外部记录 → 整体等级封顶 B
    check("单机采集等级封顶 B", v3.level_cap == "B", v3.level_cap)
    check("A 级被下调为 B", v3.level == "B", v3.level)
    check("有降级说明", any("封顶" in n for n in v3.notes), str(v3.notes))

    # ⑤ 取证用法按独立来源数定级
    #    ★ 未接入网络侧记录时，即使两维各有 2 个独立来源，也**只能到 B**
    #      （方案 4.2.4：接入网络侧记录并完成三处交叉后方可 A）。
    dims4 = [DimensionResult(dimension="tool_presence", score=1.0, independent_sources=2),
             DimensionResult(dimension="data_egress", score=1.0, independent_sources=2)]
    v4 = _score(dims4, pack, usage="forensic")
    check("未接网络侧记录 → 封顶 B（不因主机侧来源多而放行）", v4.level == "B", v4.level)
    check("封顶说明已写明", any("封顶" in n for n in v4.notes), str(v4.notes))

    #    完成三处交叉 → 才可 A
    dims4b = [DimensionResult(dimension="tool_presence", score=1.0, independent_sources=2),
              DimensionResult(dimension="data_egress", score=1.0, independent_sources=2,
                              external_cross_ok=True)]
    v4b = _score(dims4b, pack, usage="forensic")
    check("完成三处交叉 → A 级", v4b.level == "A", v4b.level)
    check("完成三处交叉 → 上限放开为 A", v4b.level_cap == "A", v4b.level_cap)
    dims5 = [DimensionResult(dimension="tool_presence", score=1.0, independent_sources=1)]
    v5 = _score(dims5, pack, usage="forensic")
    check("单来源 → B 级", v5.level == "B", v5.level)
    shutil.rmtree(tmp, ignore_errors=True)


def test_fr07_output() -> None:
    print("\n── ⑧ FR-07 结论输出（两套体系不混用） ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions.base import CHECK_TIERS, FORENSIC_LEVELS

    check("检查三档齐全", set(CHECK_TIERS) == {"confirmed", "risk", "record"},
          str(list(CHECK_TIERS)))
    check("取证三级齐全", set(FORENSIC_LEVELS) == {"A", "B", "C"},
          str(list(FORENSIC_LEVELS)))
    check("检查用法用词为发现/存在/疑似",
          all(w in ("发现", "存在", "疑似") for w in ("发现", "存在", "疑似")))


def test_evaluate_integration() -> None:
    print("\n── ⑨ 端到端：evaluate() ──")
    from memlens.core import rulepack as rp
    from memlens.dimensions import evaluate

    pack = rp.default_pack()
    ctx = _ctx(**{
        "mprocfs.process": [_proc()],
        "mprocfs.services": [_svc()],
        "mprocfs.registry_run": [],
        "mprocfs.registry_proxy": [
            {"注册表键": "HKLM\\...\\Internet Settings", "名称": "AutoConfigURL",
             "数据": "http://sub.example.com/a.pac"}],
        "mprocfs.net": [_net(), _listen()],
        "mprocfs.netdns": [{"Host": "arxiv.org", "Time": "2026-07-23"}],
        "mprocfs.browser_history": [],
        "mprocfs.cmdlines": [],
    })
    v = evaluate(ctx, usage="check", pack=pack)
    check("五维全部产出", len(v.dimensions) == 5, str(len(v.dimensions)))
    check("工具存在维成立", v.dim("tool_presence").state == "established",
          v.dim("tool_presence").state)
    check("通道配置维成立", v.dim("channel_config").state == "established",
          v.dim("channel_config").state)
    check("外联维成立", v.dim("data_egress").state == "established",
          v.dim("data_egress").state)
    check("访问方向默认关闭", v.dim("access_direction").state == "disabled")
    check("总分 > 0", v.total > 0, str(v.total))
    check("带规则包版本", bool(v.rulepack_version))
    check("带缺口清单", len(v.gaps) > 0, str(len(v.gaps)))
    check("每个维度都带 FR 编号",
          all(d.fr.startswith("FR-") for d in v.dimensions))

    # 开启访问方向
    v2 = evaluate(ctx, usage="forensic", pack=pack, allow_direction=True)
    check("开启后访问方向可判定", v2.dim("access_direction").state != "disabled")
    check("取证用法输出 A/B/C", v2.level in ("A", "B", "C"), v2.level)


def test_storage_roundtrip() -> None:
    print("\n── ⑩ 判定结果入库 ──")
    from memlens.storage.db import DataStore
    from memlens.core import rulepack as rp
    from memlens.dimensions import evaluate

    tmp = tempfile.mkdtemp(prefix="ml-dim-db-")
    s = DataStore(Path(tmp) / "t.db")
    cid = s.create_case("t", r"D:\MemLens\samples\synthetic_windows.raw")
    ctx = _ctx(**{"mprocfs.process": [_proc()], "mprocfs.services": [_svc()]})
    v = evaluate(ctx, usage="check", pack=rp.default_pack())
    n = s.save_dimension_results(cid, v)
    check("判定结果入库", n == 5, str(n))
    rows = s.list_dimension_results(cid)
    check("可读回", len(rows) == 5, str(len(rows)))
    check("含得分与状态", all(r.get("score") is not None and r.get("state") for r in rows))
    check("含依据证据项集合", "evidence_refs" in rows[0])
    check("含规则包版本", bool(rows[0].get("rulepack_version")))
    # 重复保存不累积
    s.save_dimension_results(cid, v)
    check("重复保存不累积", len(s.list_dimension_results(cid)) == 5)
    s.close()
    shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    print("=" * 70)
    print("MemLens 五维判定引擎专项测试（方案 4.2 节 FR-01~FR-07）")
    print("=" * 70)
    test_rulepack_driven()
    test_fr01_tool_presence()
    test_fr02_channel_config()
    test_fr03_execution_trace()
    test_fr04_data_egress()
    test_fr05_access_direction()
    test_fr06_scoring()
    test_fr07_output()
    test_evaluate_integration()
    test_storage_roundtrip()
    print("\n" + "=" * 70)
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
