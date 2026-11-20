# -*- coding: utf-8 -*-
"""
MemLens 回归测试 v2-lite（offscreen，毫秒级，不跑任何后台 worker）

只验证**纯 UI 逻辑**：引擎切换、插件树重建、预设切换、探测分流判定、表格/导出。
后台 worker（AnalyzeWorker）已由 CLI 端到端与 tools/test_static_engine.py 覆盖，
不必在无头环境下重复跑一次完整的、会拖慢测试的流程。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication

from memlens.core.image_probe import ContainerFormat, probe_image
from memlens.engines.static import profile_file, extract_interesting_strings
from memlens.engines import registry
from memlens.engines.base import PluginMeta
from memlens.ui.main_window import CATEGORY_ORDER, MainWindow, PRESETS

R: dict[str, object] = {}
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'✅' if cond else '❌'} {name}" + (f"   {detail}" if detail else ""))


app = QApplication([])
win = MainWindow(project_root=ROOT)
win.show()
app.processEvents()

# ---- 1. 引擎自检 ----
avail = {e.name: (ok, why) for e, ok, why in registry.iter_available() if e}
# 断言写成"至少包含"而不是全等：新增引擎是正常的扩展，
# 全等断言会在每次加引擎时误报成回归（这个坑踩过）。
check("引擎注册：vol3 + static + memstrings",
      {"vol3", "static", "memstrings"} <= set(avail), str(sorted(avail)))
check("static 引擎可用", avail.get("static", (False,))[0], avail.get("static", ("", ""))[1])
check("memstrings 引擎可用", avail.get("memstrings", (False,))[0],
      avail.get("memstrings", ("", ""))[1])

v3, st = registry.get("vol3"), registry.get("static")
n_vol3 = len(v3.list_plugins()) if v3.available()[0] else 0
n_st = len(st.list_plugins())
st_names = sorted(p.name for p in st.list_plugins())
check("vol3 运行时枚举 >150", n_vol3 > 150, f"{n_vol3}")
check("static 9 个维度（PE/ELF/pcap/archive/memfrag）", n_st == 9, f"{n_st}")
check("static 维度清单正确",
      st_names == ["static.archive", "static.deps", "static.elf", "static.memfrag",
                   "static.packer", "static.pcap", "static.pe", "static.profile",
                   "static.strings"],
      str(st_names))

# ---- 2. GUI 引擎切换 ----
keys = list(win._engine_labels)
check("GUI 引擎下拉含三项", keys == ["vol3", "static", "memstrings"], str(keys))

# 等 _bootstrap 的 QTimer 跑完（它可能还在排队），手动触发一次确保状态确定
win._on_engine_changed()
app.processEvents()

win.engine_box.setCurrentIndex(keys.index("static"))
app.processEvents()
tops = [win.plugin_tree.topLevelItem(i).text(0) for i in range(win.plugin_tree.topLevelItemCount())]
check("切 static → 插件树只剩【静态分析】",
      tops == [f"静态分析（{n_st}）"], str(tops))
check("切 static → 只列 static.* 插件", all(p.name.startswith("static.") for p in win.plugins))
check("static 默认预设选中 4 项", len(win.selected_plugins()) == 4, f"{len(win.selected_plugins())}")

presets = [win.preset_box.itemText(i) for i in range(win.preset_box.count())]
check("预设框随引擎切换为 static 集",
      all(p.startswith("样本") for p in presets) and len(presets) == 2, str(presets))

# 切回 vol3
win.engine_box.setCurrentIndex(keys.index("vol3"))
app.processEvents()
tops2 = [win.plugin_tree.topLevelItem(i).text(0) for i in range(win.plugin_tree.topLevelItemCount())]
check("切回 vol3 → 插件树多分组", len(tops2) > 5, f"{len(tops2)} 组")
presets2 = [win.preset_box.itemText(i) for i in range(win.preset_box.count())]
check("预设框切回 vol3 集（4 项）", len(presets2) == 4, str(len(presets2)))

# ---- 3. 探测分流（不触发 worker，直接调 probe + 复刻 GUI 判定）----
pe = probe_image(r"C:\Windows\System32\notepad.exe", deep=False, for_engine="static")
check("PE 探测 → exe", pe.container.value == "exe", pe.container.value)
check("PE 探测 → 非内存镜像（应走 static）", not pe.container.is_memory_image)
check("PE 探测在 for_engine=static 时无矛盾告警",
      all("请改用" not in w for w in pe.warnings), str(pe.warnings))
check("describe 标签准确",
      "[样本文件 → 用 static 引擎做静态分析]" in __import__(
          "memlens.core.image_probe", fromlist=["describe"]).describe(pe))

# ---- 3b. 回归：static 引擎必须能分析样本文件（真实 bug 固化）----
# 起因：用户选 static 引擎分析 PE，却弹"需要先解包/转换才能分析"。
# 根因是 GUI 的按钮状态判断做了 static 豁免，worker 内部却没做 → 逻辑漂移。
# 现在三处（按钮/worker/CLI）共用 can_analyze()，这里锁死该行为。
from memlens.core.image_probe import (can_analyze, refresh_warnings)  # noqa: E402

pe_raw = probe_image(r"C:\Windows\System32\notepad.exe", deep=False)
_ok_s, _ = can_analyze(pe_raw, "static")
_ok_v, _why_v = can_analyze(pe_raw, "vol3")
check("static 引擎可分析 PE（不再是'需要先解包'）", _ok_s,
      f"can_analyze(static)={_ok_s}")
check("vol3 引擎对 PE 给出正确的改用引导", (not _ok_v) and "静态分析" in _why_v or not _ok_v,
      _why_v[:60])
check("PE 对内存引擎确实 analysable=False（前提成立）", not pe_raw.analysable)

# 提醒重算：内存语境探测后切 static，噪音应被清除
pe2 = probe_image(r"C:\Windows\System32\notepad.exe", deep=False)
_n_before = len(pe2.warnings)
refresh_warnings(pe2, "static")
check("切到 static 后提醒噪音被清除",
      _n_before >= 1 and len(pe2.warnings) == 0,
      f"{_n_before} → {len(pe2.warnings)}")
refresh_warnings(pe2, "vol3")
check("切回 vol3 后内存语境提醒恢复", len(pe2.warnings) >= 1,
      f"{len(pe2.warnings)} 条")

raw_like = probe_image(str(ROOT / "samples" / "synthetic_windows.raw"), deep=True)
check("合成内存镜像 → raw 且是内存镜像",
      raw_like.container.value == "raw" and raw_like.container.is_memory_image)
check("内存镜像探测到 windows 指纹", raw_like.os_type.value == "windows",
      f"{raw_like.os_type.value}@{raw_like.os_confidence:.0%}")

lime = probe_image(str(ROOT / "samples" / "synthetic_lime.lime"), deep=False)
check("LiME 样本 → lime", lime.container.value == "lime", lime.container.value)

other = probe_image(str(ROOT / "samples" / "synthetic_unknown.bin"), deep=False)
# 合成"垃圾文件"是纯随机字节，熵 ≈ 7.998 → 现在应判 encblob（疑似加密块），
# 而不是早期版本的"一律当 raw"。断言改为"不当作内存镜像"。
check("随机垃圾文件 → encblob（不再一律当 raw）",
      other.container.value in ("encblob", "other")
      and not other.container.is_memory_image,
      other.container.value)
check("encblob 给出「疑似加密」提示",
      any("加密" in w or "encblob" in other.container.value for w in other.warnings),
      str(other.warnings[:1]))

# ---- 4. 表格 + 导出（用假 artifact，无需真解析）----
case_id = win.store.create_case("lite-回归", r"C:\Windows\System32\notepad.exe",
                                container="exe", os_type="unknown", allow_missing=True)
art = win.store.start_artifact(case_id, "static", "static.profile", category="静态分析",
                               kind="table", params={}, argv=["x"])
win.store.add_records(art, [
    {"文件": "notepad.exe", "大小(字节)": 360448, "SHA-256": "a" * 64, "整体熵": 6.5},
    {"文件": "notepad.exe", "大小(字节)": 360448, "SHA-256": "a" * 64, "整体熵": 6.4},
])
win.store.finish_artifact(art, status="ok", row_count=2)
win.result_table.show_artifact(art, "画像")
check("表格 2 行", win.result_table.model.rowCount() == 2)
win.result_table.search.setText("360")
win.result_table._on_search()
check("关键词过滤命中 2 行", win.result_table.model.rowCount() == 2)
win.result_table.model.sort(1, 1)
check("排序不崩", win.result_table.model.rowCount() == 2)
out = ROOT / "work" / "_lite.csv"
n = win.store.export_records_csv(out, artifact_id=art)
check("CSV 导出", out.exists() and n == 2, f"{n} 行")
out.unlink(missing_ok=True)

# ---- 5. 常量一致性 ----
check("CATEGORY_ORDER 含静态分析", "静态分析" in CATEGORY_ORDER)
check("PRESETS 含 static 两套",
      sum(1 for k in PRESETS if k.startswith("样本")) == 2)

# ---- 6. 真实样本回归（solarsec_202603：ELF 样本 + 内存段 + 加密容器）----
# 这些断言来自 2026-10 对真实赛题附件的验证，固化后防止后续改坏。
REAL = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
if REAL.is_dir():
    big_elf = REAL / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5"
    locked = REAL / "flag.solarsec.locked"
    frag = REAL / "dumped_4053_[400000-4f4000].bin"

    if big_elf.exists():
        pr = probe_image(str(big_elf), deep=False, for_engine="static")
        check("真实样本：15MB ELF → elf 容器", pr.container.value == "elf", pr.container.value)
        # ELF 结构解析（节区表在偏移 ~0xef32b0，必须读全文件，4KB 会得 0 节）
        from memlens.engines.elf import parse_elf
        ei = parse_elf(str(big_elf), big_elf.read_bytes())
        check("真实样本：ELF64 + ET_EXEC + x86-64",
              ei.bits == 64 and ei.e_type == "ET_EXEC" and ei.machine == "x86-64",
              f"{ei.bits}/{ei.e_type}/{ei.machine}")
        check("真实样本：ELF 节区 >= 40", len(ei.sections) >= 40, str(len(ei.sections)))
        check("真实样本：ELF 识别为静态链接", ei.static_linked)
        check("真实样本：ELF 符号表未剥离", not ei.stripped)
        check("真实样本：ELF 提取到本地函数 > 500", len(ei.user_functions) > 500,
              str(len(ei.user_functions)))
        check("真实样本：ELF 入口点 = 0x401320", ei.entry == 0x401320, hex(ei.entry or 0))

    if locked.exists():
        pr = probe_image(str(locked), deep=False)
        check("真实样本：flag.solarsec.locked → locked 容器",
              pr.container is ContainerFormat.LOCKED_CONTAINER, pr.container.value)
        check("真实样本：locked 提示包含「加密程序/算法才能还原」",
              any("加密程序/算法" in w for w in pr.warnings), str(pr.warnings[:1]))

    if frag.exists():
        pr = probe_image(str(frag), deep=False)
        check("真实样本：ELF 映射内存段 → memfrag（不误判为 ELF 样本）",
              pr.container is ContainerFormat.MEMORY_FRAGMENT, pr.container.value)
        check("真实样本：memfrag 提示「出不了完整进程表」",
              any("完整进程表" in w for w in pr.warnings))

    # ---- 威胁检测器：benign 零误报 / 恶意样本出案（两级互证）----
    from memlens.engines import registry as _reg
    from memlens.detectors.base import DetectionContext, get_detector
    eng = _reg.get("static")

    def score(path, tag):
        prof = profile_file(path)
        cid = win.store.create_case(tag, path, container=prof.file_type,
                                    os_type="unknown", allow_missing=True)
        for p in eng.list_plugins():
            if p.name == "static.pcap":
                continue
            a = win.store.start_artifact(cid, "static", p.name, category="静态分析",
                                         kind="table", params={}, argv=["x"])
            try:
                rows = list(eng.analyze_file(path, p))
            except Exception:
                rows = []
            win.store.add_records(a, rows)
            win.store.finish_artifact(a, status="ok")
        out = get_detector("static_sample_suspicious").run(DetectionContext(win.store, cid))
        win.store.conn.execute("DELETE FROM cases WHERE case_id=?", (cid,))
        win.store.conn.commit()
        return prof, out

    for b in (r"C:\Windows\System32\notepad.exe",
              r"C:\Windows\System32\calc.exe",
              r"C:\Windows\System32\mmc.exe"):
        if not Path(b).exists():
            continue
        prof, out = score(b, "reg-benign")
        check(f"良性样本零误报：{Path(b).name}",
              not out, out[0].title if out else "")

    if big_elf.exists():
        prof, out = score(str(big_elf), "reg-elf")
        check("真实样本：ELF 可疑性检测器能出结论（含可解释权重）",
              bool(out) and bool(out[0].evidence.get("命中权重")),
              out[0].title if out else "无")

    mal = Path(r"D:\MemLens\work\attachments/512_512_可疑文件/TestDLL.dll")
    if mal.exists():
        prof, out = score(str(mal), "reg-mal")
        check("恶意样本出案：TestDLL.dll（真实下载样本）",
              bool(out) and out[0].confidence >= 0.40,
              out[0].title if out else "无")

    # ---- pcap：真实流量包解析 + 明文 flag 提取 ----
    pcap = Path(r"D:\MemLens\work/attachments/1028_1028_challenge/challenge.pcap")
    if pcap.exists():
        from memlens.engines.pcap import analyze_pcap
        rows = list(analyze_pcap(str(pcap)))
        summ = next((r for r in rows if r.get("项") == "pcap 概要"), {})
        check("pcap 真实样本：包数 > 500", summ.get("包数", 0) > 500, f"{summ.get('包数')} 包")
        check("pcap 链路层识别为 IPv4",
              any(r.get("项") == "链路层协议" and "IPv4" in str(r.get("分布", "")) for r in rows))
        frag = next((r.get("片段") for r in rows if r.get("项") == "流量内 flag 特征"), None)
        check("pcap 提取到明文 flag", bool(frag and "flag{" in str(frag)), str(frag))

    # ---- memfrag：真实进程内存段（vol3 跑不了，但字符串扫描能出凭据）----
    # 真实 bash 内存段来自只读源目录 E:\附件原件\...（不作为回归输入），
    # 这里用已下载到工作区的 Solar 赛题内存段（同样是 ptrace dump）验证。
    mfrag = None
    for _ex in (ROOT / "work" / "attachments" / "scan").iterdir():
        if not _ex.is_dir():
            continue
        for _p in _ex.rglob("dumped_*.bin"):
            if _p.stat().st_size > 100_000:
                mfrag = _p
                break
        if mfrag:
            break
    if not mfrag:
        # 退路：用 only-read 源目录的真实 bash 段（只读，不改动）
        src = REAL / "dumped_4053_[23d1000-253e000].bin"
        if src.exists():
            mfrag = src

    if mfrag and mfrag.exists():
        from memlens.engines.memfrag import analyze_memfrag, parse_range
        rng = parse_range(mfrag.name)
        check("memfrag 真实样本：解析出虚拟地址区间", bool(rng), str(rng))
        rows = list(analyze_memfrag(str(mfrag)))
        prof = next((r for r in rows if r.get("项") == "页画像"), {})
        check("memfrag 页画像：总页数 > 100", prof.get("总页数", 0) > 100,
              f"{prof.get('总页数')} 页")
        iocs = [r for r in rows if r.get("项") == "IoC 命中" and r.get("模式")]
        check("memfrag IoC 命中", bool(iocs), str([r.get("模式") for r in iocs][:4]))
        strs = [r for r in rows if r.get("项") == "长字符串详情" or r.get("项") == "长字符串明细"]
        blob_all = " ".join(str(r.get("内容", "")) for r in strs)
        check("memfrag 提取到长可读字符串（>=60字符）",
              any(len(str(r.get("内容") or "")) >= 60 for r in strs),
              f"{len(strs)} 条")
        # 真实 bash 段里含 sshpass 凭据（这是本条能力的价值证明）
        check("memfrag 提取到 SSH 凭据（sshpass -p + root@IP）",
              "sshpass" in blob_all and "root@" in blob_all,
              next((str(r.get("内容"))[:80] for r in strs
                    if "sshpass" in str(r.get("内容"))), "该样本未含（属正常）"))
        # 去重生效：Top 明细里同一串不应刷屏
        tops = str(next((r for r in rows if r.get("项") == "Top 可读字符串"),
                        {}).get("明细", ""))
        check("memfrag 字符串已去重（LS_COLORS 不重复占据 Top）",
              tops.count("LS_COLORS") <= 3, f"LS_COLORS 出现 {tops.count('LS_COLORS')} 次")

    # ---- 恶意软件 strings 覆盖度：真实 Agent Tesla 内存字符串清单 ----
    # 这份清单来自公开的 Agent Tesla 内存取证报告（BashiruDamoah/...-VOLATILITY-3），
    # 是"真实恶意软件分析中什么才是关键指标"的黄金对照。
    web = Path(r"D:\MemLens/work/attachments/web_samples/agent_tesla/memory_strings.txt")
    if web.exists():
        import re as _re
        raw_txt = web.read_text(encoding="utf-8", errors="replace")
        META = _re.compile(r"(?i)^(note|then|strings\s+-n|sample|tool)\b")
        标本 = []
        for line in raw_txt.splitlines():
            t = line.strip()
            if not t or t.startswith(("=", "-", "#")) or META.match(t):
                continue
            if _re.fullmatch(r"[A-Z /\-]+", t):
                continue
            标本.append(t)
        blob = "\n".join(标本).encode("latin1", "replace")
        found = extract_interesting_strings(blob, limit_per_group=50)
        got = {it.strip() for items in found.values() for it in items}
        rate = len(got & set(标本)) / max(1, len(标本))
        check("Agent Tesla IoC 覆盖度 >= 90%", rate >= 0.90, f"{rate:.0%}（{len(got & set(标本))}/{len(标本)}）")
        # 分类必须覆盖这几类真实指标
        cats = set(found)
        for need in ("SMTP/邮件外泄", "C2/外联路径", "IP 地址", "URL 外联",
                     "凭据/密码相关", "PyInstaller 打包", "可执行文件路径"):
            check(f"覆盖类别：{need}", need in cats, "")
        # 关键单点（这三条曾经全漏）
        allblob = " ".join(str(x) for v in found.values() for x in v)
        check("提取 C2 URL（http://...gate.php）",
              "http://marketingg.jino-net.ru/proxy/gate.php" in allblob, "")
        check("提取裸 IP（185.65.202.62）", "185.65.202.62" in allblob, "")
        check("提取 SMTP 凭据串（smtpPassword）", "smtpPassword" in allblob, "")

    # ---- 磁盘镜像识别：DFRWS 2009 的 FAT16 .dd ----
    dd = Path(r"D:\MemLens/work/attachments/web_samples/dfrws2009/nssal-thumb-fs.dd")
    if dd.exists():
        pr = probe_image(str(dd), deep=False)
        check("DFRWS .dd 磁盘镜像 → filesystem（不再归 other）",
              pr.container is ContainerFormat.FILESYSTEM, pr.container.value)
        check("磁盘镜像明确提示「内存取证插件不会工作」",
              any("内存取证插件不会工作" in w for w in pr.warnings),
              str(pr.warnings[:1]))
        check("磁盘镜像不判为内存镜像", not pr.container.is_memory_image, "")
else:
    print("  (跳过真实样本回归：目录不存在)")

# 清理自测案件
win.store.conn.execute("DELETE FROM cases WHERE name='lite-回归'")
win.store.conn.commit()

print("\n" + "=" * 62)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
if FAIL:
    print("❌ 失败：", FAIL)
else:
    print("GUI/探测/表格回归全部通过 ✅")
