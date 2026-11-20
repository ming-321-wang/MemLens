"""
MemLens 新增能力的端到端联调（intel / memstrings / timeline / report / knowledge）。

运行：
    .venv\\Scripts\\python.exe tools\\test_intel_stack.py
"""
from __future__ import annotations

import base64
import io
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from memlens import report, timeline
from memlens.detectors.base import DetectionContext, run_all
from memlens.engines import registry
from memlens.intel import knowledge, scan
from memlens.storage.db import DataStore
from memlens.tasks.runner import TaskRunner

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}" + (f"  {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


def build_evidence(path: Path) -> None:
    """造一份"像样"的证据：含多编码 flag、IOC、远控进程、持久化路径。"""
    flag = "flag{9f3a-memlens}"
    parts = [
        flag.encode(),
        flag.encode().hex().encode(),
        base64.b64encode(flag.encode()),          # 真实形态：整段 base64（天然以 ZmxhZ 开头）
        flag.encode("utf-16le"),
        b"C2 beacon to 45.77.1.22:8443  user@corp.example.com",
        b"http://c2.evil.top/gate.php",
        b"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        b"TeamViewer.exe mimikatz.exe nmap.exe",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".encode(),
        r"C:\Users\Public\svchost.exe".encode(),
        b"Bitcoin 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        b"vssadmin delete shadows /all /quiet",
        b"Your files have been encrypted. Contact: onion-abcxyz.onion",
        b"AKIAIOSFODNN7EXAMPLE",
        b"203.0.113.66 documentation range",
    ]
    blob = bytearray(os.urandom(2048))
    for p in parts:
        blob += b"\x00" * 32 + p
    path.write_bytes(bytes(blob))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="memlens_it_"))
    evidence = tmp / "evidence.raw"
    build_evidence(evidence)

    db = tmp / "memlens.db"
    store = DataStore(db)
    print("\n=== 1. 建案 ===")
    case_id = store.create_case("集成测试", str(evidence), container="raw", os_type="windows",
                               os_confidence=0.98)
    check("建案成功", len(case_id) == 12, case_id)

    runner = TaskRunner(store, registry.get("memstrings"), workdir=tmp / "work")

    print("\n=== 2. memstrings 引擎 ===")
    plugins = {p.name: p for p in registry.get("memstrings").list_plugins()}
    res_flag = runner.run_plugin(case_id, plugins["memstrings.flag"], {"limit": 100})
    check("flag 插件执行成功", res_flag.ok, f"{res_flag.rows} 行 {res_flag.error or ''}")
    rows = store.query_records(artifact_id=res_flag.artifact_id, limit=100)
    kinds = {r["parsed"].get("encoding") for r in rows}
    check("命中明文 flag", "明文" in kinds)
    check("命中十六进制 flag", "十六进制" in kinds)
    check("命中 Base64 flag", "Base64" in kinds)
    decoded = [r["parsed"].get("decoded") for r in rows if r["parsed"].get("decoded")]
    check("解码还原出明文 flag", any("9f3a-memlens" in d for d in decoded), str(decoded))
    check("每条命中都带偏移", all(r["parsed"].get("offset", -1) >= 0 for r in rows))

    res_u16 = runner.run_plugin(case_id, plugins["memstrings.utf16"], {"min_len": 8, "limit": 50})
    u16 = [r["parsed"].get("value") for r in store.query_records(artifact_id=res_u16.artifact_id, limit=50)]
    check("UTF-16LE 字符串提取", res_u16.ok and any("flag" in (v or "") for v in u16),
          f"{len(u16)} 行")

    res_ioc = runner.run_plugin(case_id, plugins["memstrings.ioc"], {"limit": 200})
    check("原始字节 IOC 提取", res_ioc.ok and res_ioc.rows > 0, f"{res_ioc.rows} 行")

    # 真实工作流：先把裸字符串捞进证据模型，情报扫描才有东西可交叉引用
    res_ascii = runner.run_plugin(case_id, plugins["memstrings.ascii"],
                                 {"min_len": 8, "limit": 500})
    check("ASCII 字符串提取", res_ascii.ok and res_ascii.rows > 0, f"{res_ascii.rows} 行")

    print("\n=== 3. 情报扫描（词典 + IOC 汇总）===")
    rep = scan.scan_case(store, case_id)
    print("     ", rep.summary())
    check("情报扫描产出记录", rep.total > 0, f"IOC={rep.ioc_records} 词典={rep.dict_records}")

    ioc_rows = store.records_of_plugin(case_id, "intel.ioc", limit=500)
    vals = {r["value"] for r in ioc_rows}
    check("提取到公网 IP", any(r.get("scope") == "公网" for r in ioc_rows),
          str([(r.get("value"), r.get("scope")) for r in ioc_rows
               if r.get("ioc_type") == "ipv4"]))
    check("文档保留段单独归类（不被误判为私网）",
          any(r.get("scope") == "文档段" for r in ioc_rows))
    check("提取到 URL", any(r.get("ioc_type") == "url" for r in ioc_rows))
    check("提取到注册表键", any(r.get("ioc_type") == "registry_key" for r in ioc_rows))
    check("提取到注册表持久化位置", any("CurrentVersion\\Run" in v for v in vals))
    check("提取到邮箱", any(r.get("ioc_type") == "email" for r in ioc_rows))
    check("IOC 记录带出处溯源", all(r.get("sources") for r in ioc_rows))

    proc_hits = store.records_of_plugin(case_id, "intel.dict.suspicious_process", limit=200)
    pvals = " ".join(str(r.get("match")) for r in proc_hits)
    check("词典命中远控软件", "TeamViewer" in pvals, pvals[:80])
    check("词典命中凭据工具", "mimikatz" in pvals.lower())
    check("词典命中 PowerShell 混淆", any("-enc" in str(r.get("match", "")) for r in proc_hits))

    pers = store.records_of_plugin(case_id, "intel.dict.persistence", limit=200)
    check("词典命中持久化位置", len(pers) > 0, f"{len(pers)} 条")

    ransom = store.records_of_plugin(case_id, "intel.dict.ransomware", limit=200)
    check("词典命中勒索特征", len(ransom) > 0, f"{len(ransom)} 条")

    cred = store.records_of_plugin(case_id, "intel.dict.credentials", limit=200)
    check("词典命中 AWS Key", any("AKIA" in str(r.get("match", "")) for r in cred))

    print("\n=== 4. 检测器（原有能力未回归）===")
    ctx = DetectionContext(store, case_id)
    findings, notes = run_all(ctx)
    check("检测器可运行且给出正面反馈", bool(notes), f"{len(notes)} 条说明")

    print("\n=== 5. 时间线 ===")
    rows_src = store.records_with_source(case_id, skip_plugins=("intel.",))
    events = timeline.build_timeline(rows_src, include_untimed=True)
    check("时间线可构建", len(events) > 0, f"{len(events)} 条")
    csv_path = tmp / "timeline.csv"
    n = timeline.to_csv(events, str(csv_path))
    check("时间线 CSV 导出", n == len(events) and csv_path.stat().st_size > 0)
    check("时间线 Markdown 可渲染", isinstance(timeline.to_markdown(events), str))

    print("\n=== 6. 知识库 ===")
    hits = knowledge.kb().match_artifacts(store.list_artifacts(case_id))
    check("按产物推荐知识条目", len(hits) > 0, f"{len(hits)} 条")
    text_hits = knowledge.kb().match_text("psscan 有而 pslist 没有，可能是隐藏进程")
    check("按文本检索知识条目", any(h[0].id == "hidden-process-diff" for h in text_hits))

    print("\n=== 7. 报告 ===")
    md = report.build_markdown(store, case_id)
    html_out = report.build_html(store, case_id)
    check("Markdown 报告生成", len(md) > 800, f"{len(md)} 字符")
    check("HTML 报告生成", html_out.startswith("<!DOCTYPE html>"), f"{len(html_out)} 字符")
    digest = (store.get_case(case_id) or {}).get("image_sha256") or ""
    check("报告含镜像指纹", bool(digest) and digest.split("(")[0] in md)
    check("报告含公网 IP 段", "45.77.1.22" in md)
    check("报告含执行情况段", "执行情况与局限" in md)

    p_md = report.export(store, case_id, str(tmp / "r.md"), fmt="md")
    p_html = report.export(store, case_id, str(tmp / "r.html"), fmt="html")
    check("报告导出到文件", Path(p_md).exists() and Path(p_html).exists())

    print("\n=== 8. 引擎自检 ===")
    names = [n for n in registry.installed()]
    check("memstrings 已注册", "memstrings" in names, str(names))
    for eng, ok, why in registry.iter_available():
        print(f"     {eng.name if eng else '?':<12} {'OK ' if ok else 'NG '} {why}")

    store.close()
    print(f"\n================  PASS={PASS}  FAIL={FAIL}  ================")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
