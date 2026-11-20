# -*- coding: utf-8 -*-
"""验证 StaticSampleDetector 在真实文件上的行为：低分文件应有可解释权重、不妨碍正确定级。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from memlens.core.image_probe import probe_image
from memlens.detectors.base import DetectionContext
from memlens.engines.static import StaticEngine, profile_file, profile_to_records
from memlens.storage.db import DataStore

engine = StaticEngine()
plugins = {p.name: p for p in engine.list_plugins()}
db = ROOT / "work" / "_detector_selftest.db"
if db.exists():
    db.unlink()
store = DataStore(db)

CASES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\calc.exe",
]

for path in CASES:
    if not Path(path).exists():
        continue
    probe = probe_image(path, deep=False, for_engine="static")
    case_id = store.create_case(Path(path).stem + "-selftest", path,
                               container=probe.container.value, os_type=probe.os_type.value)
    # 只跑 profile + pe + strings（packer 是 packer 派生，检测器不看）
    for name in ("static.profile", "static.pe", "static.strings"):
        art = store.start_artifact(case_id, "static", name, category="静态分析",
                                   kind="table", params={}, argv=["x"])
        rows = store.add_records(art, engine.analyze_file(path, plugins[name]))
        store.finish_artifact(art, status="ok", row_count=rows)
    print("=" * 72)
    print(path)

    ctx = DetectionContext(store, case_id)
    for det_name in ("static_pe_suspicious", "hidden_process", "code_injection"):
        from memlens.detectors.base import get_detector
        det = get_detector(det_name)
        reason = det.guard(ctx)
        if reason:
            print(f"  [{det_name}] 跳过：{reason}")
            continue
        out = det.run(ctx)
        print(f"  [{det_name}] 执行 → {len(out)} 条")
        for d in out:
            print(f"      {d.title}  severity={d.severity}")
            print(f"      weights={d.evidence.get('命中权重')}")

    # 同时打印该文件的原始画像要素，便于人工核对
    prof = profile_file(path)
    if prof.pe:
        header = next((r for r in profile_to_records(prof)
                       if r.get("项") == "PE 头"), {})
        print(f"  画像: 签名={header.get('数字签名')} 加壳={header.get('加壳嫌疑')} "
              f"节={len(prof.pe.sections)} DLL导入={len(prof.pe.imports)} TLS={len(prof.pe.tls_callbacks)}")

# 反向验证：构造一个"应该高分"的合成画像（注入三件套 + 加壳 + TLS + WX 节），
# 确认检测器能把它判成 high。这是"检测器真的会叫"的关键证据。
print("=" * 72)
print("合成高危样本（验证检测器能否正确告警）")
case_id = store.create_case("synthetic-malicious", r"C:\fake\evil.exe", container="exe",
                           os_type="unknown", allow_missing=True)
# ---- 静态画像 ----
def _profile_rows() -> list[dict]:
    return [
        {"文件": "evil.exe", "路径": r"C:\fake\evil.exe", "大小(字节)": 20480,
         "文件类型": "pe", "整体熵": 7.6, "语言/运行时": "未知",
         "SHA-256": "ab" * 32, "MD5": "cd" * 16,
         "画像提醒": "加壳/保护特征：UPX(节名:upx0)"},
    ]


def _pe_rows() -> list[dict]:
    return [
        {"文件": "evil.exe", "项": "PE 头", "位数": 64, "CPU": "AMD64", "子系统": "Windows GUI",
         "DLL": False, "驱动(.sys)": False, "入口点": "0x1000", "镜像基址": "0x140000000",
         "链接器版本": "0.0", "编译时间": "", "Rich 头 Key": "", "数字签名": False,
         "加壳嫌疑": True, "加壳标记": "UPX(节名:upx0)"},
        {"文件": "evil.exe", "项": "节区", "节名": "upx0", "虚拟大小": 16384, "原始大小": 16384,
         "熵": 7.8, "可写且可执行(W+X)": True},
        {"文件": "evil.exe", "项": "TLS 回调", "地址": "0x140001000"},
        {"文件": "evil.exe", "项": "导入表", "DLL": "kernel32.dll", "函数数": 4,
         "函数": "VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, CreateProcessA"},
        {"文件": "evil.exe", "项": "导入表", "DLL": "ws2_32.dll", "函数数": 2,
         "函数": "WSAStartup, connect"},
        {"文件": "evil.exe", "项": "导入表", "DLL": "user32.dll", "函数数": 2,
         "函数": "SetWindowsHookExA, BitBlt"},
    ]


def _string_rows() -> list[dict]:
    return [
        {"文件": "evil.exe", "项": "字符串", "类别": "命令行痕迹", "字符串": "cmd.exe /c whoami"},
        {"文件": "evil.exe", "项": "字符串", "类别": "加壳标记", "字符串": "UPX!"},
        {"文件": "evil.exe", "项": "字符串", "类别": "共享路径", "字符串": r"\\10.0.0.1\IPC$"},
    ]


# ---- 灌数据：按真实 CLI 流程分成 3 个 artifact ----
for name, rows in (("static.profile", _profile_rows()),
                   ("static.pe", _pe_rows()),
                   ("static.strings", _string_rows())):
    a = store.start_artifact(case_id, "static", name, category="静态分析",
                            kind="table", params={}, argv=["x"])
    store.add_records(a, rows)
    store.finish_artifact(a, status="ok", row_count=len(rows))

from memlens.detectors.base import get_detector
det = get_detector("static_pe_suspicious")
print(f"  依赖检查: {det.guard(DetectionContext(store, case_id)) or '通过'}")
out = det.run(DetectionContext(store, case_id))
print(f"  → {len(out)} 条发现项")
for d in out:
    print(f"    [{d.severity.upper()}] {d.title}")
    print(f"    描述: {d.description[:120]}...")
    print(f"    权重: {d.evidence.get('命中权重')}")

store.close()
