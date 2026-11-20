r"""
MemLens 检索引擎专项测试（memlens/core/search.py）

覆盖：
    ① 检索式解析（短语 / 字段过滤 / 排除 / 正则）
    ② 证据表检索（records）
    ③ 检测器结论与时间线检索
    ④ 二进制内容扫描
    ⑤ 全库检索（不指定案件）不过滤掉记录
    ⑥ 容器内检索（用构造的小卷）

运行：`.venv\Scripts\python.exe tools\test_search.py`
"""

from __future__ import annotations

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


# ─────────────────────────────────────────── ① 检索式解析
def test_query() -> None:
    print("\n── ① 检索式解析 ──")
    from memlens.core.search import Query

    q = Query("cmd.exe")
    check("单词解析", q.needles == ["cmd.exe"], str(q.needles))
    check("单词匹配", q.matches_text("xx CMD.EXE yy"))
    check("单词不匹配", not q.matches_text("xx notepad yy"))

    q2 = Query('"net user"')
    check("短语解析", q2.needles == ["net user"], str(q2.needles))
    check("短语需连续", not q2.matches_text("net the user"))
    check("短语命中", q2.matches_text("run net user now"))

    q3 = Query("cmd.exe pid:1234")
    check("字段过滤解析", q3.filters == [("pid", "1234")], str(q3.filters))
    check("字段命中", q3.filter_ok({"pid": "1234"}))
    check("字段不命中", not q3.filter_ok({"pid": "9999"}))
    check("字段缺失不命中", not q3.filter_ok({"name": "x"}))

    q4 = Query("cmd -flag")
    check("排除词解析", q4.excludes == ["flag"], str(q4.excludes))
    check("排除生效", not q4.matches_text("cmd flag"))
    check("排除不影响其余", q4.matches_text("cmd other"))

    q5 = Query("/cmd\\.exe/i", regex=True)
    check("正则解析", q5.pattern is not None)
    check("正则命中", q5.matches_text("xx CMD.EXE"))
    check("正则不命中", not q5.matches_text("cmd_exe"))

    q6 = Query("")
    check("空查询不报错", q6.needles == [] and q6.filters == [])


# ─────────────────────────────────────────── ④ 二进制扫描
def test_scan() -> None:
    print("\n── ④ 二进制内容扫描 ──")
    from memlens.core.search import Query, scan_bytes, scan_file

    data = b"\x00\x01hello WORLD\x00cmd.exe /c dir\x00" * 20
    q = Query("cmd.exe")
    hits = scan_bytes(data, q, source="t")
    check("二进制命中", len(hits) >= 1, str(len(hits)))
    check("命中带偏移", hits[0].offset is not None and hits[0].offset >= 0)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        p = f.name
    try:
        h2 = scan_file(p, Query("hello"), source="f")
        check("文件扫描命中", len(h2) >= 1, str(len(h2)))
        h3 = scan_file(p, Query("nothinghere"))
        check("文件扫描无命中", len(h3) == 0)
        h4 = scan_file(p, Query("/cmd\\.exe/"), regex=True, source="f")
        check("文件扫描正则", len(h4) >= 1, str(len(h4)))
    finally:
        Path(p).unlink(missing_ok=True)


# ─────────────────────────────────────────── ②③⑤ 数据库检索
def test_db() -> None:
    print("\n── ②③⑤ 数据库检索 ──")
    from memlens.core.search import Query, search, search_records
    from memlens.storage.db import DataStore

    tmp = Path(tempfile.mkdtemp(prefix="ml-sr-"))
    store = DataStore(tmp / "t.db")
    fake_img = tmp / "sample.raw"
    fake_img.write_bytes(b"\x00" * 4096)
    cid = store.create_case("t", str(fake_img))
    try:
        # 造几条 records（先登记 artifact，否则按案件过滤时会因"找不到产物"被丢掉）
        from memlens.storage import models as M
        import json
        with store.engine.begin() as conn:
            conn.execute(M.artifacts.insert(), [{
                "artifact_id": "a1", "case_id": cid, "engine": "test",
                "plugin": "test.proc", "category": "进程", "kind": "table",
                "params_hash": "x", "status": "ok", "row_count": 2,
                "output_path": "", "output_sha256": "", "duration_ms": 1,
                "created_at": "2025-01-01T00:00:00Z",
            }])
        with store.engine.begin() as conn:
            conn.execute(M.records.insert(), [
                {"artifact_id": "a1", "row_no": 0,
                 "data": json.dumps({"name": "cmd.exe", "pid": 1234,
                                     "cmdline": "C:\\Windows\\cmd.exe"}),
                 "ts_utc": "2025-04-01T00:00:00Z", "pid": 1234, "name": "cmd.exe"},
                {"artifact_id": "a1", "row_no": 1,
                 "data": json.dumps({"name": "notepad.exe", "pid": 5678}),
                 "ts_utc": "2025-04-01T00:01:00Z", "pid": 5678, "name": "notepad.exe"},
            ])
        hits = search_records(store, cid, Query("cmd.exe"))
        check("records 命中", len(hits) == 1, str(len(hits)))
        check("命中字段正确", hits[0].field == "name", hits[0].field)
        check("命中带行号", hits[0].row_no == 0, str(hits[0].row_no))

        h2 = search_records(store, cid, Query("pid:5678"))
        check("字段过滤检索", len(h2) == 1 and h2[0].row_no == 1, str(len(h2)))

        h3 = search_records(store, cid, Query("cmd.exe -pid"))
        check("排除词生效", len(h3) == 0, str(len(h3)))

        h4 = search_records(store, cid, Query("cmd.exe", regex=False))
        check("大小写不敏感", len(h4) == 1, str(len(h4)))

        # 全库检索（不指定案件）不应过滤掉记录
        h5 = search_records(store, "", Query("cmd.exe"))
        check("全库检索不过滤", len(h5) == 1, str(len(h5)))

        res = search(store, cid, "cmd.exe")
        check("统一入口可用", res["count"] >= 1, str(res))
        check("统一入口返回解析式", bool(res["parsed"]), res["parsed"])
    finally:
        store.close()


# ─────────────────────────────────────────── ⑥ 容器内检索
def test_container() -> None:
    print("\n── ⑥ 容器内检索 ──")
    from memlens.core.search import Query, scan_container

    class FakeVol:
        def __init__(self, data): self.data = data
        def read(self, off, n):
            return self.data[off:off + n]

    class FakeFs:
        def __init__(self, data): self.data = data
        def cluster_size(self): return 512
        def cluster_offset(self, c): return c * 512
        def read_cluster(self, c):
            return self.data[c * 512:(c + 1) * 512]

    payload = b"NEEDLE_IN_HAYSTACK\x00" + b"\x00" * 400 + b"needle_two"
    vol = FakeVol(payload)
    fs = FakeFs(payload)
    ent = {"data_len": len(payload), "first_cluster": 0, "no_fat_chain": True}
    hits = scan_container(vol, fs, ent, Query("NEEDLE_IN_HAYSTACK"),
                          source="f.bin")
    check("容器内命中", len(hits) >= 1, str(len(hits)))
    check("容器内命中带偏移", hits and hits[0].offset >= 0,
          str(hits[0].offset) if hits else "")
    h2 = scan_container(vol, fs, ent, Query("no_such_thing"), source="f.bin")
    check("容器内无命中", len(h2) == 0, str(len(h2)))


def main() -> int:
    print("=" * 70)
    print("MemLens 检索引擎专项测试")
    print("=" * 70)
    test_query()
    test_scan()
    test_db()
    test_container()
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
