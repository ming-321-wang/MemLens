# -*- coding: utf-8 -*-
"""从 682 题中筛出内存取证相关题：①附件是内存镜像 ②标题/描述含内存关键词。"""
import json
import re
from pathlib import Path

WORK = Path(r"D:\MemLens\work\qsnctf")
items = json.loads((WORK / "all_challenges.json").read_text(encoding="utf-8"))

MEM_SUFFIX = (".raw", ".mem", ".vmem", ".vmsn", ".sav", ".vmss", ".dmp",
              ".dump", ".dd", ".lime", ".core", ".hiber", ".img", ".bin")
IMG_NAME = re.compile(r"(?i)(mem|memory|dump|镜像|内存)")

KW = ("内存", "memory", "memdump", "dump", "镜像", "volatil", "memproc",
      "vmem", "raw", "取证", "应急", "应急响应", "malware", "恶意",
      "勒索", "webshell", "入侵", "木马", "后门", "安全事件")


def has_mem_file(it):
    for f in (it.get("file_list") or []):
        n = (f.get("file_name") or "").lower()
        if n.endswith(MEM_SUFFIX) or IMG_NAME.search(Path(n).stem):
            return True
    return False


def kw_hits(it):
    text = f"{it.get('question','')} {it.get('description','')}".lower()
    return [k for k in KW if k.lower() in text]


mem_file = [it for it in items if has_mem_file(it)]
kw_only = [it for it in items if not has_mem_file(it) and kw_hits(it)]

print(f"总题数 {len(items)}")
print(f"A. 附件含内存镜像/命名可疑：{len(mem_file)} 题")
print(f"B. 仅关键词命中：{len(kw_only)} 题\n")

print("=" * 80)
print("A 类（有镜像附件，可直接验证内存域）")
print("=" * 80)
for it in mem_file:
    fl = it.get("file_list") or []
    print(f"[{it['id']:>5}] {it['question']:<34} 难度={it.get('difficulty')} "
          f"提交={it.get('answer_count')} tags={[t['name'] for t in (it.get('tag') or [])][:1]}")
    for f in fl:
        print(f"         📎 {f.get('file_name')}  ({f.get('file_size','?')})")

print()
print("=" * 80)
print(f"B 类（关键词命中，前 40）")
print("=" * 80)
for it in kw_only[:40]:
    hits = kw_hits(it)
    print(f"[{it['id']:>5}] {it['question']:<34} 附件={len(it.get('file_list') or [])} "
          f"命中词={hits[:4]}")
    desc = (it.get("description") or "").replace("\n", " ⏎ ")[:150]
    if desc:
        print(f"         {desc}")

(WORK / "mem_file_challenges.json").write_text(json.dumps(mem_file, ensure_ascii=False, indent=1))
(WORK / "kw_only_challenges.json").write_text(json.dumps(kw_only, ensure_ascii=False, indent=1))

# 统计全部附件文件名，看看有哪些类型
print()
print("=" * 80)
print("全部附件后缀分布")
from collections import Counter
c = Counter()
for it in items:
    for f in (it.get("file_list") or []):
        n = f.get("file_name") or ""
        c[Path(n).suffix.lower() or "(无后缀)"] += 1
for suf, n in c.most_common(30):
    print(f"  {suf:<24} {n}")
