# -*- coding: utf-8 -*-
"""跑真实 45 GiB 全盘扫描（含新增 gd 目标），落缓存 + JSON。"""
import sys, io
sys.path.insert(0, r'D:\MemLens')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from memlens.formats.xfs import open_server_fs
from memlens.core import server_forensics as sf
import json, time

IMG = r'E:\2025平航杯\平航杯题目'
# 与 _extract_files.py 保持完全一致的字面量（\u2764），避免字符集差异
PW = '早起王的爱恋日记\u2764'

t0 = time.time()

def prog(done, total, n_hits):
    pct = done * 100 // total if total else 0
    if pct % 10 == 0 and done % (4 << 30) < (32 << 20):
        print(f"  [进度] {pct}%（{n_hits} 命中）", flush=True)

print('打开容器 → XFS …', flush=True)
x, meta = open_server_fs(IMG, PW)
xs = x.summary()
print(f"  XFS：{xs.get('total_gb')} GB  dblocks={xs.get('dblocks')} "
      f"bs={xs.get('blocksize')} lv={meta.get('lvm_lv')} xfs_offset={meta.get('lvm_offset')}",
      flush=True)

print('全盘内容扫描（9 类特征）…', flush=True)
res = sf.solve_server_fs(x, progress_cb=prog, password='sbwyz1',
                          hits_cache=r'D:\MemLens\work\server_solve_hits.json',
                          rescan=True)
print(f'\n扫描+解析耗时 {time.time()-t0:.1f}s', flush=True)

out = r'D:\MemLens\work\server_solve.json'
open(out, 'w', encoding='utf-8').write(json.dumps(res, ensure_ascii=False, indent=2))
print('JSON →', out, flush=True)

# 摘要
for k, v in res.items():
    if isinstance(v, dict):
        print(f"[{k}] boot={v.get('boot_count')} earliest={v.get('earliest')}", flush=True)
    else:
        print(f"[{k}] 命中 {len(v)} 项", flush=True)
