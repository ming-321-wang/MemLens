# -*- coding: utf-8 -*-
"""精查 blk 3000143 附近的 run_type 与 JSON 结构。"""
import io, sys, json
sys.path.insert(0, r'D:\MemLens')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from memlens.formats.xfs import open_server_fs

IMG = r'E:\2025平航杯\平航杯题目'
PW = '早起王的爱恋日记\u2764'
x, meta = open_server_fs(IMG, PW)
off = 3000143 * 4096
big = x.read(max(0, off - (1 << 20)), 64 << 20)
ctx = big.decode('utf-8', 'replace')
i = ctx.find('run_type')
print('run_type at', i)
print('context:', repr(ctx[max(0, i - 300):i + 120]))
# 找所有 '{' 在 i 之前的 200 个字符内
r = ctx.rfind('{', 0, i)
print('last { before i at', r, '=>', repr(ctx[r:r + 60]))
# 从 i 附近找配平
from memlens.core.server_forensics import _balanced_brace, _extract_json_at
for st in (r, ctx.rfind('{', 0, i - 50), ctx.rfind('{', 0, i - 10)):
    if st >= 0:
        e = _balanced_brace(ctx, st)
        print(f'  {{ at {st} -> }} at {e} len={e - st + 1 if e>=0 else None}')
print('extract len:', len(_extract_json_at(ctx)))