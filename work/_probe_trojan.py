# -*- coding: utf-8 -*-
"""只开卷不解密全盘：按 blk 回读 config.json 所在区域，验证 _extract_json_at。"""
import io, sys, json
sys.path.insert(0, r'D:\MemLens')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from memlens.formats.xfs import open_server_fs
from memlens.core import server_forensics as sf

IMG = r'E:\2025平航杯\平航杯题目'
PW = '早起王的爱恋日记\u2764'
x, meta = open_server_fs(IMG, PW)
for blk in (2999996, 3000143, 3037497, 5928600):
    off = blk * 4096
    big = x.read(max(0, off - (1 << 20)), (64 << 20) - (1 << 20))
    ctx = big.decode('utf-8', 'replace')
    js = sf._extract_json_at(ctx)
    print('=' * 12, 'blk', blk, 'json_len', len(js))
    print('  has run_type:', 'run_type' in js, '| wyzshop1:', 'wyzshop1' in js)
    if js:
        try:
            print('   parsed ->', json.dumps(sf.parse_trojan_config(js), ensure_ascii=False)[:300])
        except Exception as e:
            print('   parse err:', e)