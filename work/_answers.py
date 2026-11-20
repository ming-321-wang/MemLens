# -*- coding: utf-8 -*-
"""读 MemLens server-solve 的 JSON 结果，打印每题答案（供教程核对）。"""
import json, os, sys

P = r'D:\MemLens\work\server_solve.json'
if not os.path.exists(P):
    print('JSON 尚未生成:', P); sys.exit(0)
r = json.load(open(P, encoding='utf-8'))

def first(name, key=None):
    items = r.get(name) or []
    if not isinstance(items, list) or not items:
        return None
    d = items[0].get('result', items[0])
    if key:
        return d.get(key) if isinstance(d, dict) else None
    return d

print('== 题1 开机时间（wtmp）==')
w = r.get('wtmp') or {}
print('  记录数:', w.get('boot_count'))
print('  最早  :', w.get('earliest'), ' 内核', w.get('earliest_kernel'))
print('  最新  :', w.get('latest'))
print('  全部开机记录:')
for b in w.get('boots', []):
    print('    -', b.get('boot_str'), b.get('kernel'), '(blk %s)' % b.get('blk'))

print('\n== 题2 当前内核 ==')
print('  （取最新一次开机记录的内核）', (w.get('boots') or [{}])[-1].get('kernel'))

print('\n== 题3 用户数（passwd）==')
d = first('passwd')
print('  count =', d and d.get('count'))
for u in (d or {}).get('users', []):
    print('   -', u)

print('\n== 题4/5/6 Trojan 配置 ==')
d = first('trojan')
print('  ', json.dumps(d, ensure_ascii=False))

print('\n== 题7 密码加密（config）==')
d = first('config')
print('  ', json.dumps(d, ensure_ascii=False))

print('\n== 题9/14 SQL ==')
d = first('sql')
print('  orders =', d and d.get('orders'), ' total_rows =', d and d.get('total_insert_rows'))
g = (d or {}).get('gap') or {}
print('  最短间隔用户:', json.dumps(g.get('best'), ensure_ascii=False))

print('\n== 题11/12 access.log ==')
d = first('access')
print('  line:', (d or {}).get('line'))
ws = (d or {}).get('webshell') or {}
for s in ws.get('webshells', []):
    print('  一句话木马:', s['payload'])
    print('  SHA-256   :', s['sha256_upper'])

print('\n== 题13 RDP 账号（result.txt）==')
d = first('result')
print('  line:', (d or {}).get('line'))

print('\n== 题8 PHP-GD 版本 ==')
d = first('gd')
print('  literals :', (d or {}).get('gd_literals'))
print('  versions :', (d or {}).get('version_candidates'))
