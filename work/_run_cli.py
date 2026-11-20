# -*- coding: utf-8 -*-
"""走 MemLens 真实 CLI 入口跑 server-solve（用命中缓存，不重扫全盘）。
口令里的 ❤ 走 Python 字面量，避免命令行编码把字符改坏。"""
import io, sys
sys.path.insert(0, r'D:\MemLens')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from memlens.cli import main

IMG = r'E:\2025平航杯\平航杯题目'
PW = '早起王的爱恋日记\u2764'
sys.exit(main(['server-solve', IMG, '--password', PW, '--plain', 'sbwyz1', '--json']))
