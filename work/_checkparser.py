# -*- coding: utf-8 -*-
import sys, argparse
sys.path.insert(0, r'D:\MemLens')
from memlens.cli import build_parser
p = build_parser()
for a in p._actions:
    if isinstance(a, argparse._SubParsersAction):
        ch = list(a.choices)
        print("子命令数:", len(ch))
        print("'server-solve' 已注册:", "server-solve" in ch)
        break
