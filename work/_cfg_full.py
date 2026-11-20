# -*- coding: utf-8 -*-
# 读取 config.php 完整内容（raw off 1179660015 / 933907749），提取 AUTH_CODE + 密码
import sys, struct, re, hashlib
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

def html_unescape(s):
    import html
    return html.unescape(s)

for off in (1179660015, 933907749):
    start = off - 512
    buf = x.read(start, 4096)
    # 找 AUTH_CODE 上下文
    i = buf.find(b"AUTH_CODE")
    ctx = buf[max(0,i-256):i+512].decode("latin-1", "replace")
    print(f"=== off {off} (blk {off//4096}) ===")
    print(html_unescape(ctx))
    print()
