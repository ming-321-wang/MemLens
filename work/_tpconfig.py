# -*- coding: utf-8 -*-
# 提取 tp_config freight_free 值（题10）+ 搜运行内核 3.10.0-1160.119（题2）
import sys, re, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

# 题10: tp_config freight_free
print("[题10] tp_config @ blk 228044", flush=True)
d = x.read(934069791, 256 << 20)
text = d.decode("utf-8", "replace")
# 找 freight_free 行（shopping group）
for m in re.finditer(r"INSERT INTO `tp_config` VALUES \('(\d+)',\s*'freight_free',\s*'([^']*)',\s*'([^']*)'", text):
    print(f"  freight_free id={m.group(1)} value={m.group(2)} group={m.group(3)}", flush=True)
# 也搜所有 shopping group
for m in re.finditer(r"INSERT INTO `tp_config` VALUES \('(\d+)',\s*'([^']*)',\s*'([^']*)',\s*'shopping'", text):
    print(f"  shopping: {m.group(2)} = {m.group(3)}", flush=True)
