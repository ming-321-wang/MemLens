# -*- coding: utf-8 -*-
# 排查：blk 5928345 附近能否 find("reboot\0")；并看 ut_user 实际字节
import sys, struct
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

x, meta = open_server_fs(r"E:\2025平航杯\平航杯题目", "早起王的爱恋日记\u2764")
off = 5928345 * 4096
r = x.read(off, 4096)
print("blk 5928345 读回", len(r), flush=True)
print("find('reboot\\0'):", r.find(b"reboot\x00"), flush=True)
print("find('reboot'):", r.find(b"reboot"), flush=True)
i = r.find(b"reboot")
if i >= 0:
    print("ut_user 32B:", r[i:i + 32], flush=True)
    print("rec 起点 off:", off + i - 44, "blk:", (off + i - 44) // 4096, flush=True)
    rr = x.read(off + i - 44, 384)
    print("ut_type@0:", struct.unpack_from("<h", rr, 0)[0], flush=True)
    print("tv_sec@340:", struct.unpack_from("<i", rr, 340)[0], flush=True)

# 用 find_content 在窄区间验证（max_bytes 覆盖该偏移）
d = x.read(off - (32 << 20), 32 << 20)
print("32MB 窗口内 find:", d.find(b"reboot\x00"), flush=True)
