# -*- coding: utf-8 -*-
"""单测：LVM 解析 + open_server_fs 全链路（秒级，不扫 inode）。"""
import sys
sys.path.insert(0, r"D:\MemLens")
sys.path.insert(0, r"D:\MemLens\work")
from _vh import open_vmdk
from memlens.formats.xfs import _VmdkView, lvm_layout, lvm_lv_offset, Xfs

vol, fs, ent, r, vd = open_vmdk()
view = _VmdkView(vd)
PV = 2099200 * 512
lay = lvm_layout(view, PV)
print("pe_start =", lay["pe_start"], " extent_size =", lay["extent_size"], "扇区")
for lv in lay["lvs"]:
    off = lvm_lv_offset(view, PV, lv["name"])
    print(f"  LV {lv['name']:<6} start_pe={lv['start_pe']:<6} "
          f"ext={lv['extent_count']:<6} 字节偏移={off:,} ({off/1024**3:.2f} GiB)")

x = Xfs(view, lvm_lv_offset(view, PV, "root"))
print("\nroot LV 超级块:", x.summary())
print("根目录条目数:", len(x.dir_entries(x.rootino)))
for e in x.dir_entries(x.rootino)[:12]:
    print(f"   [{e['ftype_s']}] {e['name']}")
vol.close()
