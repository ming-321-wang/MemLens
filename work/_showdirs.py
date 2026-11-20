# -*- coding: utf-8 -*-
import json
d = json.load(open(r"D:\MemLens\work\_lvm_dirs.json"))
t = {1: "f", 2: "d", 3: "l", 4: "c", 5: "b", 6: "f", 7: "s"}
for owner in sorted(int(k) for k in d):
    ents = d[str(owner)]
    print(f"=== owner {owner} ({len(ents)}) ===")
    for ino, ft, nm in sorted(ents, key=lambda x: x[0])[:40]:
        print(f"   ino={ino:<8} [{t.get(ft, '?')}] {nm}")
