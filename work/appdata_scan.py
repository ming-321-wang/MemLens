import os, sys
from pathlib import Path
def sz(p):
    t=0
    for r,d,f in os.walk(p):
        for n in f:
            try: t+=os.path.getsize(os.path.join(r,n))
            except OSError: pass
    return t
base=Path(r"C:\Users\WZH\AppData")
for sub in ("Local","Roaming","LocalLow"):
    p=base/sub
    if not p.is_dir(): continue
    rows=[]
    for e in os.scandir(p):
        try:
            s=sz(e.path) if e.is_dir(follow_symlinks=False) else e.stat().st_size
        except OSError: continue
        rows.append((s,e.path))
    rows.sort(reverse=True)
    print(f"=== AppData\\{sub} 前 14 ===")
    for s,n in rows[:14]:
        print(f"  {s/1073741824:8.2f} GB  {n}")
    print()
