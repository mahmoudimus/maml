import json, os, pathlib, sqlite3, struct
import lief
BASE = pathlib.Path(os.environ.get("MAML_DUMPS", "/Volumes/code/re/eidolon"))
OUT = pathlib.Path(os.environ.get("MAML_DURABILITY_DIR", "/tmp/eido"))

# The BinDiff primary is the -deob variant, not the -devirt one already
# flattened, so it needs its own image.
src = BASE/"12.1.0.69497/WowT_loader-12.1.0.69497-deob.dll"
b = lief.parse(str(src))
from flatten import write_build
manifest = write_build(src, "69497deob", OUT)
buf = (OUT / "69497deob.img").read_bytes()
ib_primary = b.optional_header.imagebase
print(f"69497deob: {len(buf)/1e6:.1f}MB imagebase=0x{ib_primary:x}")

ib_secondary = lief.parse(str(BASE/"12.1.0.69404/Wow_loader-12.1.0.69404-devirt.dll")).optional_header.imagebase
print(f"69404 imagebase=0x{ib_secondary:x}")

db = sqlite3.connect(str(BASE/"12.1.0.69497/WowT_loader-12.1.0.69497-deob.dll_vs_Wow_loader-12.1.0.69404-devirt.BinDiff"))
rows = db.execute("select address1,address2,similarity,confidence from function").fetchall()
pairs, dropped = [], 0
for a1,a2,sim,conf in rows:
    r1, r2 = a1 - ib_primary, a2 - ib_secondary
    if not (0 < r1 < len(buf)) or r2 <= 0:
        dropped += 1; continue
    pairs.append((r2, r1, sim, conf))          # secondary(69404) -> primary(69497deob)
pairs.sort()
print(f"matches: {len(rows)}  usable: {len(pairs)}  dropped(out of range): {dropped}")
hi = [p for p in pairs if p[3] >= 0.5]
print(f"  confidence >= 0.5: {len(hi)}")
with open(OUT/"map.txt","w") as f:
    for r2,r1,sim,conf in pairs:
        f.write(f"{r2} {r1} {conf:.4f}\n")
print("wrote map.txt")
