import json, os, pathlib, sqlite3, struct
import lief
BASE = pathlib.Path(os.environ.get("MAML_DUMPS", "/Volumes/code/re/eidolon"))
OUT = pathlib.Path(os.environ.get("MAML_DURABILITY_DIR", "/tmp/eido"))

# The BinDiff primary is the -deob variant, not the -devirt one already
# flattened, so it needs its own image.
src = BASE/"12.1.0.69497/WowT_loader-12.1.0.69497-deob.dll"
b = lief.parse(str(src))
end = max(s.virtual_address + max(s.virtual_size, len(s.content)) for s in b.sections)
buf = bytearray(end)
for s in b.sections:
    d = bytes(s.content)
    buf[s.virtual_address:s.virtual_address+len(d)] = d
(OUT/"69497deob.img").write_bytes(buf)
ib_primary = b.optional_header.imagebase
def rng(n):
    s = next((x for x in b.sections if x.name == n), None)
    return None if s is None else (s.virtual_address, s.virtual_address+s.virtual_size)
txt = rng(".text")
# funcs matter as much as code and rodata: without them a `func` pipeline
# stage has no substrate and every pipeline fails. That is a CONFIGURATION
# failure, not a durability result -- and it read as "0 of 40 survived" until
# the executor's own error message was actually read.
pd = next((x for x in b.sections if x.name == ".pdata"), None)
funcs = []
if pd is not None:
    import struct as _s
    raw = bytes(pd.content)
    for off in range(0, (len(raw)//12)*12, 12):
        beg, fin, unw = _s.unpack_from("<III", raw, off)
        if not beg or fin <= beg or fin > len(buf):
            continue
        if not (txt[0] <= beg < txt[1]):
            continue
        # UNW_FLAG_CHAININFO fragments are not function starts; generate.hpp
        # states that precondition in bold.
        if unw < len(buf) and ((buf[unw] >> 3) & 0x4):
            continue
        funcs.append((beg, fin))

with open(OUT/"69497deob.txt","w") as f:
    f.write(f"size {len(buf)}\n")
    f.write(f"code {txt[0]} {txt[1]}\n")
    for n in (".rdata",".data"):
        r = rng(n)
        if r: f.write(f"rodata {r[0]} {r[1]}\n")
    for a, z in funcs:
        f.write(f"func {a} {z}\n")
print(f"69497deob: {len(funcs)} funcs from .pdata")
print(f"69497deob: {len(buf)/1e6:.1f}MB text={txt} imagebase=0x{ib_primary:x}")

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
