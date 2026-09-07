"""Flatten each PE into an RVA-addressed image plus a manifest.

maml indexes straight into Image::bytes with no image-base subtraction, so
the buffer has to be laid out by RVA rather than by file offset. Function
starts come from .pdata (the x64 exception directory), which gives a complete
list with no symbols -- these binaries export exactly one name.
"""
import json, os, pathlib, struct, sys
import lief

BASE = pathlib.Path(os.environ.get("MAML_DUMPS", "/Volumes/code/re/eidolon"))
OUT = pathlib.Path(os.environ.get("MAML_DURABILITY_DIR", "/tmp/eido"))
BUILDS = {
    "69273": BASE / "12.1.0.69273/WowT_loader-12.1.0.69273-devirt.dll",
    "69382": BASE / "12.1.0.69382/WowT_loader-12.1.0.69382-devirt.dll",
    "69404": BASE / "12.1.0.69404/Wow_loader-12.1.0.69404-devirt.dll",
    "69497": BASE / "12.1.0.69497/Wow_loader-12.1.0.69497-devirt.dll",
}

for tag, path in BUILDS.items():
    b = lief.parse(str(path))
    end = max(s.virtual_address + max(s.virtual_size, len(s.content)) for s in b.sections)
    buf = bytearray(end)
    for s in b.sections:
        data = bytes(s.content)
        buf[s.virtual_address:s.virtual_address + len(data)] = data
    (OUT / f"{tag}.img").write_bytes(buf)

    def rng(name):
        s = next((x for x in b.sections if x.name == name), None)
        return None if s is None else [s.virtual_address, s.virtual_address + s.virtual_size]

    pd = next(s for s in b.sections if s.name == ".pdata")
    d = bytes(pd.content)
    txt = next(s for s in b.sections if s.name == ".text")
    lo, hi = txt.virtual_address, txt.virtual_address + txt.virtual_size
    funcs = []
    for i in range(len(d) // 12):
        beg, fin, _ = struct.unpack_from("<III", d, i * 12)
        if beg and lo <= beg < hi and fin > beg:
            funcs.append([beg, min(fin, hi)])
    funcs.sort()

    man = {"tag": tag, "size": len(buf), "code": [rng(".text")],
           "rodata": [r for r in (rng(".rdata"), rng(".data")) if r],
           "funcs": funcs}
    (OUT / f"{tag}.json").write_text(json.dumps(man))
    print(f"{tag}: image {len(buf)/1e6:.1f}MB  text {rng('.text')}  funcs {len(funcs)}")

# A trivial line format instead of JSON: the measurement harness is C++, and a
# hand-rolled JSON scan that silently mis-parses one range would corrupt every
# number downstream with no visible symptom.
for tag in BUILDS:
    man = json.loads((OUT / f"{tag}.json").read_text())
    with open(OUT / f"{tag}.txt", "w") as f:
        f.write(f"size {man['size']}\n")
        for a, b in man["code"]:
            f.write(f"code {a} {b}\n")
        for a, b in man["rodata"]:
            f.write(f"rodata {a} {b}\n")
        for a, b in man["funcs"]:
            f.write(f"func {a} {b}\n")
    print(f"{tag}.txt written")
