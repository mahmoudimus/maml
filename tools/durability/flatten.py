"""Flatten each PE into an RVA-addressed image plus a manifest.

maml indexes straight into Image::bytes with no image-base subtraction, so
the buffer has to be laid out by RVA rather than by file offset. Function
entries and coverage come from resolved .pdata unwind records. This table
need not enumerate every function, particularly leaf functions.
"""
import json, os, pathlib
from maml._containers import flatten_pe

BASE = pathlib.Path(os.environ.get("MAML_DUMPS", "/Volumes/code/re/eidolon"))
OUT = pathlib.Path(os.environ.get("MAML_DURABILITY_DIR", "/tmp/eido"))
BUILDS = {
    "69273": BASE / "12.1.0.69273/WowT_loader-12.1.0.69273-devirt.dll",
    "69382": BASE / "12.1.0.69382/WowT_loader-12.1.0.69382-devirt.dll",
    "69404": BASE / "12.1.0.69404/Wow_loader-12.1.0.69404-devirt.dll",
    "69497": BASE / "12.1.0.69497/Wow_loader-12.1.0.69497-devirt.dll",
}


def write_build(path, tag, out):
    buf, sections, code, rodata, functions = flatten_pe(path)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{tag}.img").write_bytes(buf)
    man = {"tag": tag, "size": len(buf),
           "code": [[r.begin, r.end] for r in code],
           "rodata": [[r.begin, r.end] for r in rodata],
           "functions": [{"entry": f.entry, "spans": f.spans} for f in functions]}
    (out / f"{tag}.json").write_text(json.dumps(man))
    with open(out / f"{tag}.txt", "w") as f:
        f.write(f"size {len(buf)}\n")
        for kind in ("code", "rodata"):
            for lo, hi in man[kind]:
                f.write(f"{kind} {lo} {hi}\n")
        for fn in functions:
            for lo, hi in fn.spans:
                f.write(f"function {fn.entry} {lo} {hi}\n")
    print(f"{tag}: image {len(buf)/1e6:.1f}MB, {len(functions)} function entries")
    return man


if __name__ == "__main__":
    for tag, path in BUILDS.items():
        write_build(path, tag, OUT)
