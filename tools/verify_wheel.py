"""Prove an installed maml wheel actually works, from outside the source tree.

Run by CIBW_TEST_COMMAND against the built wheel. Three properties, none of
which a successful `pip install` establishes on its own:

  1. the extension imports and its version matches what was packaged;
  2. the SIMD backend compiled in is the one this platform should have --
     `scan_literal` keeps a correct memchr fallback, so a build that selected
     no vector path passes every functional test while quietly costing ~1.9x.
     Pass --expect-simd to make that a hard failure instead of a shrug;
  3. a real scan returns a real hit, which is the only check that separates
     "the wheel has a loadable .so in it" from "the wheel does its job".

Must be run from a directory that is NOT the source tree: `import maml`
succeeding next to python/maml/ proves nothing about the wheel.
"""

import argparse
import os
import pathlib
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    # An argument, not just an environment variable: cibuildwheel runs the
    # Linux legs inside a container, and an env var that silently fails to
    # cross that boundary turns this check into a no-op that still prints
    # "wheel OK". The env var stays as a fallback for local runs.
    ap.add_argument("--expect-simd", choices=("neon", "sse2", "scalar"),
                    default=os.environ.get("MAML_EXPECT_SIMD"))
    args = ap.parse_args(argv)

    import maml

    here = pathlib.Path.cwd().resolve()
    mod = pathlib.Path(maml.__file__).resolve()
    print(f"maml {maml.__version__} from {mod}")
    print(f"  cwd:          {here}")
    print(f"  simd_backend: {maml.simd_backend()}")

    # "Installed" means site-packages, not merely "outside the cwd". The
    # earlier test -- is the module under the current directory -- called a
    # venv living in the cwd a source tree, which is exactly what the sdist
    # check does: it makes /tmp/sd and then runs from /tmp.
    if not any(part in ("site-packages", "dist-packages") for part in mod.parts):
        return fail(f"imported from {mod}, which is not under site-packages; "
                    "this is the source tree, not an installed distribution")

    # 1. the packaged version and the compiled headers agree
    from importlib.metadata import version as dist_version
    packaged, compiled = dist_version("maml"), maml.__version__
    if packaged != compiled:
        return fail(f"dist version {packaged} != extension version {compiled}")
    print(f"  version:      {packaged} (dist and extension agree)")

    # 2. the vector backend is the one this platform should have
    expect = args.expect_simd
    got = maml.simd_backend()
    if expect:
        if got != expect:
            return fail(f"expected SIMD backend {expect!r}, got {got!r} -- the "
                        "wheel would ship the scalar fallback")
        print(f"  simd:         {got} as expected")
    elif got == "scalar":
        print("  WARNING: scalar backend; no --expect-simd given to enforce it")

    # 3. it actually scans
    img = bytes([0x90] * 64 + [0x4C, 0x8B, 0xD0] + [0x90] * 64)
    hit = maml.Pattern("4C 8B D0").find(maml.Image.from_bytes(img))
    if hit is None or hit.offset != 64:
        return fail(f"scan returned {hit!r}; expected a hit at offset 64")
    print(f"  scan:         hit at offset {hit.offset}")

    from maml import v1
    semantic = v1.Image(bytes.fromhex("E8 01 00 00 00 90 CC"))
    result = v1.Pipeline('bytes("E8 rel32(x):follow CC") -> capture("x") -> unique').run(semantic)
    if result.values != (v1.CaptureValue(6, "ResolvedRelativeTarget", "image"),):
        return fail("semantic pipeline did not resolve its named capture")
    print("  maml-v1:      named capture and pipeline passed")

    print("wheel OK")
    return 0


def fail(msg: str) -> int:
    print(f"::error::{msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
