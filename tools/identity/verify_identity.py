#!/usr/bin/env python3
"""Verify claimed correspondences against BinDiff's function matching.

    verify_identity.py --diff A_vs_B.BinDiff \
                       --primary A.dll --secondary B.dll \
                       --claims claims.tsv [--out verdicts.tsv]

`--claims` is `name <TAB> rva_a <TAB> rva_b` (hex, `0x` optional), which is the
shape of the target tables this project already passes around. Comment lines
start with `#`; a header row naming the columns is tolerated.

    verify_identity.py ... --from-maml --sample 200

instead DERIVES the claims: it takes function entries from build A, generates
anchors with maml.generate, resolves each in build B, and asks BinDiff
whether the address it resolved to is the same FUNCTION. That is the
re-derivation -- it reports what generate::verified() would have said next to
what identity actually supports, and the gap between them is the number this
tool exists to produce.

Exits non-zero if any claim comes back WRONG_FUNCTION, so it can gate.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from identity import (AddressSpaceError, Claim, MatchIndex, Verdict,  # noqa: E402
                      classify, summarise)

BINDIFF_PY = pathlib.Path.home() / "src/idapro/bindiff/python"


def _load_bindiff():
    """Import `bindiff`, falling back to the sibling source tree.

    Named separately so the failure says which of the two it was: the package
    missing is a setup problem, the database being unreadable is a data one.
    """
    try:
        import bindiff  # noqa: F401
        return bindiff
    except ImportError:
        if BINDIFF_PY.is_dir():
            sys.path.insert(0, str(BINDIFF_PY))
            try:
                import bindiff  # noqa: F811
                return bindiff
            except ImportError:
                pass
    raise SystemExit(
        "bindiff is not importable. Install bindiff-ng, or place its Python\n"
        f"package at {BINDIFF_PY}. This tool cannot approximate it: guessing\n"
        "at function identity is what it exists to replace.")


def _pe_facts(path):
    """(imagebase, virtual size) for a PE, via lief."""
    import lief
    b = lief.parse(str(path))
    if b is None:
        raise SystemExit(f"cannot parse {path}")
    end = max(s.virtual_address + max(s.virtual_size, len(s.content))
              for s in b.sections)
    return b.optional_header.imagebase, end


def read_target_table(path, col_a, col_b):
    """Read a consumer target table: a header row naming the columns.

    Supports the shape these tables actually arrive in -- name, kind, several
    per-build address columns, and per-build witness counts -- rather than
    requiring it be reshaped first. Reshaping by hand is where a column gets
    swapped, and a swapped address column produces a full set of confident
    WRONG_FUNCTION verdicts that look like a finding.
    """
    lines = [l for l in pathlib.Path(path).read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    if not lines:
        raise SystemExit(f"{path}: empty")
    header = lines[0].split("\t")
    need = [col_a, col_b]
    for c in need:
        if c not in header:
            raise SystemExit(
                f"{path}: no column {c!r}. Columns are: {', '.join(header)}")
    ia, ib = header.index(col_a), header.index(col_b)
    iname = header.index("name") if "name" in header else 0
    ikind = header.index("kind") if "kind" in header else None
    wa = header.index(f"witnesses_{col_a.lstrip('b')}") if f"witnesses_{col_a.lstrip('b')}" in header else None
    wb = header.index(f"witnesses_{col_b.lstrip('b')}") if f"witnesses_{col_b.lstrip('b')}" in header else None

    out, dropped = [], 0
    for raw in lines[1:]:
        f = raw.split("\t")
        if max(ia, ib) >= len(f):
            dropped += 1
            continue
        a, b = f[ia].strip(), f[ib].strip()
        if a in ("-", "") or b in ("-", ""):
            dropped += 1                      # absent in one build: not a failure
            continue
        try:
            rva_a, rva_b = int(a, 16), int(b, 16)
        except ValueError:
            dropped += 1
            continue
        w = None
        if wa is not None and wb is not None and max(wa, wb) < len(f):
            try:
                w = min(int(f[wa]), int(f[wb]))
            except ValueError:
                w = None
        out.append(Claim(f[iname], rva_a, rva_b,
                         f[ikind] if ikind is not None and ikind < len(f) else "", w))
    if not out:
        raise SystemExit(f"{path}: no usable rows in columns {col_a}/{col_b}")
    print(f"# table      {len(out)} claims from {path} ({col_a} -> {col_b}), "
          f"{dropped} rows skipped (missing in one build)", file=sys.stderr)
    return out


def read_claims(path):
    out = []
    for lineno, raw in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) < 3:
            raise SystemExit(f"{path}:{lineno}: want `name<TAB>rva_a<TAB>rva_b`")
        name, a, b = parts[0], parts[1], parts[2]
        try:
            out.append(Claim(name, int(a, 16), int(b, 16)))
        except ValueError:
            if lineno == 1:
                continue                      # a header row, not an error
            raise SystemExit(f"{path}:{lineno}: {a!r}/{b!r} are not hex addresses")
    if not out:
        raise SystemExit(f"{path}: no claims. An empty run reports 100% and means nothing")
    return out


def claims_from_maml(primary, secondary, sample):
    """Generate anchors in A, resolve them in B, and claim the result.

    This is the honest version of the durability measurement: every claim it
    emits is one generate::verified() would have called a success, so the
    verdicts below are a direct audit of that function's output.
    """
    import maml
    from maml import generate

    img_a = maml.Image.from_pe(str(primary))
    img_b = maml.Image.from_pe(str(secondary))
    if not img_a.funcs:
        raise SystemExit(f"{primary} has no .pdata; nothing to sample")

    step = max(1, len(img_a.funcs) // sample)
    claims, skipped, out_of_range = [], 0, 0
    for r in img_a.funcs[::step][:sample]:
        cands = generate.candidates(img_a, r.begin)
        resolved = None
        for c in cands:
            try:
                p = maml.Pattern(c.pattern)
            except Exception:
                continue
            hits = p.prime(img_b).find_all(c.save_index, 2)
            if len(hits) != 1:
                continue
            got = hits[0].value if c.save_index else hits[0].offset - c.anchor_delta
            # A UNIQUE MATCH IS NOT A SANE ANSWER. A capturing pattern can
            # match exactly once and still capture a displacement that points
            # nowhere -- the first real run of this tool produced 0xc1608c5c
            # against a 0x2802764-byte image. verified() would reject it for
            # not equalling the target, so this is not a defect in generate;
            # it is a reminder that "resolved uniquely" and "resolved to an
            # address" are different claims. Counted, never silently dropped.
            if not (0 <= got < img_b.size):
                out_of_range += 1
                continue
            resolved = got
            break
        if resolved is None:
            skipped += 1
            continue
        claims.append(Claim(f"fn_{r.begin:x}", r.begin, resolved))
    return claims, skipped, out_of_range


def run_durability(args, index, size_b):
    """Two-build durability, with BinDiff supplying build B's ground truth.

    Every durability number this project has published used an ADDRESS map to
    say where a target went. That map is the weaker invariant: it can be right
    about the address and wrong about the function. Here BinDiff names build
    B's counterpart, verified() is asked to anchor that pair, and the resulting
    percentage rests on function identity.

    Not circular. BinDiff supplies the target; verified() still has to find
    byte patterns that resolve to it, in both images, on their own merits.
    """
    import maml
    from maml import generate

    img_a = maml.Image.from_pe(str(args.primary))
    img_b = maml.Image.from_pe(str(args.secondary))
    if not img_a.funcs:
        raise SystemExit(f"{args.primary} has no .pdata; nothing to sample")

    step = max(1, len(img_a.funcs) // args.sample)
    tried = anchored = no_gt = 0
    for r in img_a.funcs[::step][:args.sample]:
        hit = index.lookup(r.begin)
        if hit is None:
            no_gt += 1
            continue                      # BinDiff has no opinion: not a failure
        rva_b = hit[0]
        if not (0 <= rva_b < size_b):
            no_gt += 1
            continue
        tried += 1
        if generate.verified(img_a, r.begin, img_b, rva_b):
            anchored += 1

    print(f"# sampled    {args.sample} function entries from build A", file=sys.stderr)
    print(f"# no ground  {no_gt} had no BinDiff counterpart (excluded, not failed)",
          file=sys.stderr)
    print(f"# DURABILITY {anchored}/{tried} = "
          f"{anchored/tried:.1%} of identity-confirmed targets got a two-build anchor"
          if tried else "# DURABILITY no targets had ground truth", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--diff", required=True, help="a .BinDiff database")
    ap.add_argument("--primary", required=True, help="build A (the diff's primary)")
    ap.add_argument("--secondary", required=True, help="build B (the diff's secondary)")
    ap.add_argument("--claims", help="TSV of name/rva_a/rva_b")
    ap.add_argument("--target-table", help="a consumer target table with a header row")
    ap.add_argument("--col-a", default="b69382", help="address column for build A")
    ap.add_argument("--col-b", default="b69404", help="address column for build B")
    ap.add_argument("--from-maml", action="store_true",
                    help="derive claims by generating and resolving anchors")
    ap.add_argument("--sample", type=int, default=200)
    ap.add_argument("--durability", action="store_true",
                    help="re-derive two-build durability using BinDiff as the "
                         "ground truth for build B, instead of an address map")
    ap.add_argument("--out", help="write per-claim verdicts here as TSV")
    args = ap.parse_args()

    modes = sum(map(bool, (args.claims, args.from_maml, args.durability,
                           args.target_table)))
    if modes != 1:
        raise SystemExit("give exactly one of --claims, --target-table, "
                         "--from-maml, --durability")

    bindiff = _load_bindiff()
    base_a, size_a = _pe_facts(args.primary)
    base_b, size_b = _pe_facts(args.secondary)

    rows = bindiff.load_matches(args.diff)
    try:
        index = MatchIndex(rows, base_a, base_b)
    except AddressSpaceError as e:
        raise SystemExit(
            f"{e}\n\n--primary must be the binary the diff calls PRIMARY and\n"
            "--secondary the one it calls SECONDARY. Swapping them produces a\n"
            "complete map in which every answer is wrong by the base difference.")

    print(f"# diff       {args.diff}", file=sys.stderr)
    print(f"# primary    {args.primary}  base=0x{base_a:x} size=0x{size_a:x}", file=sys.stderr)
    print(f"# secondary  {args.secondary}  base=0x{base_b:x} size=0x{size_b:x}", file=sys.stderr)
    print(f"# matches    {len(index):,}", file=sys.stderr)

    if args.durability:
        return run_durability(args, index, size_b)

    skipped = 0
    if args.claims:
        claims = read_claims(args.claims)
    elif args.target_table:
        claims = read_target_table(args.target_table, args.col_a, args.col_b)
    else:
        claims, skipped, oor = claims_from_maml(
            args.primary, args.secondary, args.sample)
        print(f"# generated  {len(claims)} claims, {skipped} targets produced no "
              f"single-resolving anchor", file=sys.stderr)
        if oor:
            print(f"# discarded  {oor} anchor(s) that matched uniquely but "
                  f"resolved OUTSIDE build B", file=sys.stderr)

    results = [classify(c, index, size_a=size_a, size_b=size_b) for c in claims]

    lines = ["name\tverdict\trva_a\tclaimed_b\tmatched_b\tsimilarity\tconfidence"]
    for r in results:
        lines.append("\t".join([
            r.claim.name, r.verdict.value,
            f"{r.claim.rva_a:x}", f"{r.claim.rva_b:x}",
            f"{r.matched_rva_b:x}" if r.matched_rva_b is not None else "-",
            f"{r.similarity:.3f}" if r.similarity is not None else "-",
            f"{r.confidence:.3f}" if r.confidence is not None else "-"]))
    body = "\n".join(lines)
    if args.out:
        pathlib.Path(args.out).write_text(body + "\n")
    else:
        print(body)

    s = summarise(results)
    print(f"\n# {s['counts']}", file=sys.stderr)
    # A claim corroborated once is an address, not a fact. Reported separately
    # rather than mixed in, so a headline rate is never carried by rows the
    # source itself would not vouch for.
    corr = summarise(results, corroborated_only=True)
    if corr["total"]:
        print(f"# corroborated-only ({corr['total']} of {len(results)} claims, "
              f">=2 witnesses):", file=sys.stderr)
        if corr["checkable"]:
            print(f"#   identity-verified {corr['identity_verified']}/"
                  f"{corr['checkable']} = "
                  f"{corr['identity_verified']/corr['checkable']:.1%}", file=sys.stderr)
    if s["checkable"]:
        print(f"# identity-verified {s['identity_verified']}/{s['checkable']} "
              f"= {s['identity_verified']/s['checkable']:.1%}", file=sys.stderr)
        print(f"# WRONG FUNCTION    {s['wrong_function']}/{s['checkable']} "
              f"= {s['wrong_function_rate']:.1%}  <- what an address-only check "
              f"reports as success", file=sys.stderr)
    return 1 if s["wrong_function"] else 0


if __name__ == "__main__":
    sys.exit(main())
