"""Function-identity verification: the verdict logic, with no I/O.

WHAT THIS IS FOR

`generate::verified()` asserts that a pattern resolves to THE ADDRESS I NAMED,
in two independent builds. That is an *address* assertion, and it is the weaker
of the two invariants anyone actually means. What a caller wants is a *function
identity* assertion: that the thing found in build B is the same function as the
thing named in build A.

The gap between them is not hypothetical. METHOD.md records that 5-13% of
patterns resolving to exactly one address in a later build resolve to the WRONG
function -- and that figure is a caveat rather than a measurement precisely
because nothing could check identity. BinDiff can. This module is the half of
that check which can be tested without BinDiff installed.

WHY THE LOGIC IS SPLIT OUT

Three errors in two days shared one shape: a measurement that returned a
plausible value while pointing at the wrong thing. A blind REX mask manufactured
false uniqueness; a harness aimed at the wrong module reported "no candidates"
instead of "address out of range"; a global drifted three different deltas
across four builds with nothing complaining. An instrument built to catch that
class must not belong to it, so everything here fails loudly and everything here
is testable with no database, no BinExport, and no 100 MB binary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    """What BinDiff says about one claimed correspondence."""

    IDENTITY_OK = "IDENTITY_OK"          # matched A -> B exactly as claimed
    WRONG_FUNCTION = "WRONG_FUNCTION"    # matched A -> something else entirely
    UNMATCHED = "UNMATCHED"              # A is known, but has no counterpart
    NOT_AN_ENTRY = "NOT_AN_ENTRY"        # A is not a function entry at all


class AddressSpaceError(ValueError):
    """Raised when an address cannot mean what the caller thinks it means.

    Its own category because it is the error this tool exists to stop being
    silent. Every instance is a question that should never have been asked, not
    an answer of `False`.
    """


@dataclass(frozen=True)
class Claim:
    """One asserted correspondence, in RVA space.

    `witnesses` is how many independent derivations agreed on this pair, when
    the source knows. It is carried because a claim corroborated once is an
    ADDRESS, not a fact -- 65 of one 132-row table are single-witness in both
    builds -- and a verdict against an uncorroborated claim tells you about the
    claim as much as about the pattern. `None` means the source did not say,
    which is different from 1.
    """

    name: str
    rva_a: int
    rva_b: int
    kind: str = ""
    witnesses: int | None = None

    @property
    def corroborated(self) -> bool:
        return self.witnesses is not None and self.witnesses >= 2


@dataclass(frozen=True)
class Result:
    claim: Claim
    verdict: Verdict
    matched_rva_b: int | None      # what BinDiff actually matched A to
    similarity: float | None
    confidence: float | None

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.IDENTITY_OK


class MatchIndex:
    """BinDiff's primary->secondary function map, normalised to RVAs.

    THE IMAGEBASES ARE SEPARATE ARGUMENTS AND BOTH ARE REQUIRED. BinDiff emits
    VAs, and two builds of the same binary do not share an imagebase -- measured
    on one real pair, 0x7ffb14d00000 against 0x7ffb122e0000. Subtracting one
    base from both sides yields a complete, self-consistent, entirely wrong map:
    every lookup succeeds and every answer is off by the difference. There is no
    default and no single-base convenience form, because the convenient form is
    the bug.
    """

    def __init__(self, rows, primary_base: int, secondary_base: int):
        if primary_base < 0 or secondary_base < 0:
            raise AddressSpaceError("imagebases must be non-negative")
        self._primary_base = primary_base
        self._secondary_base = secondary_base
        self._by_rva: dict[int, tuple[int, float, float]] = {}

        n = 0
        for r in rows:
            n += 1
            pa, sa = r.primary_address, r.secondary_address
            if pa < primary_base:
                raise AddressSpaceError(
                    f"primary address 0x{pa:x} is below the primary imagebase "
                    f"0x{primary_base:x} -- the bases are swapped, or these "
                    f"matches belong to a different pair of binaries")
            if sa < secondary_base:
                raise AddressSpaceError(
                    f"secondary address 0x{sa:x} is below the secondary "
                    f"imagebase 0x{secondary_base:x} -- same diagnosis")
            self._by_rva[pa - primary_base] = (
                sa - secondary_base,
                getattr(r, "similarity", None),
                getattr(r, "confidence", None),
            )

        if n == 0:
            raise AddressSpaceError(
                "the match table is empty; a verifier over no matches reports "
                "every claim as NOT_AN_ENTRY, which reads like a result")

    def __len__(self) -> int:
        return len(self._by_rva)

    def lookup(self, rva_a: int):
        return self._by_rva.get(rva_a)


def classify(claim: Claim, index: MatchIndex, *,
             size_a: int | None = None, size_b: int | None = None) -> Result:
    """Verdict for one claim.

    `size_a` / `size_b` are the two images' sizes. Passing them turns "this
    address is not in the match table" into "this address is not in the image",
    which are different problems with the same symptom -- and confusing them is
    how a harness aimed at a 42 MB loader reported nine targets from a 115 MB
    client as simply unanchorable.
    """
    if size_a is not None and not (0 <= claim.rva_a < size_a):
        raise AddressSpaceError(
            f"{claim.name}: rva_a 0x{claim.rva_a:x} is outside build A "
            f"(size 0x{size_a:x}). This is the wrong image, not a miss")
    if size_b is not None and not (0 <= claim.rva_b < size_b):
        raise AddressSpaceError(
            f"{claim.name}: rva_b 0x{claim.rva_b:x} is outside build B "
            f"(size 0x{size_b:x}). This is the wrong image, not a miss")

    hit = index.lookup(claim.rva_a)
    if hit is None:
        return Result(claim, Verdict.NOT_AN_ENTRY, None, None, None)

    got, sim, conf = hit
    if got is None:
        return Result(claim, Verdict.UNMATCHED, None, sim, conf)
    verdict = Verdict.IDENTITY_OK if got == claim.rva_b else Verdict.WRONG_FUNCTION
    return Result(claim, verdict, got, sim, conf)


def summarise(results, *, corroborated_only: bool = False) -> dict:
    """Counts per verdict, plus the number that matter.

    `address_verified` is what generate::verified() would have reported --
    every claim whose address resolved. `identity_verified` is the subset
    BinDiff agrees is the same function. The DIFFERENCE is the quantity this
    whole tool exists to produce: it is the 5-13% figure, measured instead of
    caveated.
    """
    results = [r for r in results
               if not corroborated_only or r.claim.corroborated]
    counts = {v: 0 for v in Verdict}
    for r in results:
        counts[r.verdict] += 1
    checked = counts[Verdict.IDENTITY_OK] + counts[Verdict.WRONG_FUNCTION]
    return {
        "total": len(results),
        "counts": {v.value: c for v, c in counts.items()},
        "checkable": checked,
        "identity_verified": counts[Verdict.IDENTITY_OK],
        "wrong_function": counts[Verdict.WRONG_FUNCTION],
        "wrong_function_rate": (counts[Verdict.WRONG_FUNCTION] / checked) if checked else None,
    }
