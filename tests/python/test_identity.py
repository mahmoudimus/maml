"""The function-identity verdict logic, tested without BinDiff.

The whole point of splitting `identity.py` out of the CLI is that this file
needs no database, no BinExport, and no 100 MB binary -- so the instrument
built to catch silent measurement errors is itself checked on every run,
including on machines where BinDiff is not installed.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools" / "identity"))
from identity import (AddressSpaceError, Claim, MatchIndex, Verdict,  # noqa: E402
                      classify, summarise)

BASE_A = 0x7FFB14D00000          # measured on a real pair; the two DIFFER,
BASE_B = 0x7FFB122E0000          # which is the entire hazard this guards


class Row:
    """Stands in for bindiff.core.MatchInfo -- same four attributes."""
    def __init__(self, pa, sa, similarity=0.9, confidence=0.8):
        self.primary_address = pa
        self.secondary_address = sa
        self.similarity = similarity
        self.confidence = confidence


def idx(pairs, base_a=BASE_A, base_b=BASE_B):
    return MatchIndex([Row(base_a + a, base_b + b) for a, b in pairs], base_a, base_b)


def test_the_three_verdicts():
    i = idx([(0x1000, 0x2000), (0x1100, 0x2100)])
    ok = classify(Claim("f", 0x1000, 0x2000), i)
    assert ok.verdict is Verdict.IDENTITY_OK and ok.ok
    assert ok.matched_rva_b == 0x2000

    # The case the whole tool exists for: the address resolved cleanly, in both
    # builds, to a DIFFERENT function. An address-only check calls this success.
    bad = classify(Claim("f", 0x1000, 0x2999), i)
    assert bad.verdict is Verdict.WRONG_FUNCTION and not bad.ok
    assert bad.matched_rva_b == 0x2000      # and it says what the truth was

    assert classify(Claim("f", 0x9999, 0x2000), i).verdict is Verdict.NOT_AN_ENTRY


def test_a_single_imagebase_would_be_silently_wrong():
    """The bug this class refuses to make available.

    Two builds do not share an imagebase. Subtract one from both sides and you
    get a complete, self-consistent map in which every lookup succeeds and every
    answer is off by the difference -- no exception, no empty result, just a
    verifier that confidently verifies nothing.

    MatchIndex has no single-base form, so the mistake cannot be spelled. What
    it CAN detect is the bases being swapped, and it raises rather than
    returning a verdict.
    """
    rows = [Row(BASE_A + 0x1000, BASE_B + 0x2000)]
    # Which SIDE trips depends on which base is larger -- here BASE_B < BASE_A,
    # so the primary check passes and the secondary one catches it. Asserting
    # the specific side would be pinning an accident of these two constants;
    # asserting that it raises at all is the actual contract.
    with pytest.raises(AddressSpaceError, match="imagebase"):
        MatchIndex(rows, BASE_B, BASE_A)          # swapped

    # And the correct construction is unremarkable, so the guard is not just
    # rejecting everything.
    assert len(MatchIndex(rows, BASE_A, BASE_B)) == 1


def test_an_empty_match_table_raises_rather_than_reporting_perfection():
    """An empty index calls every claim NOT_AN_ENTRY, which reads as a result.

    This is the exact failure mode that made a wrong-binary harness report
    "no candidates" for nine targets that were simply not in the image.
    """
    with pytest.raises(AddressSpaceError, match="match table is empty"):
        MatchIndex([], BASE_A, BASE_B)


def test_an_out_of_range_address_is_an_error_not_a_miss():
    """Wrong image, not wrong answer.

    Nine real targets were once reported unanchorable because the harness was
    aimed at a 42 MB loader while they lived in a 115 MB client. Every address
    was past the end. The tool said "no candidates"; the truth was "you are
    searching the wrong file".
    """
    i = idx([(0x1000, 0x2000)])
    with pytest.raises(AddressSpaceError, match="outside build A"):
        classify(Claim("f", 0x500000, 0x2000), i, size_a=0x10000, size_b=0x10000)
    with pytest.raises(AddressSpaceError, match="outside build B"):
        classify(Claim("f", 0x1000, 0x500000), i, size_a=0x10000, size_b=0x10000)

    # In range, the same call is an ordinary verdict.
    assert classify(Claim("f", 0x1000, 0x2000), i,
                    size_a=0x10000, size_b=0x10000).ok


def test_summarise_reports_the_gap_not_just_the_successes():
    """`wrong_function_rate` IS the 5-13% figure, measured rather than caveated.

    Its denominator is deliberately the CHECKABLE set -- claims BinDiff had an
    opinion about -- not the total. Dividing by the total would let a run with
    many unmatched claims report a flattering rate.
    """
    i = idx([(0x1000, 0x2000), (0x1100, 0x2100), (0x1200, 0x2200)])
    rs = [classify(Claim("a", 0x1000, 0x2000), i),   # OK
          classify(Claim("b", 0x1100, 0x9999), i),   # WRONG
          classify(Claim("c", 0x7777, 0x2200), i)]   # NOT_AN_ENTRY
    s = summarise(rs)
    assert s["identity_verified"] == 1
    assert s["wrong_function"] == 1
    assert s["checkable"] == 2                        # the NOT_AN_ENTRY is excluded
    assert s["wrong_function_rate"] == 0.5
    assert s["counts"]["NOT_AN_ENTRY"] == 1


def test_no_checkable_claims_reports_none_not_zero():
    """A rate of 0.0 would read as "nothing was wrong". Nothing was CHECKED."""
    i = idx([(0x1000, 0x2000)])
    s = summarise([classify(Claim("x", 0x7777, 0x2000), i)])
    assert s["checkable"] == 0
    assert s["wrong_function_rate"] is None
