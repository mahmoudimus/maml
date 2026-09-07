import pytest

import maml


def test_a_valid_pattern_constructs():
    p = maml.Pattern("E8 $ { ' } [3-5] 4C 8B D0")
    assert isinstance(p, maml.Pattern)


def test_repr_shows_the_source_text():
    assert "4C 8B D0" in repr(maml.Pattern("4C 8B D0"))


@pytest.mark.parametrize("bad", ["48 8B [5-", "48 8B {", "48 8B ZZ", "[3-2]"])
def test_malformed_patterns_raise_PatternError(bad):
    with pytest.raises(maml.PatternError):
        maml.Pattern(bad)


def test_PatternError_is_a_ValueError():
    # Callers should be able to catch it without importing our type.
    with pytest.raises(ValueError):
        maml.Pattern("48 8B {")


def test_PatternError_carries_the_span_the_parser_produced():
    # The whole reason this is not just `return None`: it points at the
    # characters that broke, which the C++ parser already computed. This
    # only validates the shape of the span (in-bounds, start <= end); it
    # would pass even if start/end were swapped or always (0, len). It is
    # kept for cheap coverage of the general contract, but the test below is
    # the one that actually pins the parser's behavior.
    with pytest.raises(maml.PatternError) as ei:
        maml.Pattern("48 8B {")
    err = ei.value
    assert isinstance(err.kind, str) and err.kind
    assert isinstance(err.start, int) and isinstance(err.end, int)
    assert 0 <= err.start <= err.end <= len("48 8B {")


@pytest.mark.parametrize("bad,kind,start,end,blamed", [
    ("48 8B {",   "UnexpectedToken",               6, 7, "{"),
    ("48 8B ZZ",  "HexValueInvalid",               6, 8, "ZZ"),
    ("[3-2]",     "RangeEndMustBeGraterThenStart", 3, 4, "2"),
    ("48 8B [5-", "UnexpectedEnd",                 9, 9, ""),
])
def test_the_span_points_at_the_characters_that_broke(bad, kind, start, end, blamed):
    with pytest.raises(maml.PatternError) as ei:
        maml.Pattern(bad)
    err = ei.value
    assert err.kind == kind
    assert (err.start, err.end) == (start, end)
    assert bad[err.start:err.end] == blamed
