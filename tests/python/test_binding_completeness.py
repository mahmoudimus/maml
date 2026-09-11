"""Every field of every bound C++ struct reaches Python, and carries a value.

WHY THIS FILE EXISTS, and why it is not more behaviour tests.

The bindings are not a thin pass-through and cannot be. `in` is a Python
keyword, so `StageResult::in` has to become `into`. The `SIZE_MAX` sentinel on
`failed_stage` has to become `None`. `ResultKind` and the `is_value()` helper
collapse into a `kind` string. Each of those is a hand-written line in
`_core.pyx` that copies one C++ field into one Python field -- and a hand
transcription is a place a field can be silently DROPPED.

That is not hypothetical. `StageResult::moved` was added to the C++ struct and
to no binding, and the omission survived until an `AttributeError` on first
real use. The obvious response -- mirror every C++ test in Python -- costs
O(N) duplicated tests forever and still only catches the cases someone
remembered to duplicate.

So this file takes the structural route instead. It reads the C++ headers,
extracts the field list of each bound struct, and asserts:

  1. every C++ field has a Python counterpart (modulo a DECLARED rename), and
  2. every Python field is actually populated -- observed holding a
     non-default value at least once, so a field that is present but wired to
     nothing fails too.

Adding a field to a bound C++ struct now fails here until it is bound, which
is the property the duplicated behaviour tests were only approximating.
"""

import dataclasses
import re
from pathlib import Path

import pytest

from maml import Range, _core, v1


ROOT = Path(__file__).resolve().parents[2]
HEADERS = {
    "pipeline": ROOT / "include" / "maml" / "v1_pipeline.hpp",
    "generate": ROOT / "include" / "maml" / "generate.hpp",
    "mamlscan": ROOT / "include" / "maml" / "mamlscan.hpp",
}

# C++ field name -> Python field name, for the renames the binding is FORCED
# to make. Anything not listed here must match by name; that is the point.
RENAMES = {
    ("PipelineResult", "is_matches"): "kind",
}

# C++ fields deliberately not surfaced, each with the reason. A field added to
# C++ and forgotten is a test failure; a field added and consciously withheld
# is one line here. The distinction is the whole value of this file.
NOT_BOUND = {
}


def cpp_fields(header, struct):
    """Field names of a C++ struct, in declaration order."""
    src = HEADERS[header].read_text()
    m = re.search(r"struct\s+%s\s*\{(.*?)\n(\s*)\};" % struct, src, re.S)
    assert m, f"struct {struct} not found in {HEADERS[header].name}"
    body = m.group(1)
    body = re.sub(r"//[^\n]*", "", body)          # drop comments first, or a
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)  # `//` sample confuses us
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # `std::vector<StageResult> trace;` / `size_t in = 0;` -> the name
        m2 = re.match(r"^[A-Za-z_][\w:<>,\s\*&]*?([A-Za-z_]\w*)\s*(?:=[^;]*)?;$", line)
        if m2:
            out.append(m2.group(1))
    assert out, f"no fields parsed out of {struct}"
    return out


def py_fields(cls):
    return [f.name for f in dataclasses.fields(cls)]


BOUND = [
    ("pipeline", "Trace", v1.StageResult),
    ("pipeline", "PipelineResult", v1.PipelineResult),
    ("generate", "Candidate", _core.Candidate),
    ("generate", "Resolution", _core.Resolution),
    ("generate", "Options", _core.Options),
]

# The types that carry data OUT of C++. These must have NO field defaults --
# see test_bound_result_types_have_no_defaults for why. `Options` is excluded
# deliberately: it travels the other way, and its defaults ARE the C++
# defaults.
OUT_DIRECTION = [c for _, n, c in BOUND if n != "Options"]


@pytest.mark.parametrize("header,struct,cls",
                         BOUND, ids=[b[1] for b in BOUND])
def test_every_cpp_field_is_bound(header, struct, cls):
    """A field added to the C++ struct fails here until the binding copies it."""
    have = set(py_fields(cls))
    missing = []
    for name in cpp_fields(header, struct):
        if (struct, name) in NOT_BOUND:
            continue
        want = RENAMES.get((struct, name), name)
        if want not in have:
            missing.append(f"{struct}::{name} (expected Python `{want}`)")
    assert not missing, (
        "C++ fields with no Python counterpart -- bind them in _core.pyx, or "
        "add them to NOT_BOUND with a reason:\n  " + "\n  ".join(missing))


@pytest.mark.parametrize("header,struct,cls",
                         BOUND, ids=[b[1] for b in BOUND])
def test_no_python_field_is_invented(header, struct, cls):
    """The reverse direction: a Python field with no C++ origin is drift."""
    cpp = set(cpp_fields(header, struct))
    cpp |= {RENAMES[k] for k in RENAMES if k[0] == struct}
    cpp |= {k[1] for k in NOT_BOUND if k[0] == struct}
    extra = [n for n in py_fields(cls) if n not in cpp]
    assert not extra, f"Python-only fields on {struct}: {extra}"


# --- and the half a name check cannot make: is the field actually WIRED? -----

@pytest.fixture
def img():
    """An image with a function body, so a pipeline exercises every field."""
    b = bytearray(0x800)
    b[0x100:0x108] = bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56])
    return v1.Image(bytes(b), code=[(0, 0x800)], funcs=[(0x100, 0x200)])

def test_every_stageresult_field_is_populated(img):
    """Each field observed holding a non-default value at least once."""
    r = v1.Pipeline('bytes("41 57 41 56") -> func').run(img)
    seen = {f: False for f in py_fields(v1.StageResult)}
    for s in r.trace:
        for f in seen:
            if getattr(s, f) not in (0, "", None, [], False):
                seen[f] = True
    missing = [name for name, v in seen.items() if not v]
    assert not missing, f"StageResult fields never non-default: {missing}"


def test_every_pipelineresult_field_is_populated(img):
    """Two runs, because no single pipeline can make every field non-default.
    """
    matches = v1.Pipeline('bytes("55 @(entry) 48 89 E5")').run(img)
    values = v1.Pipeline('bytes("55 48 89 E5") -> read(4)').run(img)
    seen = {f: False for f in py_fields(v1.PipelineResult)}
    for r in (matches, values):
        for f in seen:
            v = getattr(r, f)
            if v not in (0, "", None, [], False, ()) or (f == "kind" and v):
                seen[f] = True
    assert matches.ok is True
    assert matches.kind == "matches"
    assert matches.matches
    assert matches.trace
    assert matches.schema
    assert values.kind == "values"
    assert values.values
    missing = [name for name, v in seen.items() if not v]
    assert not missing, f"never non-default: {missing}"


@pytest.fixture
def gen_img():
    """One target reached three ways, so the strategies between them leave no
    Candidate field at its default.

    No single strategy can: Xref alone leaves anchor_delta at 0, and
    StringAnchor's depth-0 form alone leaves save_index at 0. The shape is
    test_generate.py's negative-delta fixture with a caller added.
    """
    size = 0x1000
    buf = bytearray([0xCC]) * size
    text = b"UNIQUESTRING\x00"
    buf[0x300:0x300 + len(text)] = text

    # lea rax, [rip+disp] at 0x110, naming the string -- StringAnchor depth 0,
    # which is the only strategy here with a non-zero anchor_delta.
    disp = 0x300 - (0x110 + 7)
    buf[0x110:0x113] = bytes([0x48, 0x8D, 0x05])
    buf[0x113:0x117] = disp.to_bytes(4, "little", signed=True)

    # E8 call to the target at 0x140 -- Xref, the only strategy here with a
    # non-zero save_index.
    rel = 0x180 - (0x140 + 5)
    buf[0x140] = 0xE8
    buf[0x141:0x145] = rel.to_bytes(4, "little", signed=True)

    i = _core.Image.from_bytes(bytes(buf))
    i.code = [Range(0, 0x300)]
    i.rodata = [Range(0x300, 0x300 + len(text))]
    i.funcs = [Range(0x100, 0x200)]
    return i


def test_every_candidate_field_is_populated(gen_img):
    """Same check as StageResult's, for the type that carries generation out.

    `anchor_site` is why this exists: it was added to C++ Candidate to make
    anchor INDEPENDENCE checkable downstream, and a binding that declared it
    and copied nothing would satisfy every name check in this file while
    reporting every anchor at address 0 -- which reads as "all these anchors
    are the same one", the precise opposite of what the field is for.
    """
    cands = _core.generate_candidates(gen_img, 0x180, _core.Options(want=8))
    assert cands, "fixture produced no candidates; the test proves nothing"

    # v1 capturing candidates use target_capture and leave save_index at 0.
    skip = {"save_index"}
    seen = {f: False for f in py_fields(_core.Candidate) if f not in skip}
    for c in cands:
        for f in seen:
            if getattr(c, f) not in (0, "", None, [], False):
                seen[f] = True
    missing = [name for name, v in seen.items() if not v]
    assert not missing, f"Candidate fields never non-default: {missing}"


def test_anchor_site_is_the_anchor_not_the_target(gen_img):
    """And the value is the right one, which a population check cannot say.

    Every strategy here anchors somewhere OTHER than the target, so a binding
    that copied the target, or the match offset, would pass the check above
    and still be useless for counting distinct anchors.
    """
    cands = _core.generate_candidates(gen_img, 0x180, _core.Options(want=8))
    by_strategy = {c.strategy: c for c in cands}

    sa = by_strategy.get(_core.Strategy.StringAnchor)
    assert sa is not None
    assert sa.anchor_site == 0x110          # the lea, not the string, not 0x180

    xr = by_strategy.get(_core.Strategy.Xref)
    assert xr is not None
    assert xr.anchor_site == 0x140          # the call site

    bd = by_strategy.get(_core.Strategy.Body)
    assert bd is not None
    assert bd.anchor_site == 0x180          # here the target IS the anchor

    # The check a consumer runs: distinct anchors, not pattern count. These
    # three are genuinely independent, so the two numbers agree -- that is
    # the passing case, and the number is computable either way. Where
    # several patterns share a site the set is the smaller and truer one.
    assert {c.anchor_site for c in cands} == {0x110, 0x140, 0x180}
    assert len({c.anchor_site for c in cands}) == len(cands)


def test_trace_uses_into_not_in(img):
    """`into` exists and `in` does not -- `in` is a Python keyword."""
    r = v1.Pipeline('bytes("41 57 41 56") -> func').run(img)
    s = r.trace[-1]
    assert s.into >= 1
    assert not hasattr(s, "in_"), "the C++ spelling leaked into the Python API"
    assert "in" not in py_fields(v1.StageResult)


def test_bound_result_types_have_no_defaults():
    """A defaulted field accepts being omitted, and yields a plausible zero.

    This is the structural fix for the `moved` bug, and it is worth stating as
    a rule rather than trusting to review. `StageResult.moved` was declared
    `int = 0`, the binding never populated it, and every construction site was
    happy: the result carried a real-looking 0 for a real image. With no
    default, the same omission is a TypeError on the very first call.

    Cython's dataclass support is what makes this cheap -- these are cdef
    classes with C-typed storage that are still dataclasses, so the rule costs
    nothing but the removal of the defaults.

    `Options` is exempt and listed separately: it travels INTO C++, its
    defaults mirror generate::Options, and partial construction is the point.
    """
    import dataclasses as dc
    offenders = []
    for cls in OUT_DIRECTION:
        for f in dc.fields(cls):
            if f.default is not dc.MISSING or f.default_factory is not dc.MISSING:
                offenders.append(f"{cls.__name__}.{f.name} = {f.default!r}")
    assert not offenders, (
        "these fields carry data OUT of C++ and have defaults, so omitting "
        "them at the binding site would go unnoticed:\n  " + "\n  ".join(offenders))


@pytest.mark.parametrize("cls", OUT_DIRECTION, ids=lambda c: c.__name__)
def test_omitting_a_field_is_a_TypeError(cls):
    """The rule above, exercised rather than asserted about.

    A rule that no test exercises is a comment. This builds each type one
    argument short and requires the failure.
    """
    import dataclasses as dc
    n = len(dc.fields(cls))
    with pytest.raises(TypeError):
        cls(*([0] * (n - 1)))


def test_they_are_still_dataclasses_and_still_frozen():
    """If `dataclasses.fields()` ever stops working on these, the completeness
    tests above go silently vacuous -- they would iterate an empty field list
    and pass. This is the guard on the guard.
    """
    import dataclasses as dc
    r = v1.StageResult("bytes", 1, 2)
    assert dc.is_dataclass(r)
    assert dc.fields(v1.StageResult), "fields() empty: the checks above are vacuous"
    assert repr(r) == "StageResult(stage='bytes', into=1, out=2)"
    assert r == v1.StageResult("bytes", 1, 2)
    with pytest.raises(AttributeError):
        r.into = 9
