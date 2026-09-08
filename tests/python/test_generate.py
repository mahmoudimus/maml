import struct

import pytest

import maml
from maml import generate


# ── fixtures, mirrored from tests/test_generate.cpp's C++ helpers ───────

def _make_call_image(callee, sites, size=0x1000):
    b = bytearray([0xCC]) * size
    b[callee] = 0x48
    b[callee + 1] = 0x89  # callee prologue, arbitrary
    for s in sites:
        b[s] = 0xE8
        rel = (callee - (s + 5)) & 0xFFFFFFFF
        for k in range(4):
            b[s + 1 + k] = (rel >> (8 * k)) & 0xFF
    return b


def _make_xref_image(callee, sites, tail, size=0x1000):
    b = _make_call_image(callee, sites, size)
    for s in sites:
        b[s + 5:s + 5 + len(tail)] = tail
    return b


def _make_xref_image_varied(callee, sites_and_tails, size=0x1000):
    # Each call site gets its OWN tail, so the sites yield DISTINCT patterns.
    # dedup keys on the resolving (pattern, save_index, anchor_delta) triple;
    # a shared tail collapses every site into ONE candidate, which is correct
    # but useless for a test whose subject is how many anchors a set holds --
    # mirrors test_generate.cpp's make_xref_image_varied, for the same reason.
    just_sites = [s for s, _ in sites_and_tails]
    b = _make_call_image(callee, just_sites, size)
    for s, tail in sites_and_tails:
        b[s + 5:s + 5 + len(tail)] = tail
    return b


def _hex(data):
    return " ".join("%02X" % x for x in data)


# ── candidates() ──────────────────────────────────────────────────────

def test_candidates_returns_candidates_with_the_documented_fields():
    # No E8 anywhere in this fixture, so only Body can emit -- it needs no
    # caller, only a target. Mirrors test_generate.cpp's "the generate
    # surface is callable, and Body emits from any address".
    img = maml.Image.from_bytes(b"\xCC" * 0x100)
    img.code = [maml.Range(begin=0, end=0x100)]

    cs = generate.candidates(img, 0x10)
    assert len(cs) == 1
    c = cs[0]
    assert isinstance(c, generate.Candidate)
    assert isinstance(c.pattern, str) and c.pattern
    assert c.strategy == generate.Strategy.Body
    assert c.save_index == 0
    assert c.anchor_delta == 0
    assert c.literals == 64
    assert c.seed is not None
    assert c.seed.bytes == b"\xCC" * 64


def test_candidates_respects_options_want():
    # Five call sites, each with its OWN tail (a shared tail would dedup into
    # one Xref candidate regardless of `want`, which would make this test
    # pass without `want` doing anything -- see _make_xref_image_varied).
    sites = [(0x200 + 0x100 * i, bytes([0x40 + i, 0x8B, 0xD0, 0x48, 0x85, 0xC0]))
             for i in range(5)]
    img = maml.Image.from_bytes(bytes(_make_xref_image_varied(0x100, sites)))
    img.code = [maml.Range(begin=0, end=0x1000)]

    assert len(generate.candidates(img, 0x100, generate.Options(want=2))) == 2
    assert len(generate.candidates(img, 0x100, generate.Options(want=3))) == 3


# ── verified() ────────────────────────────────────────────────────────

def test_verified_across_two_synthetic_images():
    tail = bytes([0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0])
    a = maml.Image.from_bytes(bytes(_make_xref_image(0x100, [0x200], tail)))
    b = maml.Image.from_bytes(bytes(_make_xref_image(0x180, [0x300], tail)))
    a.code = b.code = [maml.Range(begin=0, end=0x1000)]

    v = generate.verified(a, 0x100, b, 0x180)
    assert v

    # Each surviving candidate must actually resolve to its own target in
    # BOTH images -- re-derive that independently via maml.Pattern
    # rather than trusting verified()'s own claim.
    for c in v:
        for img, want in ((a, 0x100), (b, 0x180)):
            hit = maml.Pattern(c.pattern).find(img, c.save_index)
            assert hit is not None
            got = hit.value if c.save_index else hit.offset - c.anchor_delta
            assert got == want


def test_verified_refuses_the_same_image_twice():
    img = maml.Image.from_bytes(bytes(_make_call_image(0x100, [0x200])))
    img.code = [maml.Range(begin=0, end=0x1000)]
    # The C++ guard compares buffer identity (pointer + size), which the
    # SAME Image object always satisfies against itself.
    assert generate.verified(img, 0x100, img, 0x100) == []


# ── anchor_delta sign ────────────────────────────────────────────────

def test_negative_anchor_delta_survives_the_round_trip():
    # StringAnchor's depth-0 form anchors on the `lea` that loads a unique
    # string, and that lea may sit BEFORE the target it names -- generate.hpp
    # documents -48 as a real observed delta. Build exactly that shape:
    # a lea at 0x110, loading a string at 0x300, inside a function [0x100,
    # 0x200) whose entry (the target) is 0x180 -- past the lea.
    size = 0x1000
    buf = bytearray([0xCC]) * size
    s = b"UNIQUESTRING\x00"
    str_at = 0x300
    buf[str_at:str_at + len(s)] = s

    lea_site = 0x110
    target = 0x180
    disp = str_at - (lea_site + 7)
    buf[lea_site] = 0x48
    buf[lea_site + 1] = 0x8D
    buf[lea_site + 2] = 0x05
    for k in range(4):
        buf[lea_site + 3 + k] = (disp >> (8 * k)) & 0xFF

    img = maml.Image.from_bytes(bytes(buf))
    img.code = [maml.Range(begin=0, end=0x300)]
    img.rodata = [maml.Range(begin=0x300, end=0x300 + len(s))]
    img.funcs = [maml.Range(begin=0x100, end=0x200)]

    cs = generate.candidates(img, target)
    string_anchors = [c for c in cs if c.strategy == generate.Strategy.StringAnchor]
    assert string_anchors
    c = string_anchors[0]
    assert c.anchor_delta == lea_site - target
    assert c.anchor_delta < 0

    # SIGNED subtraction must recover the real target; an unsigned one would
    # wrap silently instead.
    hit = maml.Pattern(c.pattern).find(img, c.save_index)
    assert hit is not None
    assert hit.offset - c.anchor_delta == target


# ── resolve_consensus() ──────────────────────────────────────────────

def test_resolve_consensus_groups_and_orders_by_agreement():
    # Anchors must actually DISAGREE, or there is one group and any order
    # passes. Two anchors resolve to 0x200, one (listed FIRST) resolves to
    # 0x500 on its own -- mirrors test_generate.cpp's "resolve_consensus puts
    # the most-agreed address first", which was vacuous before it was
    # rebuilt this way.
    size = 0x1000
    buf = bytearray([0xCC]) * size
    a1 = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    a2 = bytes([0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCD])
    lone = bytes([0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6])
    buf[0x200:0x206] = a1       # resolves to 0x200 - 0
    buf[0x300:0x306] = a2       # resolves to 0x300 - 0x100 == 0x200 too
    buf[0x500:0x506] = lone     # resolves to 0x500, on its own
    img = maml.Image.from_bytes(bytes(buf))

    def mk(at, delta):
        return generate.Candidate(dialect="maml-current", target_capture="",
            pattern=_hex(buf[at:at + 6]), save_index=0, anchor_delta=delta,
            anchor_site=at, strategy=generate.Strategy.Body, literals=6,
            seed=None)

    cands = [mk(0x500, 0), mk(0x200, 0), mk(0x300, 0x100)]
    groups = generate.resolve_consensus(img, cands)

    assert len(groups) == 2
    assert groups[0].address == 0x200
    assert sorted(groups[0].anchors) == [1, 2]     # two anchors agreed
    assert groups[1].address == 0x500
    assert groups[1].anchors == [0]                # the lone one, listed first in input


def test_resolve_consensus_drops_anchors_not_unique_in_the_new_image():
    buf = bytearray([0xCC]) * 0x800
    run = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    buf[0x100:0x106] = run
    buf[0x400:0x406] = run  # the SAME bytes twice: not unique
    img = maml.Image.from_bytes(bytes(buf))

    amb = generate.Candidate(dialect="maml-current", target_capture="", pattern=_hex(run), save_index=0, anchor_delta=0,
                              anchor_site=0x100, strategy=generate.Strategy.Body,
                              literals=6, seed=None)
    assert generate.resolve_consensus(img, [amb]) == []

    # Positive control: made unique, the same anchor does vote. Without this,
    # an empty result above proves nothing -- a binding that always returns
    # [] (e.g. one that silently corrupts save_index) would pass the
    # assertion above for the wrong reason.
    buf[0x400:0x406] = b"\xCC" * 6
    img2 = maml.Image.from_bytes(bytes(buf))
    ok = generate.resolve_consensus(img2, [amb])
    assert len(ok) == 1
    assert ok[0].address == 0x100


# ── Strategy / Options shape ─────────────────────────────────────────

def test_strategy_members_match_the_cpp_enum():
    names = [s.name for s in generate.Strategy]
    assert names == ["Body", "Xref", "StringAnchor", "RipRef"]


def test_options_defaults_match_the_cpp_struct():
    o = generate.Options()
    assert o.max_len == 64
    assert o.want == 4
    assert o.prefer_short is True
    assert o.deep_anchor is True


# ── Image.from_pe ─────────────────────────────────────────────────────

def _build_pe_with_sections(tmp_path):
    """A tiny PE32+ with .text (executable), .rdata (initialised data) and
    .pdata (one RUNTIME_FUNCTION inside .text, one outside it)."""
    lief = pytest.importorskip("lief", reason="needs the maml[pe] extra")

    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
    CH = lief.PE.Section.CHARACTERISTICS

    text = lief.PE.Section(".text")
    text.virtual_address = 0x1000
    text.virtual_size = 0x40
    text.characteristics = int(CH.MEM_EXECUTE) | int(CH.MEM_READ) | int(CH.CNT_CODE)
    factory.add_section(text)

    rdata = lief.PE.Section(".rdata")
    rdata.virtual_address = 0x2000
    rdata.virtual_size = 0x20
    rdata.characteristics = int(CH.MEM_READ) | int(CH.CNT_INITIALIZED_DATA)
    factory.add_section(rdata)

    pdata = lief.PE.Section(".pdata")
    pdata.virtual_address = 0x3000
    pdata.virtual_size = 24
    pdata.characteristics = int(CH.MEM_READ) | int(CH.CNT_INITIALIZED_DATA)
    factory.add_section(pdata)

    binary = factory.get()

    s_text = binary.sections[0]
    s_text.size = 512
    s_text.content = list(b"\x90" * 0x40) + [0] * (512 - 0x40)

    s_rdata = binary.sections[1]
    s_rdata.size = 512
    s_rdata.content = list(b"\x41" * 0x20) + [0] * (512 - 0x20)

    s_pdata = binary.sections[2]
    s_pdata.size = 512
    inside = struct.pack("<III", 0x1008, 0x1028, 0)   # begin is inside .text
    outside = struct.pack("<III", 0x5000, 0x5010, 0)  # begin is NOT inside .text
    content = inside + outside
    s_pdata.content = list(content) + [0] * (512 - len(content))

    out = tmp_path / "sections.exe"
    builder = lief.PE.Builder(binary, lief.PE.Builder.config_t())
    builder.build()
    builder.write(str(out))
    return out


def test_from_pe_fills_code_and_rodata(tmp_path):
    pytest.importorskip("lief", reason="needs the maml[pe] extra")
    out = _build_pe_with_sections(tmp_path)

    img = maml.Image.from_pe(str(out))

    assert [r.name for r in img.code] == [".text"]
    assert img.code[0].begin == 0x1000
    assert img.code[0].end == 0x1000 + 0x40

    rodata_names = {r.name for r in img.rodata}
    assert ".rdata" in rodata_names
    for r in img.rodata:
        assert r.executable is False


def test_from_pe_fills_funcs_from_pdata_filtered_to_text(tmp_path):
    pytest.importorskip("lief", reason="needs the maml[pe] extra")
    out = _build_pe_with_sections(tmp_path)

    img = maml.Image.from_pe(str(out))

    assert len(img.funcs) == 1
    assert img.funcs[0].begin == 0x1008
    assert img.funcs[0].end == 0x1028


def test_from_pe_leaves_funcs_empty_without_pdata(tmp_path):
    lief = pytest.importorskip("lief", reason="needs the maml[pe] extra")

    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
    text = lief.PE.Section(".text")
    text.virtual_address = 0x1000
    text.virtual_size = 64
    text.characteristics = (
        int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        | int(lief.PE.Section.CHARACTERISTICS.MEM_READ)
    )
    factory.add_section(text)
    binary = factory.get()
    section = binary.sections[0]
    section.size = 512
    section.content = list(b"\x90" * 64) + [0] * (512 - 64)

    out = tmp_path / "no_pdata.exe"
    builder = lief.PE.Builder(binary, lief.PE.Builder.config_t())
    builder.build()
    builder.write(str(out))

    img = maml.Image.from_pe(str(out))
    assert img.funcs == []


# --- .pdata parsing, tested without building a PE -------------------------
#
# Both defects here were found by review rather than by mutation, because each
# needs a specific binary shape to show and the test suite had no way to make
# one. funcs_from_pdata is extracted for exactly that reason.

import struct

from maml import Range
from maml._containers import funcs_from_pdata


def _pdata(*records):
    return b"".join(struct.pack("<III", *r) for r in records)


def test_pdata_drops_chained_fragments():
    """UNW_FLAG_CHAININFO records are not function starts.

    generate.hpp states this as a precondition in bold. A hot/cold-split
    function has several .pdata records and only one is the entry; admitting
    the fragments makes enclosing_func() report a fragment as the function.
    """
    buf = bytearray(0x2000)
    buf[0x1000] = 0x01              # Version 1, Flags 0  -> a real entry
    buf[0x1010] = 0x01 | (0x4 << 3)  # Version 1, UNW_FLAG_CHAININFO -> fragment
    code = [Range(begin=0x100, end=0x900)]

    got = funcs_from_pdata(_pdata((0x200, 0x300, 0x1000),
                                  (0x400, 0x500, 0x1010)), code, buf)
    assert [f.begin for f in got] == [0x200]

    # Positive control: with the chain flag cleared the same record IS a start,
    # so this test fails for the flag and not for some other filter.
    buf[0x1010] = 0x01
    got = funcs_from_pdata(_pdata((0x200, 0x300, 0x1000),
                                  (0x400, 0x500, 0x1010)), code, buf)
    assert [f.begin for f in got] == [0x200, 0x400]


def test_pdata_filters_on_code_ranges_not_on_a_section_name():
    """The old filter keyed on a section literally named '.text'.

    So a PE whose executable section is called anything else disabled the
    filter completely, and a PE with a second executable section silently lost
    every function in it.
    """
    buf = bytearray(0x2000)
    buf[0x1000] = 0x01
    # Two executable ranges, neither of which has to be called .text.
    code = [Range(begin=0x100, end=0x200), Range(begin=0x800, end=0x900)]

    got = funcs_from_pdata(_pdata((0x150, 0x160, 0x1000),   # in the first
                                  (0x850, 0x860, 0x1000),   # in the SECOND
                                  (0xDEAD0, 0xDEAE0, 0x1000)), code, buf)
    assert [f.begin for f in got] == [0x150, 0x850]


def test_pdata_ignores_a_trailing_partial_record():
    buf = bytearray(0x2000)
    buf[0x1000] = 0x01
    code = [Range(begin=0x100, end=0x900)]
    raw = _pdata((0x200, 0x300, 0x1000)) + b"\x01\x02\x03\x04"   # 4 spare bytes
    got = funcs_from_pdata(raw, code, buf)
    assert [f.begin for f in got] == [0x200]


def test_pdata_rejects_an_end_before_its_begin_or_past_the_image():
    buf = bytearray(0x2000)
    buf[0x1000] = 0x01
    code = [Range(begin=0x100, end=0x900)]
    got = funcs_from_pdata(_pdata((0x300, 0x200, 0x1000),      # end < begin
                                  (0x400, 0x99999, 0x1000),    # end past image
                                  (0x500, 0x600, 0x1000)), code, buf)
    assert [f.begin for f in got] == [0x500]
