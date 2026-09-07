import struct

import maml
from maml import pipeline


# ── fixture, mirrored from tests/test_pipeline.cpp's C++ helper ────────
#
# Crowded rather than 0xCC filler: every byte value present and hundreds of
# decoy instructions carrying each stage's opcode, so no short literal is
# unique by luck.

ONCE = "PipelineOnlyReferentOnce"
TWICE = "PipelineReferentTwice"

# The displacement `find "F7 80 ' ? ? 00 00" -> read 4` must come back with,
# and a second one sharing its `58` but differing in value.
FIELD_OFFSET = 0x1C58
OTHER_OFFSET = 0x2A58


def _crowd(state):
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= state >> 7
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    return state, (state >> 24) & 0xFF


class PipeImage:
    pass


def _make_image(variant=0, decoys=300):
    p = PipeImage()
    n = 0x20000
    code_end = 0x18000
    b = bytearray(n)
    s = (0x9E3779B97F4A7C15 + variant) & 0xFFFFFFFFFFFFFFFF
    for i in range(n):
        s, byte = _crowd(s)
        b[i] = byte

    def rel32(at, to, end):
        b[at:at + 4] = struct.pack("<i", to - end)

    def lea(at, to):
        b[at] = 0x48
        b[at + 1] = 0x8D
        b[at + 2] = 0x0D
        rel32(at + 3, to, at + 7)

    def call(at, to):
        b[at] = 0xE8
        rel32(at + 1, to, at + 5)

    def field(at, disp):
        # `test dword ptr [rax+disp32], imm32` -- the F7 /0 form whose
        # disp32 is a structure field offset. The 3-byte prefix `F7 80 58` is
        # everywhere in the image and unique inside one function, which is
        # exactly what `find` exists for.
        b[at] = 0xF7
        b[at + 1] = 0x80
        b[at + 2:at + 6] = struct.pack("<I", disp)
        b[at + 6:at + 10] = b"\x00\x00\x00\x00"

    def put_str(at, text):
        # The byte BEFORE matters: strings() reports MAXIMAL printable runs,
        # so printable filler in front would change the run's content.
        b[at - 1] = 0
        b[at:at + len(text)] = text.encode()
        b[at + len(text)] = 0

    for d in range(decoys):
        at = 0x2000 + d * 0x30
        if at + 24 >= code_end:
            break
        lea(at, 0x19800 + d * 4)
        call(at + 8, 0x1500 + variant)

    p.str_once, p.str_twice = 0x18400, 0x18500
    put_str(p.str_once, ONCE)
    put_str(p.str_twice, TWICE)

    p.fn_once = 0x11000
    p.ref_once = p.fn_once + 0x20
    lea(p.ref_once, p.str_once)

    p.fns_twice = []
    for k in range(2):
        fn = 0x11800 + k * 0x400
        lea(fn + 0x10 + k * 8, p.str_twice)
        p.fns_twice.append(fn)

    # Two strings sharing a prefix, referenced in the OPPOSITE order to the
    # strings themselves: a stage emitting discovery order returns these two
    # the wrong way round.
    p.str_alpha, p.str_bravo = 0x18600, 0x18700
    put_str(p.str_alpha, "PipelineOrderAlpha")
    put_str(p.str_bravo, "PipelineOrderBravo")
    p.ref_alpha, p.ref_bravo = 0x12400, 0x11400
    lea(p.ref_alpha, p.str_alpha)
    lea(p.ref_bravo, p.str_bravo)

    p.callee = 0x1000
    b[p.callee:p.callee + 8] = bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56])
    p.call_sites, p.caller_fns = [], []
    for k in range(3):
        fn = 0x13000 + k * 0x200
        call(fn + 0x30, p.callee)
        p.call_sites.append(fn + 0x30)
        p.caller_fns.append(fn)

    # 220 copies of the exact six bytes, inside `code` and inside NO
    # function, so the 3-byte prefix is hopeless image-wide.
    for d in range(220):
        field(0x8000 + d * 0x20, FIELD_OFFSET)
    p.field_site = p.fn_once + 0x40          # the one copy inside fn_once
    p.field_disp_at = p.field_site + 2       # where the `'` capture lands
    field(p.field_site, FIELD_OFFSET)
    # The same prefix inside a DIFFERENT function, with a different
    # displacement: a `find` that leaked out of its scope is caught by the
    # value, not merely by the count.
    p.field_other = p.caller_fns[0] + 0x50
    field(p.field_other, OTHER_OFFSET)
    p.field_sites_twice = [fn + 0x80 for fn in p.fns_twice]
    for at in p.field_sites_twice:
        field(at, FIELD_OFFSET)

    # A marker in the last four bytes, so `read 4` fits and `read 8` does not.
    p.tail = n - 4
    b[p.tail:n] = bytes([0xC7, 0x3D, 0x9A, 0x5E])

    img = maml.Image.from_bytes(bytes(b))
    img.code = [maml.Range(0, code_end)]
    img.rodata = [maml.Range(code_end, n)]
    img.funcs = ([maml.Range(p.callee, p.callee + 0x100),
                  maml.Range(p.fn_once, p.fn_once + 0x200)] +
                 [maml.Range(f, f + 0x200) for f in p.fns_twice] +
                 [maml.Range(f, f + 0x100) for f in p.caller_fns])
    p.image = img
    p.raw = bytes(b)
    p.n = n
    p.code_end = code_end
    return p


def _reshaped(p, code=None, rodata=None, funcs=None):
    """The same bytes with one piece of substrate withheld."""
    img = maml.Image.from_bytes(p.raw)
    img.code = p.image.code if code is None else code
    img.rodata = p.image.rodata if rodata is None else rodata
    img.funcs = p.image.funcs if funcs is None else funcs
    return img


CALLEE_PATTERN = 'bytes "55 48 89 E5 41 57 41 56"'
PREFIX_PATTERN = 'bytes "%s"' % " ".join("%02X" % c for c in b"PipelineOrder")


# ── the fixture itself ────────────────────────────────────────────────

def test_the_fixture_is_actually_crowded():
    # Asserted, not assumed: a helper that quietly stopped producing density
    # would weaken every test below to the sparse case they replace.
    p = _make_image(0)
    assert len(set(p.raw)) == 256
    assert p.raw.count(b"\x48\x8d\x0d") > 100
    assert p.raw.count(b"\xe8") > 100


# ── stages ────────────────────────────────────────────────────────────

def test_str_seeds_on_exact_content():
    p = _make_image(0)
    r = pipeline.run(p.image, 'str "%s"' % ONCE)
    assert r.ok
    assert r.addresses == [p.str_once]
    assert [(t.stage, t.into, t.out) for t in r.trace] == [
        ('str "%s"' % ONCE, 0, 1)]


def test_bytes_seeds_on_a_pattern():
    p = _make_image(0)
    r = pipeline.run(p.image, CALLEE_PATTERN)
    assert r.ok
    assert r.addresses == [p.callee]


def test_xref_callers_func_nth_and_limit():
    p = _make_image(0)

    # A data address goes to the rip index, a code address to the call graph.
    assert pipeline.run(p.image, 'str "%s" -> xref' % ONCE).addresses == [p.ref_once]
    assert pipeline.run(p.image, CALLEE_PATTERN + " -> xref").addresses == p.call_sites
    assert pipeline.run(p.image, CALLEE_PATTERN + " -> callers").addresses == p.call_sites
    assert (pipeline.run(p.image, CALLEE_PATTERN + " -> callers -> func").addresses
            == p.caller_fns)
    assert (pipeline.run(p.image, CALLEE_PATTERN + " -> callers -> nth 1").addresses
            == [p.call_sites[1]])
    assert (pipeline.run(p.image, CALLEE_PATTERN + " -> callers -> limit 2").addresses
            == p.call_sites[:2])


def test_string_escapes_and_the_arrow():
    # `->` rather than `|`, because a `bytes` stage embeds the pattern dialect
    # whole and that dialect uses `|` for alternation.
    r = pipeline.run(_make_image(0).image, 'bytes "48 (8B | 89) 05 ? ? ? ?" -> func')
    assert len(r.trace) == 2

    escaped = pipeline.run(_make_image(0).image, r'str "a\"b\\c\nd\te\x41"')
    assert not escaped.failed          # parsed; simply not present in the image
    assert escaped.addresses == []


# ── the chain that matters ────────────────────────────────────────────

def test_str_xref_func_resolves_to_a_known_function():
    p = _make_image(0)
    r = pipeline.run(p.image, 'str "%s" -> xref -> func -> unique' % ONCE)
    assert r.ok
    assert r.addresses == [p.fn_once]
    assert [t.out for t in r.trace] == [1, 1, 1, 1]
    assert r.failed_stage is None
    assert r.error == ""
    assert not r.failed


def test_unique_fails_at_the_stage_that_introduced_the_ambiguity():
    # The index is the diagnostic: for a string with two referents this names
    # stage 1 (xref), which says the STRING was referenced from several
    # places -- a different problem from the function having several callers,
    # which names a later stage. Naming `unique`'s own index would report the
    # same number for both and distinguish nothing.
    p = _make_image(0)

    r = pipeline.run(p.image, 'str "%s" -> xref -> func -> unique' % TWICE)
    assert not r.ok
    assert r.failed
    assert r.failed_stage == 1
    assert "got 2" in r.error
    assert r.addresses == []
    assert [t.out for t in r.trace] == [1, 2, 2]

    callers = pipeline.run(p.image, CALLEE_PATTERN + " -> func -> callers -> unique")
    assert callers.failed_stage == 2
    assert "got 3" in callers.error


# ── R2 / R3: empty is not an error ────────────────────────────────────

def test_an_empty_result_is_not_an_error():
    p = _make_image(0)
    r = pipeline.run(p.image, 'str "NoSuchStringAnywhere"')
    assert not r.ok               # ok means "ended with at least one address"
    assert not r.failed
    assert r.error == ""
    assert r.failed_stage is None
    assert len(r.trace) == 1      # and the stage still ran


def test_nth_past_the_end_and_limit_zero_are_empty():
    p = _make_image(0)
    base = CALLEE_PATTERN + " -> callers"
    for src in (base + " -> nth 99", base + " -> limit 0"):
        r = pipeline.run(p.image, src)
        assert not r.ok
        assert not r.failed
        assert r.addresses == []


# ── R1: a malformed pipeline is a result, not an exception ────────────

def test_a_parse_error_is_a_result_naming_the_stage():
    p = _make_image(0)
    for src, stage in [('str "x" -> xrefs', 1),
                       ('str "no closing', 0),
                       (r'str "bad \q escape"', 0),
                       ('str "x" -> nth', 1),
                       ('str "x" -> xref ->', 2),
                       ('   ', 0),
                       ('str "x" -> xref -> str "y"', 2),
                       ('xref -> func', 0),
                       ('bytes "48 (8B"', 0)]:
        r = pipeline.run(p.image, src)
        assert r.failed, src
        assert not r.ok, src
        assert r.failed_stage == stage, src
        assert r.trace == [], src


# ── R4: missing substrate is named, never answered with silence ───────

def test_a_stage_whose_substrate_is_missing_says_so():
    p = _make_image(0)

    no_funcs = pipeline.run(_reshaped(p, funcs=[]),
                            CALLEE_PATTERN + " -> callers -> func")
    assert no_funcs.failed
    assert no_funcs.failed_stage == 2
    assert "funcs" in no_funcs.error

    no_rodata = pipeline.run(_reshaped(p, rodata=[]), 'str "%s"' % ONCE)
    assert no_rodata.failed
    assert no_rodata.failed_stage == 0
    assert "rodata" in no_rodata.error

    # xref on a data address with no rodata: neither index applies, and an
    # empty answer would read as "nothing references it".
    literal = " ".join("%02X" % c for c in p.raw[p.str_once:p.str_once + 12])
    no_index = pipeline.run(_reshaped(p, rodata=[]), 'bytes "%s" -> xref' % literal)
    assert no_index.failed
    assert no_index.failed_stage == 1
    assert "neither" in no_index.error

    no_code = pipeline.run(_reshaped(p, code=[]), 'str "%s" -> xref' % ONCE)
    assert no_code.failed
    assert no_code.failed_stage == 1
    assert "code" in no_code.error


def test_output_is_ascending_not_discovery_order():
    # The set is SORTED after every stage, not merely deduplicated: these two
    # seeds are found in ascending order but referenced in the opposite one,
    # so discovery order would return the same two addresses the wrong way
    # round and `nth 0` would stop meaning "the lowest".
    p = _make_image(0)
    assert p.ref_bravo < p.ref_alpha and p.str_alpha < p.str_bravo

    r = pipeline.run(p.image, PREFIX_PATTERN + " -> xref")
    assert r.trace[0].out == 2
    assert r.addresses == [p.ref_bravo, p.ref_alpha]
    assert (pipeline.run(p.image, PREFIX_PATTERN + " -> xref -> nth 0").addresses
            == [p.ref_bravo])


# ── R6: determinism ───────────────────────────────────────────────────

def test_the_same_input_always_gives_the_same_output():
    p = _make_image(0)
    src = 'str "%s" -> xref -> func' % TWICE
    first = pipeline.run(p.image, src)
    assert first.addresses == sorted(set(first.addresses))
    for _ in range(4):
        again = pipeline.run(p.image, src)
        assert again.addresses == first.addresses
        assert [(t.stage, t.into, t.out) for t in again.trace] == \
               [(t.stage, t.into, t.out) for t in first.trace]

    # Permuting the caller-supplied funcs must not change the answer either.
    permuted = pipeline.run(_reshaped(p, funcs=list(reversed(p.image.funcs))), src)
    assert permuted.addresses == first.addresses


def test_the_same_text_finds_the_function_in_an_independent_image():
    # A pipeline never encodes a literal address, so the same text works
    # against a second image whose decoys and addresses differ. Evidence that
    # no stage reads a baked-in address -- not a durability claim; these two
    # images are one generator apart, not one compiler apart.
    b = _make_image(1)
    r = pipeline.run(b.image, 'str "%s" -> xref -> func -> unique' % ONCE)
    assert r.ok
    assert r.addresses == [b.fn_once]


# ── find: the pattern is matched INSIDE the enclosing function ────────

FIND_CHAIN = 'str "%s" -> xref -> func -> find ' % ONCE


def test_find_scopes_the_search_to_the_enclosing_function():
    # The whole point. `F7 80 58` is three bytes: image-wide it matches
    # hundreds of times, and inside fn_once exactly once, because the set
    # arriving at `find` has already been narrowed to that function.
    p = _make_image(0)

    wide = pipeline.run(p.image, 'bytes "F7 80 58"')
    assert wide.ok
    assert len(wide.addresses) > 200          # hopeless image-wide

    scoped = pipeline.run(p.image, FIND_CHAIN + '"F7 80 58"')
    assert scoped.ok
    assert scoped.addresses == [p.field_site]
    assert scoped.kind == "address"
    assert (scoped.trace[3].stage, scoped.trace[3].into, scoped.trace[3].out) == \
           ('find "F7 80 58"', 1, 1)

    # Not "inside SOME function": the identical prefix sits inside a caller
    # function too, and scoping to fn_once excludes it.
    assert p.field_other not in scoped.addresses

    # `bytes` is unchanged and still image-wide -- the two are not variants of
    # each other, and an existing chain keeps its meaning.
    assert len(pipeline.run(p.image, 'bytes "F7 80 58"').addresses) == len(wide.addresses)


def test_find_searches_every_scope_and_emits_the_capture():
    p = _make_image(0)

    both = pipeline.run(p.image, 'str "%s" -> xref -> func -> find "F7 80 58"' % TWICE)
    assert both.addresses == p.field_sites_twice

    # save_index 1 when the pattern holds a `'`, 0 otherwise -- and the two
    # differ, so this would not pass either way.
    captured = pipeline.run(p.image, FIND_CHAIN + """ "F7 80 ' ? ? 00 00" """)
    assert captured.addresses == [p.field_disp_at]
    assert pipeline.run(p.image, FIND_CHAIN + '"F7 80 ? ? 00 00"').addresses == \
        [p.field_site]
    assert p.field_disp_at != p.field_site


def test_find_with_no_funcs_says_so():
    # R4: "not configured" and "not found" must stay distinguishable. Without
    # funcs `find` has no scope at all, and empty would read as "the pattern
    # is not in the function".
    p = _make_image(0)
    r = pipeline.run(_reshaped(p, funcs=[]), CALLEE_PATTERN + ' -> find "F7 80 58"')
    assert r.failed
    assert not r.ok
    assert r.failed_stage == 1
    assert "funcs" in r.error
    assert r.addresses == []


def test_find_skips_an_address_with_no_enclosing_function():
    # Not an error: funcs IS configured, so an address outside every one of
    # them genuinely has no scope -- the ruling `func` already follows.
    p = _make_image(0)
    r = pipeline.run(p.image, 'str "%s" -> find "F7 80 58"' % ONCE)
    assert not r.ok
    assert not r.failed
    assert r.addresses == []
    assert (r.trace[-1].into, r.trace[-1].out) == (1, 0)


def test_find_is_not_a_seed():
    p = _make_image(0)
    first = pipeline.run(p.image, 'find "F7 80 58" -> func')
    assert first.failed
    assert first.failed_stage == 0

    bad = pipeline.run(p.image, FIND_CHAIN + '"48 (8B"')
    assert bad.failed
    assert bad.failed_stage == 3
    assert bad.error.startswith("find:")


# ── read: the terminal stage, and the values it yields ────────────────

DISP_CHAIN = FIND_CHAIN + """ "F7 80 ' ? ? 00 00" """


def test_read_loads_n_little_endian_bytes():
    # The chain the feature exists for: a structure field offset, reached
    # with seven bytes of context.
    p = _make_image(0)
    four = pipeline.run(p.image, DISP_CHAIN + " -> read 4")
    assert four.ok
    assert four.addresses == [FIELD_OFFSET]
    assert four.kind == "value"
    assert four.values == [FIELD_OFFSET]

    at = p.field_disp_at
    whole = int.from_bytes(p.raw[at:at + 8], "little")
    for width in (1, 2, 4, 8):
        r = pipeline.run(p.image, DISP_CHAIN + " -> read %d" % width)
        assert r.addresses == [whole & ((1 << (8 * width)) - 1)], width

    # Big-endian would differ at every width but 1, which is what makes the
    # loop above load-bearing.
    assert p.raw[at] != p.raw[at + 1]


def test_read_past_the_end_drops_the_address():
    # R10: dropped, not truncated. Half a displacement is a different number,
    # and a zero-padded one is indistinguishable from a field at offset 0.
    p = _make_image(0)
    assert p.tail + 4 == p.n

    assert pipeline.run(p.image, 'bytes "C7 3D 9A 5E"').addresses == [p.tail]
    assert pipeline.run(p.image, 'bytes "C7 3D 9A 5E" -> read 4').addresses == \
        [0x5E9A3DC7]

    eight = pipeline.run(p.image, 'bytes "C7 3D 9A 5E" -> read 8')
    assert not eight.ok
    assert not eight.failed            # empty is not an error
    assert eight.addresses == []
    assert eight.kind == "value"
    assert (eight.trace[-1].into, eight.trace[-1].out) == (1, 0)


def test_read_yields_values_sorted_and_deduplicated():
    # The same displacement in two functions: two addresses in, ONE value out.
    p = _make_image(0)
    base = 'str "%s" -> xref -> func -> find "F7 80 \' ? ? 00 00"' % TWICE
    assert len(pipeline.run(p.image, base).addresses) == 2

    vals = pipeline.run(p.image, base + " -> read 4")
    assert vals.addresses == [FIELD_OFFSET]
    assert (vals.trace[-1].into, vals.trace[-1].out) == (2, 1)

    # A different displacement reads back differently, so the collapse above
    # is not `read` dropping one or returning a constant.
    other = pipeline.run(
        p.image,
        CALLEE_PATTERN + ' -> callers -> func -> find "F7 80 \' ? ? 00 00" -> read 4')
    assert other.addresses == [OTHER_OFFSET]
    assert OTHER_OFFSET != FIELD_OFFSET


def test_kind_is_address_unless_read_ran():
    # Without this a consumer cannot tell a field displacement from an RVA,
    # and dereferencing the former is silent garbage.
    p = _make_image(0)
    for src in ('str "%s"' % ONCE,
                'str "%s" -> xref -> func' % ONCE,
                'str "NoSuchStringAnywhere"',
                FIND_CHAIN + '"F7 80 58"'):
        r = pipeline.run(p.image, src)
        assert r.kind == "address", src
        try:
            r.values
        except ValueError:
            pass
        else:
            raise AssertionError("values must refuse an address result: " + src)

    assert pipeline.run(p.image, 'bytes "C7 3D 9A 5E" -> read 2').kind == "value"


def test_read_is_terminal_and_takes_a_width_of_1_2_4_or_8():
    # Enforced in the PARSER: a following `xref` or `func` would take a field
    # displacement for an RVA and answer confidently from an unrelated part
    # of the image. A jobfile carrying that is rejected before any image is
    # touched.
    p = _make_image(0)
    for tail in ("xref", "func", "callers", "unique", "nth 0", "limit 1",
                 "read 4", 'find "90"'):
        r = pipeline.run(p.image, 'str "x" -> read 4 -> ' + tail)
        assert r.failed, tail
        assert r.failed_stage == 2, tail
        assert "read 4" in r.error, tail
        assert r.trace == [], tail

    for bad in ("read 0", "read 3", "read 5", "read 9", "read", "read x"):
        r = pipeline.run(p.image, 'str "x" -> ' + bad)
        assert r.failed, bad
        assert r.failed_stage == 1, bad

    for good in (1, 2, 4, 8):
        assert not pipeline.run(p.image, 'str "x" -> read %d' % good).failed


def test_the_find_read_chain_holds_in_an_independent_image():
    # The same TEXT, a second image whose decoys and addresses differ.
    # Evidence that neither stage reads a baked-in address -- not a
    # durability claim.
    b = _make_image(1)
    r = pipeline.run(b.image, DISP_CHAIN + " -> read 4")
    assert r.ok
    assert r.addresses == [FIELD_OFFSET]
    assert r.kind == "value"


def test_stage_trace_reports_moved():
    """`moved` must survive the C++ -> Python crossing.

    It was added to the C++ StageResult and not to the binding, so the field
    existed, was correct, and was invisible to every Python caller -- which is
    the only place it was going to be read. Found by using it.
    """
    p = _make_image()
    r = pipeline.run(p.image, f'str "{ONCE}" -> xref')
    assert r.ok
    # xref replaces a string address with the sites referencing it, so every
    # output is new. If `moved` were dropped in marshalling this would be 0.
    assert r.trace[-1].stage == "xref"
    assert r.trace[-1].moved == r.trace[-1].out
    assert r.trace[-1].moved > 0


def test_func_strict_rejects_a_replaced_address():
    """`func:strict` asserts that the address was LOCATED, not replaced.

    Reaches the parser as pure syntax, so this checks the whole crossing --
    the flag, the failure, the trace name and the message -- rather than
    assuming a C++-side feature is visible from Python because it compiled.
    """
    b = bytearray(0x800)
    b[0x100:0x108] = bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56])
    img = maml.Image.from_bytes(bytes(b))
    img.code = [maml.Range(0, 0x800)]
    img.funcs = [maml.Range(0x100, 0x200)]
    pat = 'bytes "41 57 41 56"'          # at 0x104, inside the function

    plain = pipeline.run(img, f"{pat} -> func")
    assert plain.ok and plain.addresses == [0x100]
    assert plain.trace[-1].stage == "func"
    assert plain.trace[-1].moved == 1     # it moved, and plain func allows it

    strict = pipeline.run(img, f"{pat} -> func:strict")
    assert not strict.ok
    assert strict.addresses == []
    assert strict.failed_stage == 1
    assert "func:strict" in strict.error
    assert strict.trace[-1].stage == "func:strict"
    assert strict.trace[-1].moved == 1

    # And strict is a no-op where nothing moves: an address already at the
    # entry passes both. Without this the test would pass if func:strict simply
    # always failed.
    entry = 'bytes "55 48 89 E5"'
    assert pipeline.run(img, f"{entry} -> func:strict").addresses == [0x100]
