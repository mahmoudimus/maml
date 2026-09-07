"""Parser punctuation and modifier behavior, exercised through the Python bindings."""

import string

import pytest

import maml
from maml import pipeline



# include/maml/maml.hpp, Lexer::next_token()
PATTERN_TAKEN = set("?&[]-{}()|%$*'/")
# include/maml/pipeline.hpp: `->`, string quoting and escapes, `:`, word chars
PIPELINE_TAKEN = set('->"\\:_')

TAKEN = PATTERN_TAKEN | PIPELINE_TAKEN
FREE = set(string.punctuation) - TAKEN


def test_the_partition_closes():
    """20 spent + 12 free = the 32 ASCII punctuation characters, exactly."""
    assert len(string.punctuation) == 32
    assert len(TAKEN) == 20
    assert len(FREE) == 12
    assert TAKEN | FREE == set(string.punctuation)
    assert not (TAKEN & FREE)
    assert "".join(sorted(FREE)) == "!#+,.;<=@^`~"


@pytest.mark.parametrize("src", [
    "48 ? 8B",          # ?  one wildcard byte
    "48 & F0",          # &  mask
    "48 [4] 8B",        # [] fixed skip
    "48 [2-6] 8B",      # -  range separator
    "E8 $ { ' }",       # $ { } '  follow rel32, capture, restore
    "EB %",             # %  follow rel8
    "48 8B 05 $ *",     # *  follow an absolute pointer
    "48 (8B|89) 05",    # () | alternation
    "48 // c\n8B",      # /  line comment
    "48 /* c */ 8B",    # /  block comment
])
def test_every_spent_pattern_character_still_parses(src):
    """Each supported pattern construct parses through the binding."""
    maml.Pattern(src)


@pytest.mark.parametrize("c", sorted(FREE))
def test_free_characters_are_rejected_by_the_pattern_dialect(c):
    """A free character is free because nothing claims it -- so it must fail.

    It fails as a HEX error rather than an unknown character, which is the
    trap SIGILS.md documents: the text scanner swallows an unclaimed
    character into the token and only then fails to read it as hex. Anyone
    spending one has to add it to the breaker set, not just the switch.
    """
    with pytest.raises(maml.PatternError):
        maml.Pattern(f"48 {c} 8B")


@pytest.mark.parametrize("c", sorted(FREE))
def test_free_characters_are_rejected_by_the_pipeline_dialect(c):
    """Same claim, other dialect. `str "x"` is a complete, valid pipeline."""
    img = maml.Image.from_bytes(b"\x00" * 0x100)
    r = pipeline.run(img, f'str "x" {c} func')
    assert not r.ok


def test_the_comment_slash_needs_whitespace_before_it():
    """`/` is in the switch but NOT the text-token breaker set.

    This is the concrete instance of the trap above, and it is the reason
    adding a sigil requires touching two places. If `/` is ever
    added to the breaker set this test fails, and its expected behavior must be updated.
    """
    maml.Pattern("48 // c\n8B")            # whitespace before: fine
    with pytest.raises(maml.PatternError):
        maml.Pattern("48// c\n8B")         # none: swallowed, then hex error

    # A character that IS in the breaker set needs no such whitespace.
    maml.Pattern("48?8B")


# --- the `:` modifier, across the binding ------------------------------------
#
# tests/test_pipeline.cpp covers these in C++. They are repeated here because
# the diagnostics are the part most likely to break in the binding and least
# likely to be noticed: a modifier flag that fails to cross shows up as a
# wrong answer, but an ERROR STRING that fails to cross shows up as an empty
# `.error` on a result that is already `ok=False` -- which looks exactly like
# working code. test_pipeline.py's happy path proves the flag crosses; only
# these prove the messages do.

@pytest.fixture
def img():
    b = bytearray(0x800)
    b[0x100:0x108] = bytes([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56])
    i = maml.Image.from_bytes(bytes(b))
    i.code = [maml.Range(0, 0x800)]
    i.funcs = [maml.Range(0x100, 0x200)]
    return i


MID = 'bytes "41 57 41 56"'      # 0x104, inside the function -> func moves it
ENTRY = 'bytes "55 48 89 E5"'    # 0x100, the entry itself    -> func is a no-op


def test_the_colon_binds_tighter_than_the_arrow(img):
    """`func:strict -> unique` is TWO stages, not three.

    This is the whole argument for the colon over `func | strict`, so it is
    worth an assertion rather than a comment: the trace is the proof.
    """
    r = pipeline.run(img, f"{ENTRY} -> func:strict -> unique")
    assert r.ok and r.addresses == [0x100]
    assert [s.stage for s in r.trace] == [
        'bytes "55 48 89 E5"', "func:strict", "unique"]


def test_modifier_diagnostics_cross_the_binding(img):
    """Each error path, checked for its message and not merely for failure."""
    # Wrong stage: modifiers apply to `func` only.
    r = pipeline.run(img, f"{MID} -> xref:strict")
    assert not r.ok and "apply to `func` only" in r.error

    # Unknown STAGE wins over the modifier -- a misspelled stage is named as
    # one, rather than reported as a modifier problem.
    r = pipeline.run(img, f"{MID} -> bogus:strict")
    assert not r.ok and "unknown stage" in r.error

    # Unknown modifier is named as such, not silently ignored.
    r = pipeline.run(img, f"{MID} -> func:neg")
    assert not r.ok and "unknown modifier" in r.error

    # A spaced colon reports the SPACING, not a bare "expected '->'".
    r = pipeline.run(img, f"{MID} -> func :strict")
    assert not r.ok and "no spaces" in r.error

    # `func:` with nothing after it.
    assert not pipeline.run(img, f"{MID} -> func:").ok


@pytest.mark.parametrize("src", [
    "strict(func)",     # call syntax
    "func | strict",    # jinja filter syntax
    "func!",            # sigil syntax
    "func strict",      # bare word
])
def test_the_retired_spellings_stay_retired(src, img):
    """All three predecessors fail, so none of them half-works."""
    assert not pipeline.run(img, f"{MID} -> {src}").ok


def test_loose_is_the_default_spelled_out(img):
    """`func:loose` must equal `func` exactly, or it is not a no-op."""
    a = pipeline.run(img, f"{MID} -> func")
    b = pipeline.run(img, f"{MID} -> func:loose")
    assert a.ok and b.ok
    assert a.addresses == b.addresses == [0x100]
    # ...and strict on the same input is the one that refuses.
    assert not pipeline.run(img, f"{MID} -> func:strict").ok


def test_strict_after_xref_says_why_it_is_the_wrong_place(img):
    """`func:strict` after `xref` rejects ~everything, so the message says so.

    `xref` yields the SITE of a reference, which is mid-function by
    definition, so the replacement `func:strict` refuses is the stage's normal
    work. Measured on a real 41.9 MB image: of 60 targets where
    `str -> xref -> func -> unique` succeeded, `:strict` passed 0 -- rejecting
    the correct answers along with the wrong ones.

    Deliberately not a parse error, because a function whose first instruction
    carries the reference does resolve to its own entry. So the guidance lives
    in the failure message, at the moment of confusion.
    """
    b = bytearray(0x800)
    b[0x100:0x110] = bytes([0x55, 0x48, 0x89, 0xE5,        # entry, then...
                            0x48, 0x8D, 0x05, 0x25, 0x01, 0x00, 0x00,  # lea rax,[rip+0x125] -> 0x230
                            0x90, 0x90, 0x90, 0x90, 0x90])
    b[0x230:0x240] = b"a-unique-string\x00"
    i = maml.Image.from_bytes(bytes(b))
    i.code = [maml.Range(0, 0x200)]
    i.rodata = [maml.Range(0x200, 0x800)]
    i.funcs = [maml.Range(0x100, 0x200)]

    plain = pipeline.run(i, 'str "a-unique-string" -> xref -> func')
    assert plain.ok, "fixture must reach func via xref for the test to mean anything"

    strict = pipeline.run(i, 'str "a-unique-string" -> xref -> func:strict')
    assert not strict.ok
    assert "yields the SITE of a reference" in strict.error
    assert "Use plain `func`" in strict.error

    # ...and the note appears ONLY there. Without a reference-yielding stage
    # in front, the plain message stands -- otherwise every strict failure
    # would carry advice that does not apply.
    bare = pipeline.run(img, 'bytes "41 57 41 56" -> func:strict')
    assert not bare.ok
    assert "yields the SITE" not in bare.error
