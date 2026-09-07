import pytest

import maml

# The xref pattern from tests/test_patterns.cpp, and its two build shapes.
XREF = "E8 $ { ' } [3-5] 4C 8B D0 48 85 C0 74 ? 0F B6 48 24"
TAIL = bytes([0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0, 0x74, 0xC8,
              0x0F, 0xB6, 0x48, 0x24])


def make_image(gap, callee_off=0x100, site_off=0x200):
    buf = bytearray(b"\xCC" * 0x400)
    buf[callee_off:callee_off + 2] = b"\x48\x89"
    rel = (callee_off - (site_off + 5)) & 0xFFFFFFFF
    buf[site_off] = 0xE8
    buf[site_off + 1:site_off + 5] = rel.to_bytes(4, "little")
    p = site_off + 5
    buf[p:p + len(gap)] = gap
    p += len(gap)
    buf[p:p + len(TAIL)] = TAIL
    return maml.Image.from_bytes(bytes(buf))


def test_pre_release_shape_captures_the_callee():
    img = make_image(bytes([0x42, 0xC6, 0x04, 0x27, 0x00]))     # 5-byte gap
    hit = maml.Pattern(XREF).find(img, save_index=1)
    assert hit is not None
    assert hit.offset == 0x200
    assert hit.value == 0x100          # the captured callee, not just "a match"


def test_release_shape_captures_the_callee():
    img = make_image(bytes([0xC6, 0x07, 0x00]))                 # 3-byte gap
    hit = maml.Pattern(XREF).find(img, save_index=1)
    assert hit is not None
    assert hit.offset == 0x200 and hit.value == 0x100


def test_a_gap_outside_the_range_does_not_match():
    img = make_image(b"\x90" * 6)                               # 6 is outside [3-5]
    assert maml.Pattern(XREF).find(img, save_index=1) is None


def test_prime_then_find_equals_the_one_shot():
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    pat = maml.Pattern(XREF)
    assert pat.prime(img).find(save_index=1).value == pat.find(img, save_index=1).value


def test_the_seed_is_readable():
    # This is what lets the consumer's seedpick.py delete its Python copy of
    # select_seed and read the real answer instead.
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    seed = maml.Pattern(XREF).prime(img).seed
    assert isinstance(seed.bytes, bytes) and len(seed.bytes) >= 1
    assert isinstance(seed.offset, int)
    assert seed.count >= 1              # lazily counted, not a stored field


def test_a_seedless_pattern_reports_no_seed_instead_of_a_sentinel():
    # "? ? ? ?" has no fixed run at all: select_seed returns an empty Seed
    # (bytes == b""), and count_up_to's empty-needle guard would return
    # SIZE_MAX if asked to count it. `ok`/`bool()` is how a caller tells
    # "no seed" from "seed counted", and `count` must not leak that sentinel.
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    seed = maml.Pattern("? ? ? ?").prime(img).seed
    assert seed.bytes == b""
    assert seed.ok is False
    assert bool(seed) is False
    assert seed.count is None


def test_exact_and_loadtime_priming_are_both_reachable():
    # The acceptance harness compares these two; the bindings must expose both.
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    pat = maml.Pattern(XREF)
    assert pat.prime(img, exact=True).find(save_index=1).value == 0x100
    assert pat.prime(img, exact=False).find(save_index=1).value == 0x100


def test_a_primed_pattern_is_reusable_across_images():
    pat = maml.Pattern(XREF)
    a = make_image(bytes([0xC6, 0x07, 0x00]))
    b = make_image(bytes([0x42, 0xC6, 0x04, 0x27, 0x00]))
    assert pat.prime(a).find(save_index=1).value == 0x100
    assert pat.prime(b).find(save_index=1).value == 0x100


def test_primed_direct_construction_is_rejected():
    # maml.Primed() must not segfault: __init__ rejects it and
    # Pattern.prime() must still work afterwards (i.e. __init__ blocking
    # __new__ would break every scan, not just the direct-construction case).
    import pytest
    with pytest.raises(TypeError):
        maml.Primed()
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    assert maml.Pattern(XREF).prime(img).find(save_index=1).value == 0x100


def test_prime_rejects_a_none_image_instead_of_segfaulting():
    with pytest.raises(TypeError):
        maml.Pattern(XREF).prime(None)


def test_find_rejects_a_none_image_instead_of_segfaulting():
    with pytest.raises(TypeError):
        maml.Pattern(XREF).find(None)


def test_primed_bypass_construction_raises_instead_of_crashing():
    # Primed.__new__(Primed) skips __init__ entirely (that is how
    # Pattern.prime() builds one internally), leaving `_img` unset. Every
    # public method must guard against that, not dereference a null image.
    bare = maml.Primed.__new__(maml.Primed)
    with pytest.raises(TypeError):
        bare.find()
    with pytest.raises(TypeError):
        bare.find_all()
    with pytest.raises(TypeError):
        bare.seed


def test_seed_is_memoized_on_the_primed_object():
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    p = maml.Pattern(XREF).prime(img)
    s1 = p.seed
    s2 = p.seed
    assert s1 is s2                     # same Seed instance, not rebuilt each access
    assert s1.count >= 1
    assert s1.count == s2.count         # reading .count twice does not recompute


def test_seed_offset_and_bytes_are_read_only():
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    seed = maml.Pattern(XREF).prime(img).seed
    import pytest
    with pytest.raises(AttributeError):
        seed.offset = 0
    with pytest.raises(AttributeError):
        seed.bytes = b""


def test_find_all_returns_every_match_in_offset_order():
    buf = bytearray(b"\x90" * 1024)
    for at in (0, 16, 32, 48, 64):
        buf[at:at + 2] = b"\x41\x42"
    img = maml.Image.from_bytes(bytes(buf))
    hits = maml.Pattern("41 42").prime(img).find_all()
    assert [h.offset for h in hits] == [0, 16, 32, 48, 64]


@pytest.mark.parametrize("limit,expected", [
    (0, 5),    # unbounded
    (1, 1),
    (2, 2),
    (4, 4),
    (5, 5),    # limit == match count
    (6, 5),    # limit == count + 1, one past the last real match
    (99, 5),
])
def test_find_all_honours_limit_and_zero_means_unbounded(limit, expected):
    buf = bytearray(b"\x90" * 1024)
    for at in (0, 16, 32, 48, 64):
        buf[at:at + 2] = b"\x41\x42"
    scan = maml.Pattern("41 42").prime(maml.Image.from_bytes(bytes(buf)))
    assert len(scan.find_all(limit=limit)) == expected


def test_find_all_honours_save_index():
    img = make_image(bytes([0xC6, 0x07, 0x00]))
    hits = maml.Pattern(XREF).prime(img).find_all(save_index=1)
    assert len(hits) == 1
    assert hits[0].value == 0x100          # the captured callee


def test_find_all_agrees_with_find_on_the_first_match():
    buf = bytearray(b"\x90" * 256)
    buf[10:12] = b"\x41\x42"
    scan = maml.Pattern("41 42").prime(maml.Image.from_bytes(bytes(buf)))
    assert scan.find().offset == scan.find_all()[0].offset


def test_no_match_returns_an_empty_list_not_None():
    img = maml.Image.from_bytes(b"\x90" * 64)
    assert maml.Pattern("41 42").prime(img).find_all() == []
