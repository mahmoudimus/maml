import pytest

from maml import _core


def test_from_bytes_reports_size_and_base():
    img = _core.Image.from_bytes(b"\x90" * 64, base=0x140000000)
    assert img.size == 64
    assert img.base == 0x140000000


def test_base_defaults_to_zero():
    assert _core.Image.from_bytes(b"\x00").base == 0


def test_to_va_adds_the_base():
    img = _core.Image.from_bytes(b"\x00" * 16, base=0x1000)
    assert img.to_va(0x10) == 0x1010


def test_from_file_round_trips(tmp_path):
    p = tmp_path / "img.bin"
    p.write_bytes(bytes(range(256)))
    img = _core.Image.from_file(str(p))
    assert img.size == 256


def _churn():
    """Make the allocator reuse freed blocks, so a broken pin shows as corruption.

    Two things matter, both found by running this against a deliberately
    broken pin (from_bytes releasing its Py_buffer export immediately instead
    of holding it):

    1. The junk must be freed and reallocated, not just allocated -- a first
       wave that is discarded (del) makes those blocks available; a second
       wave then has somewhere to land.
    2. The junk's content must NOT match the source image's content
       (0, 1, 2, ..., 255). An earlier version of this helper filled junk with
       bytes(range(256)) -- identical to the test image -- so even when the
       allocator DID hand the freed block back to new junk, img[0]/img[255]
       still read 0/255 and the corruption was invisible. Measured: 0 of 5
       runs against a broken pin failed with same-content junk; 5 of 5 failed
       once the junk content (0xEE / 0xCC) was made to differ from the
       image's (0..255).

    The second wave is returned so the caller can keep it alive until after
    the assertions -- reading through a pin that no longer owns its memory is
    a race against whatever reuses the block next, and holding the reference
    open keeps that block "next" for as long as possible.
    """
    import gc
    gc.collect()
    stale = [bytes([0xEE]) * 256 for _ in range(2000)]
    del stale
    return [bytearray(b"\xCC" * 256) for _ in range(2000)]


def test_the_buffer_survives_its_source_going_away():
    # from_file's `bytes` temporary has NO Python reference once from_bytes
    # returns -- only the Py_buffer export keeps it alive. Reading through
    # __getitem__ is what actually exercises that; asserting .size does not,
    # because .size is copied out at construction time. _churn() forces the
    # allocator to reuse the freed block so a broken pin shows up as observed
    # corruption instead of passing by luck.
    img = _core.Image.from_bytes(bytes(range(256)))
    _keepalive = _churn()
    assert img[0] == 0
    assert img[255] == 255
    assert bytes(img[i] for i in range(16)) == bytes(range(16))


def test_from_file_data_is_readable_after_the_temporary_is_gone(tmp_path):
    p = tmp_path / "img.bin"
    p.write_bytes(bytes(range(256)))
    img = _core.Image.from_file(str(p))      # the bytes temporary is unreferenced
    _keepalive = _churn()
    assert img[0] == 0 and img[255] == 255


def test_getitem_supports_negative_indexing():
    img = _core.Image.from_bytes(bytes(range(16)))
    assert img[-1] == 15
    assert img[-16] == 0


def test_getitem_out_of_range_raises_index_error():
    img = _core.Image.from_bytes(bytes(range(16)))
    with pytest.raises(IndexError):
        img[16]
    with pytest.raises(IndexError):
        img[-17]


def test_a_pinned_bytearray_cannot_be_resized():
    buf = bytearray(b"\x90" * 32)
    img = _core.Image.from_bytes(buf)
    with pytest.raises(BufferError):
        buf += b"\x00"          # resizing while exported must fail, not corrupt
    assert img.size == 32


def test_direct_construction_is_rejected():
    with pytest.raises(TypeError):
        _core.Image()
