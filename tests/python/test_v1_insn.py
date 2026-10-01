from maml import Function, v1


def _image():
    # movups xmm0,[rcx+0x228] (16-byte read); movss xmm0,[rcx+0x111] (4-byte read); ret
    code = "0F 10 81 28 02 00 00 F3 0F 10 81 11 01 00 00 C3"
    return v1.Image(bytes.fromhex(code), functions=[Function(0, [(0, 16)])])


def test_insn_size_selects_the_right_read():
    img = _image()
    r16 = v1.Pipeline('bytes("C3") -> func -> insn("read size=16 @(d)") -> capture("d") -> unique').run(img)
    assert [v.value for v in r16.values] == [0x228]
    r4 = v1.Pipeline('bytes("C3") -> func -> insn("read size=4 @(d)") -> capture("d") -> unique').run(img)
    assert [v.value for v in r4.values] == [0x111]


def test_insn_size_filter_is_strict_and_capture_is_required():
    img = _image()
    none = v1.Pipeline('bytes("C3") -> func -> insn("read size=2 @(d)") -> capture("d")').run(img)
    assert list(none.values) == []
    both = v1.Pipeline('bytes("C3") -> func -> insn("read @(d)") -> capture("d")').run(img)
    assert sorted(v.value for v in both.values) == [0x111, 0x228]
    try:
        v1.Pipeline('bytes("C3") -> func -> insn("read size=4")')
        assert False, "expected parse error for missing capture"
    except Exception as e:
        assert "capture" in str(e)
