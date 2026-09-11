import pytest

from maml import _core

lief = pytest.importorskip("lief", reason="needs the maml[pe] extra")


def _build_pe(tmp_path):
    """A tiny PE32+ with one executable .text section at RVA 0x1000.

    lief >=1.0 dropped the constructor-based from-scratch API the earlier
    0.14-era API used (`lief.PE.Binary(name, PE_TYPE)`); binaries are now
    assembled through `lief.PE.Factory` instead. The section's raw size must
    be set explicitly (`section.size = ...`) before its content is assigned,
    or the builder silently drops the content on write.
    """
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
    section.size = 512  # raw (on-disk) size; must precede the content assign
    section.content = list(b"\x90" * 64) + [0] * (512 - 64)

    out = tmp_path / "t.exe"
    builder = lief.PE.Builder(binary, lief.PE.Builder.config_t())
    builder.build()
    builder.write(str(out))
    return out


def test_a_flat_image_has_no_sections():
    assert _core.Image.from_bytes(b"\x90" * 16).sections == []


def test_from_pe_flattens_sections_to_rvas(tmp_path):
    out = _build_pe(tmp_path)

    img = _core.Image.from_pe(str(out))
    assert img.size > 0x1000              # section placed at its virtual address
    names = [s.name for s in img.sections]
    assert ".text" in names
    text_range = next(s for s in img.sections if s.name == ".text")
    assert text_range.begin == 0x1000
    assert text_range.executable is True


def test_from_pe_raises_cleanly_on_a_non_pe(tmp_path):
    p = tmp_path / "not.exe"
    p.write_bytes(b"not a PE at all")
    with pytest.raises(ValueError):
        _core.Image.from_pe(str(p))
