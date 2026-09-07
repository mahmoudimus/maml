"""A masked byte must not cost matches on the seeded path.

`mamlscan.hpp::fixed_bytes` is a whitespace-split pre-scan independent of the
real lexer. It did not know `&`, so `83 38 & 38` kept the `38` as an exact
seed byte and `find` silently rejected every match whose masked bits
differed. The bindings go through that path, so this is asserted here as
well as in tests/test_seed_selection.cpp, and against the mamlscan CLI's
seeded mode (`--scan`) so all three surfaces are pinned to one answer.
"""
import pathlib
import subprocess

import pytest

import maml

# `83 3D` at 0 is a genuine reg=7 ModRM; `83 38` at 9 is the literal.
IMAGE = bytes([0x83, 0x3D, 0x11, 0x22, 0x33, 0x44, 0x00, 0x90, 0x90,
               0x83, 0x38, 0x00])
SPELLINGS = ["83 38 & 38", "83 38&38", "83 38 &38", "83 38& 38"]


@pytest.mark.parametrize("text", SPELLINGS)
def test_find_all_sees_the_masked_match(text):
    img = maml.Image.from_bytes(IMAGE)
    primed = maml.Pattern(text).prime(img)
    assert [h.offset for h in primed.find_all()] == [0, 9]


@pytest.mark.parametrize("text", SPELLINGS)
def test_one_shot_find_sees_it_too(text):
    img = maml.Image.from_bytes(IMAGE)
    hit = maml.Pattern(text).find(img)
    assert hit is not None and hit.offset == 0


def test_the_seed_never_contains_the_masked_byte():
    img = maml.Image.from_bytes(IMAGE)
    for text in SPELLINGS:
        seed = maml.Pattern(text).prime(img).seed
        assert seed is not None and seed.bytes == bytes([0x83]), text


def test_fixed_bytes_past_the_mask_still_seed():
    img = maml.Image.from_bytes(IMAGE)
    seed = maml.Pattern("83 38 & 38 11 22 33 44").prime(img).seed
    assert seed.offset == 2
    assert seed.bytes == bytes([0x11, 0x22, 0x33, 0x44])


@pytest.mark.parametrize("modrm", range(256))
def test_seeded_agrees_with_the_reg_field_arithmetic(modrm):
    # 32 of 256 ModRM bytes carry reg=7; the seeded path must say yes on
    # exactly those. This is the sweep the C++ test runs against the unseeded
    # matcher, restated in terms the binding can check on its own.
    img = maml.Image.from_bytes(bytes([0x83, modrm]))
    hit = maml.Pattern("83 38 & 38").find(img)
    assert (hit is not None) == (((modrm >> 3) & 7) == 7)


def _mamlscan():
    root = pathlib.Path(__file__).resolve().parents[2]
    for rel in ("build/mamlscan", "build/mamlscan.exe", "build/Release/mamlscan.exe"):
        if (root / rel).exists():
            return root / rel
    return None


@pytest.mark.skipif(_mamlscan() is None, reason="build mamlscan first")
def test_mamlscan_scan_mode_agrees(tmp_path):
    """`--scan` is locate::find -- the DLL path -- not the CLI's unseeded
    single-shot, which was never wrong. Tab-separated: name, save, pattern."""
    image = tmp_path / "mask.bin"
    image.write_bytes(IMAGE)
    jobs = tmp_path / "jobs.tsv"
    jobs.write_text("".join(f"j{i}\t0\t{t}\n" for i, t in enumerate(SPELLINGS)))
    out = subprocess.run([str(_mamlscan()), "--scan", str(image), str(jobs)],
                         capture_output=True, text=True, check=True).stdout
    rows = [line.split("\t") for line in out.strip().splitlines()]
    assert len(rows) == len(SPELLINGS)
    for row, text in zip(rows, SPELLINGS):
        assert row[1] == "OK" and int(row[2], 16) == 0, (text, row)
