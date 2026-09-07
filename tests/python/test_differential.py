"""The bindings must agree with the mamlscan CLI, which is the verified path."""
import pathlib
import subprocess

import pytest

import maml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _find_mamlscan():
    """Locate the CLI this suite compares against.

    A single hardcoded path silently disabled all 8 of these tests wherever the
    layout differed -- which was every CI platform. The wheel jobs have no
    build/ at all, and MSVC puts the binary under build/Release with an .exe
    suffix, so even a job that built it would have skipped. The env var comes
    first so a caller can point at a binary built anywhere.
    """
    import os
    env = os.environ.get("MAML_SCAN")
    if env:
        # Set but wrong is a configuration error, not a reason to skip. Skipping
        # here would recreate the exact bug this locator fixes: a CI job that
        # believes it is running the differential suite and silently is not.
        cand = pathlib.Path(env)
        if not cand.exists():
            raise RuntimeError(
                f"MAML_SCAN points at {cand}, which does not exist")
        return cand
    for rel in ("build/mamlscan", "build/mamlscan.exe",
                "build/Release/mamlscan.exe", "build/Debug/mamlscan.exe"):
        cand = ROOT / rel
        if cand.exists():
            return cand
    return None


MAMLSCAN = _find_mamlscan()

pytestmark = pytest.mark.skipif(
    MAMLSCAN is None,
    reason="build mamlscan first: cmake -B build && cmake --build build, "
           "or set MAML_SCAN")

# Named individually (rather than kept in a PATTERNS list crossed with every
# save_index) because each pattern's shape decides which save_index values
# are even meaningful for it -- see DISCRIMINATING_CASES below.
DUP = "41 42"                                             # matches TWICE in `image`
TAIL_ONLY = "4C 8B D0 48 85 C0"                            # no `'` capture
XREF = "E8 $ { ' } [3-5] 4C 8B D0 48 85 C0 74 ? 0F B6 48 24"
RIPREL = "48 69 15 $ { [4] ' } 98 00 00 00 48 8B C8"


@pytest.fixture(scope="module")
def image(tmp_path_factory):
    """One image containing a match for every pattern above."""
    buf = bytearray(b"\xCC" * 0x800)
    for at in (0x40, 0x60):
        buf[at:at + 2] = b"\x41\x42"
    # xref shape: call at 0x200 -> 0x100, 3-byte gap, pinned tail
    buf[0x100:0x102] = b"\x48\x89"
    rel = (0x100 - 0x205) & 0xFFFFFFFF
    buf[0x200] = 0xE8
    buf[0x201:0x205] = rel.to_bytes(4, "little")
    buf[0x205:0x208] = bytes([0xC6, 0x07, 0x00])
    buf[0x208:0x214] = bytes([0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0, 0x74, 0xC8,
                              0x0F, 0xB6, 0x48, 0x24])
    # rip-relative with a trailing imm32, at 0x300
    disp = (0x440 - (0x300 + 11)) & 0xFFFFFFFF
    buf[0x300:0x303] = bytes([0x48, 0x69, 0x15])
    buf[0x303:0x307] = disp.to_bytes(4, "little")
    buf[0x307:0x30B] = bytes([0x98, 0x00, 0x00, 0x00])
    buf[0x30B:0x30E] = bytes([0x48, 0x8B, 0xC8])
    p = tmp_path_factory.mktemp("img") / "diff.bin"
    p.write_bytes(bytes(buf))
    return p


def run_mamlscan(image_path, pattern, save_index):
    """The CompletedProcess, with the crash guard every caller below needs.

    mamlscan only ever exits 0 (OK) or 1 (MISS/MULTI/NONE/ERR) by design --
    tools/mamlscan.cpp ends with `return s.status == "OK" ? 0 : 1;`. Anything
    else (a segfault, an abort) is a real crash of the oracle, and the
    differential test must never let that pass silently as "no answer":
    empty stdout on a crash and empty stdout on a legitimate non-OK result
    look identical to a parser that only checks `parts[0]`.
    """
    proc = subprocess.run(
        [str(MAMLSCAN), str(image_path), pattern, "--save-index", str(save_index)],
        capture_output=True, text=True)
    assert proc.returncode in (0, 1), (
        f"mamlscan crashed (exit {proc.returncode}) on {pattern!r}: {proc.stderr!r}")
    return proc


def cli(image_path, pattern, save_index):
    """Single-shot mamlscan output is SPACE separated: 'OK hits=1 <rva>'."""
    parts = run_mamlscan(image_path, pattern, save_index).stdout.strip().split()
    if not parts or parts[0] != "OK":
        return None
    return int(parts[2], 16)


# Every (pattern, save_index) pair here produces an actual value on both
# sides -- i.e. the comparison can fail in a way that means something. Pairs
# where a pattern has no `'` capture and save_index=1 is asked for (DUP and
# TAIL_ONLY) are deliberately excluded: both sides return None there
# unconditionally, so `None == None` would be agreement on FAILING, not on
# an answer -- see test_cli_and_bindings_agree_a_missing_save_index_yields_no_answer
# below, where that ERR contract is pinned on its own terms instead of
# disguised as a differential case.
DISCRIMINATING_CASES = [
    (TAIL_ONLY, 0),
    (XREF, 0),
    (XREF, 1),
    (RIPREL, 0),
    (RIPREL, 1),
]


@pytest.mark.parametrize("pattern,save_index", DISCRIMINATING_CASES)
def test_bindings_agree_with_the_cli(image, pattern, save_index):
    expected = cli(image, pattern, save_index)
    hit = maml.Pattern(pattern).find(
        maml.Image.from_file(str(image)), save_index=save_index)
    got = hit.value if hit is not None else None
    assert got == expected


@pytest.mark.parametrize("pattern", [DUP, TAIL_ONLY])
def test_cli_and_bindings_agree_a_missing_save_index_yields_no_answer(image, pattern):
    """Neither pattern has a `'` capture, so save_index=1 does not exist.

    CLI: ERR "save index 1 but only 1 saved". Bindings: None, because
    `h->size() <= save_index` in locate::find. Pinned separately from
    DISCRIMINATING_CASES precisely because both sides returning None here is
    not evidence of agreement on an answer -- it is the case
    run_mamlscan's returncode guard exists to keep honest.
    """
    proc = run_mamlscan(image, pattern, 1)
    assert proc.returncode == 1
    assert proc.stdout.split()[0] == "ERR"

    hit = maml.Pattern(pattern).find(
        maml.Image.from_file(str(image)), save_index=1)
    assert hit is None


def test_the_cli_enforces_uniqueness_where_find_returns_the_first(image):
    """Not a bindings bug -- two different, both-documented contracts.

    DUP ("41 42") deliberately matches TWICE in `image` (0x40 and 0x60).
    mamlscan's single-shot CLI enumerates every match and refuses to answer
    (MULTI) when a pattern is not unique in the image -- that uniqueness
    check lives in mamlscan.cpp's classify(), an application-level policy that
    makes mamlscan a pattern *validator* (see CLAUDE.md's "Verification
    standard": a shipped pattern must be unique in two builds). By contrast
    `locate::find()` (include/maml/mamlscan.hpp), which Pattern.find and
    Primed.find wrap unchanged, is documented as "First match of an
    already-compiled pattern" and stops at the first verified hit by
    design -- checking uniqueness on every call would cost a full-image
    scan, exactly what the seed-then-refine design exists to avoid. So
    CLI == MULTI and bindings == the first hit both do precisely what their
    own contract promises; this pins that fact rather than leaving it as an
    xfail, which would assert "this ought to pass and currently does not"
    when nothing is, in fact, failing.
    """
    proc = run_mamlscan(image, DUP, 0)
    assert proc.returncode == 1
    parts = proc.stdout.split()
    assert parts[0] == "MULTI"
    assert parts[1] == "hits=2"

    img = maml.Image.from_file(str(image))
    hit = maml.Pattern(DUP).find(img, save_index=0)
    assert hit is not None
    assert hit.value == 0x40

    hits = maml.Pattern(DUP).prime(img).find_all(save_index=0)
    assert [h.value for h in hits] == [0x40, 0x60]
