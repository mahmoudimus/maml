"""The GIL is released during scans, so the shared objects must be safe."""
from concurrent.futures import ThreadPoolExecutor

import maml

PATTERN = "4C 8B D0 48 85 C0"


def _image():
    buf = bytearray(b"\x90" * (1 << 20))
    for at in (0x1000, 0x40000, 0xF0000):
        buf[at:at + 6] = bytes([0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0])
    return maml.Image.from_bytes(bytes(buf))


def test_one_primed_object_shared_across_threads_matches_the_serial_run():
    img = _image()
    scan = maml.Pattern(PATTERN).prime(img)
    serial = [scan.find().offset for _ in range(64)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        parallel = list(ex.map(lambda _: scan.find().offset, range(64)))
    assert parallel == serial
    assert len(set(parallel)) == 1


def test_find_all_is_also_safe_shared():
    img = _image()
    scan = maml.Pattern(PATTERN).prime(img)
    serial = [h.offset for h in scan.find_all()]
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: [h.offset for h in scan.find_all()], range(32)))
    assert all(r == serial for r in results)


def test_a_deeply_nested_pattern_does_not_blow_the_stack():
    # match_atoms recurses through 12 self-call sites. Pool threads get smaller
    # stacks than the main thread, so pin a bound before relying on that.
    pattern = " ".join(["41"] * 512)
    img = maml.Image.from_bytes(b"\x41" * 1024)
    scan = maml.Pattern(pattern).prime(img)
    with ThreadPoolExecutor(max_workers=4) as ex:
        assert all(r is not None for r in ex.map(lambda _: scan.find(), range(16)))


def test_seed_identity_is_stable_across_racing_threads():
    # Regression test for the Task 4 review finding: `Primed.seed` used to
    # build the `Seed` lazily in pure Python with a check-then-build-then-store
    # sequence, with no `nogil` section but still interruptible on the
    # interpreter's switch interval. Two threads racing the FIRST `.seed`
    # access could each see `self._seed is None`, each build a `Seed`, and
    # the second write would win -- so the loser got back an object that was
    # no longer `self._seed`, breaking `p.seed is p.seed` identity and
    # duplicating the count work.
    #
    # The fix builds `_seed` eagerly in `Pattern.prime()`, while the `Primed`
    # is still thread-local, so there is nothing left to race: every thread
    # below reads an already-built object.
    img = maml.Image.from_bytes(b"\x90" * 4096)
    pat = maml.Pattern("90 90")

    for _ in range(50):
        scan = pat.prime(img)  # freshly primed each round; no access yet
        with ThreadPoolExecutor(max_workers=16) as ex:
            seeds = list(ex.map(lambda _: scan.seed, range(64)))
        first = seeds[0]
        assert all(s is first for s in seeds)
