"""The GIL is released during scans, so shared objects must be safe."""
from concurrent.futures import ThreadPoolExecutor

import maml

PATTERN = "4C 8B D0 48 85 C0"


def _image():
    buf = bytearray(b"\x90" * (1 << 20))
    for at in (0x1000, 0x40000, 0xF0000):
        buf[at:at + 6] = bytes([0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0])
    return maml.Image(bytes(buf))


def test_one_pattern_shared_across_threads_matches_the_serial_run():
    img = _image()
    pattern = maml.Pattern(PATTERN)
    serial = [pattern.find(img).offset for _ in range(64)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        parallel = list(ex.map(lambda _: pattern.find(img).offset, range(64)))
    assert parallel == serial
    assert len(set(parallel)) == 1


def test_find_all_is_also_safe_shared():
    img = _image()
    pattern = maml.Pattern(PATTERN)
    serial = [h.offset for h in pattern.find_all(img)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: [h.offset for h in pattern.find_all(img)], range(32)))
    assert all(r == serial for r in results)


def test_a_deeply_nested_pattern_does_not_blow_the_stack():
    pattern = maml.Pattern(" ".join(["41"] * 512))
    img = maml.Image(b"\x41" * 1024)
    with ThreadPoolExecutor(max_workers=4) as ex:
        assert all(r is not None for r in ex.map(lambda _: pattern.find(img), range(16)))
