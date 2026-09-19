"""Code references include address-taking LEAs; callers remain direct calls."""
import struct

import pytest
from maml import Image, Pipeline, PipelineBuilder


@pytest.mark.parametrize('base', [0, 0x140000000])
@pytest.mark.parametrize('with_call', [False, True])
def test_code_address_references(base, with_call, tmp_path, cli_executable):
    import subprocess
    data = bytearray(b'\x90' * 128)
    target = 64
    data[target] = 0xCC
    # Different registers, both displacement signs, plus an unrelated target.
    for site, destination, opcode in [(8, target, b'\x48\x8D\x05'),
                                      (96, target, b'\x4C\x8D\x0D'),
                                      (112, 80, b'\x48\x8D\x15')]:
        data[site:site + 7] = opcode + struct.pack('<i', destination - site - 7)
    if with_call:
        data[24:29] = b'\xE8' + struct.pack('<i', target - 29)
    image = Image(data, base=base, code=[(0, 128), (0, 128)])
    expected = [base + site for site in ([8, 24, 96] if with_call else [8, 96])]
    for query in [Pipeline('bytes("CC") -> xrefs'),
                  PipelineBuilder().bytes('CC').xrefs().build()]:
        assert [v.value for v in query.run(image).values] == expected
    calls = Pipeline('bytes("CC") -> callers').run(image)
    assert [v.value for v in calls.values] == ([base + 24] if with_call else [])

    # Run the same metadata through the native CLI (buffer-relative addresses).
    binary = tmp_path / 'image.bin'
    binary.write_bytes(data)
    manifest = tmp_path / 'ranges.txt'
    manifest.write_text('size 128\ncode 0 128\ncode 0 128\n')
    result = subprocess.run([cli_executable('mamlpipe'), str(binary), '--ranges',
                             str(manifest), 'bytes("CC") -> xrefs'],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert f'values={len(expected)}' in result.stdout
