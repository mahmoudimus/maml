import struct
import subprocess

import pytest
from maml import v1, Function

QUERY = 'str("PitchUpStart") -> ptrrefs -> unique -> offset(8) -> read_ptr -> func:strict -> unique'


def fixture(base=0, *, extra=False, callback=0x300, mapping=True):
    raw = bytearray(0x400)
    raw[0x100:0x10d] = b'PitchUpStart\0'
    ptrs = {0x140000100: base+0x100, 0x140000300: base+callback} if mapping else {}
    struct.pack_into('<QQ', raw, 0x200, 0x140000100, 0x140000300)
    if extra:
        struct.pack_into('<QQ', raw, 0x220, 0x140000100, 0x140000300)
    return v1.Image(raw, base=base, pointer_map=ptrs, rodata=[(0x100,0x120)],
                    data_ranges=[(0x200,0x230)], code=[(0x300,0x320)],
                    functions=[Function(0x300,[(0x300,0x320)])])


@pytest.mark.parametrize('base', [0, 0x140000000])
def test_table_text_builder_and_cli(base, tmp_path, cli_executable):
    image = fixture(base)
    builder = v1.PipelineBuilder().str('PitchUpStart').ptrrefs().unique().offset(8).read_ptr().func(strict=True).unique()
    for pipeline in (v1.Pipeline(QUERY), builder.build()):
        result = pipeline.run(image)
        assert [v.value for v in result.values] == [base+0x300]
        stats = result.trace[1].pointer_stats
        assert stats['candidates'] == 25+41
        assert stats['mapped'] == 2
        assert stats['output'] == 1
        assert stats['unmapped'] + stats['mapped'] + stats['invalid'] == stats['candidates']
    binary = tmp_path/'table.bin'; binary.write_bytes(image.data)
    manifest = tmp_path/'ranges.txt'
    manifest.write_text(f'size 1024\nbase {base}\nrodata 256 288\ndata 512 560\ncode 768 800\nfunction 768 768 800\npointer 5368709376 {base+256}\npointer 5368709888 {base+768}\n')
    result = subprocess.run([cli_executable('mamlpipe'),str(binary),'--ranges',str(manifest),QUERY,'--trace'],capture_output=True,text=True)
    assert result.returncode == 0, result.stdout+result.stderr
    assert f'{base+0x300:x}:CursorAddress:image' in result.stdout
    assert 'candidates=66 mapped=2' in result.stderr


def test_distinct_slots_and_strict_entry():
    image = fixture(extra=True)
    prefix = 'str("PitchUpStart") -> ptrrefs'
    assert [v.value for v in v1.Pipeline(prefix).run(image).values] == [0x200,0x220]
    with pytest.raises(v1.CardinalityError): v1.Pipeline(prefix+' -> unique').run(image)
    assert [v.value for v in v1.Pipeline(prefix+' -> offset(8) -> read_ptr').run(image).values] == [0x300]
    with pytest.raises(v1.ExecutionError): v1.Pipeline(QUERY).run(fixture(callback=0x301))


@pytest.mark.parametrize('n', [-257, 1024, -(1<<63), (1<<63)-1])
def test_bad_offsets_fail(n):
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline(f'str("PitchUpStart") -> offset({n})').run(fixture())


def test_offsets_preserve_type_and_mapping_is_explicit():
    image = fixture()
    result = v1.Pipeline('str("PitchUpStart") -> offset(8) -> offset(-8)').run(image)
    assert result.values[0].kind == 'CursorAddress' and result.values[0].value == 0x100
    assert not v1.Pipeline('str("PitchUpStart") -> ptrrefs').run(fixture(mapping=False)).ok
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('str("PitchUpStart") -> offset(264) -> read_ptr').run(fixture(mapping=False))
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('str("PitchUpStart") -> offset(767) -> read_ptr').run(image)
    for text in ['bytes("00") -> offset(1)', 'bytes("00") -> read_ptr',
                 'str("PitchUpStart") -> offset(9223372036854775808)',
                 'str("PitchUpStart") -> offset(-9223372036854775809)']:
        with pytest.raises(v1.CompileError): v1.Pipeline(text)
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('str("PitchUpStart") -> read(1) -> offset(1)').run(image)


def test_scan_ranges_alignment_overlap_and_exclusions():
    image = fixture()
    raw = bytearray(image.data)
    struct.pack_into('<Q', raw, 0x201, 0x140000100)
    image = v1.Image(raw, pointer_map=image.pointer_map, rodata=image.rodata,
                     data_ranges=[(0x200,0x220),(0x201,0x221)],code=[(0x210,0x218)])
    result = v1.Pipeline('str("PitchUpStart") -> ptrrefs').run(image)
    assert [v.value for v in result.values] == [0x201]
    assert result.trace[1].pointer_stats['searched_ranges'] == [(0x100,0x120),(0x200,0x210),(0x218,0x221)]
    image.data_ranges = ((0x201,0x205),(0x205,0x209))
    assert not v1.Pipeline('str("PitchUpStart") -> ptrrefs').run(image).ok
    image.data_ranges = ((0x200,0x220),); image.code=((0x200,0x220),)
    assert not v1.Pipeline('str("PitchUpStart") -> ptrrefs').run(image).ok


def test_invalid_mapping_is_not_identity_fallback():
    image = fixture()
    image.pointer_map[0x140000100] = 0x100000
    result = v1.Pipeline('str("PitchUpStart") -> ptrrefs').run(image)
    assert not result.ok and result.trace[1].pointer_stats['invalid'] == 1
    image = fixture(); image.pointer_map[0x140000300] = 0x100000
    with pytest.raises(v1.ExecutionError): v1.Pipeline(QUERY).run(image)


def test_empty_inputs_and_absent_data_are_distinct():
    image = fixture()
    assert not v1.Pipeline('str("MissingName") -> ptrrefs').run(image).ok
    with pytest.raises(v1.ExecutionError, match='data ranges'):
        v1.Pipeline('bytes("@(x) 00") -> capture("x") -> ptrrefs').run(v1.Image(b'\0'))
    image.pointer_map[0x140000100] = image.base + len(image.data)
    assert not v1.Pipeline('str("PitchUpStart") -> ptrrefs').run(image).ok


def test_named_pe_loader_maps_sections_and_custom_values(tmp_path):
    lief = pytest.importorskip('lief')
    from test_generate import _build_pe_with_sections
    from maml._containers import flatten_pe
    from maml import _core
    path = _build_pe_with_sections(tmp_path)
    binary = lief.PE.parse(str(path))
    source = binary.optional_header.imagebase
    section = binary.sections[1]
    raw = bytearray(section.content)
    # Preserve the unwind header at offset zero.
    struct.pack_into('<QQ', raw, 8, source+0x1008, source+0x900)
    section.content = list(raw)
    builder = lief.PE.Builder(binary,lief.PE.Builder.config_t())
    builder.build(); builder.write(str(path))
    loaded = flatten_pe(path, base=0x140000000)
    assert loaded.source_base == source
    assert loaded.pointer_map[source+0x1008] == 0x140001008
    assert source+0x900 not in loaded.pointer_map  # image padding is not a section
    assert loaded.data_ranges
    assert _core.Image.from_pe(path).pointer_map[source+0x1008] == 0x1008
    assert v1.Image.from_pe(path, base=0x140000000).pointer_map == loaded.pointer_map
    override = flatten_pe(path, pointer_map={source+0x1008:0x1020})
    assert override.pointer_map[source+0x1008] == 0x1020
    with pytest.raises(ValueError): flatten_pe(path,pointer_map={source+0x1008:0xffffffffffffffff})
    relocated = flatten_pe(path, loaded_base=source+8)
    assert relocated.pointer_map[source+0x1008] == 0x1000
