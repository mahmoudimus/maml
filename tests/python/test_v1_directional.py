import pytest
from maml import v1


def test_before_all_matches_and_adjacency():
    image = v1.Image(bytes.fromhex('E8 00 00 00 00 90 E8 00 00 00 00 CC'), base=0x1000)
    assert [m.offset for m in v1.Pipeline('bytes("CC") -> before("E8 rel32(callee)", within=6)').run(image).matches] == [0, 6]
    assert [m.offset for m in v1.Pipeline('bytes("CC") -> before("E8 rel32(callee)", within=0)').run(image).matches] == [6]
    assert [m.offset for m in v1.Pipeline('bytes("CC") -> before("E8 rel32(callee)", within=5)').run(image).matches] == [6]
    result = v1.PipelineBuilder().bytes('CC').before('E8 rel32(callee)', within=0).capture('callee').build().run(image)
    assert result.values[0].value == 0x100B


def test_before_backtracks_for_endpoint_and_deduplicates():
    image = v1.Image(bytes.fromhex('AA 90 CC CC'))
    result = v1.Pipeline('bytes("CC") -> before("AA [0..3]", within=0)').run(image)
    assert [m.offset for m in result.matches] == [0]


def test_after_requires_instruction_end_and_includes_boundary():
    data = bytes.fromhex('AA BB CC 90 CC')
    with pytest.raises(v1.ExecutionError, match='instruction'):
        v1.Pipeline('bytes("AA") -> after("CC", within=2)').run(v1.Image(data))
    image = v1.Image(data, instructions=[(0, 2)])
    query = v1.PipelineBuilder().bytes('AA').after('CC', within=2).build()
    assert [m.offset for m in query.run(image).matches] == [2, 4]
    assert [m.offset for m in v1.Pipeline('bytes("AA") -> after("CC", within=0)').run(image).matches] == [2]


@pytest.mark.parametrize('stage', ['before("AA")', 'before("AA", within=-1)', 'after("AA", within=18446744073709551616)', 'before("AA", wrong=1)'])
def test_bad_window_syntax(stage):
    with pytest.raises(v1.CompileError):
        v1.Pipeline('bytes("CC") -> ' + stage)


def test_directional_edges_schema_and_types():
    image = v1.Image(bytes.fromhex('AA CC'), instructions=[(0, 1)])
    assert [m.offset for m in v1.Pipeline('bytes("AA") -> before("@(x)", within=0)').run(image).matches] == [0]
    assert [m.offset for m in v1.Pipeline('bytes("AA") -> after("CC @(x)", within=18446744073709551615)').run(image).matches] == [1]
    with pytest.raises(v1.SchemaError):
        v1.Pipeline('bytes("@(old)") -> before("@(new)", within=0) -> capture("old")')
    with pytest.raises(v1.CompileError, match='Address stage'):
        v1.Pipeline('bytes("AA") -> read(1) -> before("CC", within=1)').run(image)
    with pytest.raises(v1.CardinalityError):
        v1.Pipeline('bytes("CC") -> before("??", within=1) -> unique').run(v1.Image(b'\xAA\xBB\xCC'))


def test_clear_scripts_reference_workflow():
    data = bytearray(b'\x90' * 80)
    data[0:5] = b'\xE8' + (60-5).to_bytes(4,'little',signed=True)
    data[5:12] = bytes.fromhex('4C 8D 05') + (64-12).to_bytes(4,'little',signed=True)
    data[64:77] = b'ClearScripts\0'
    image = v1.Image(data, code=[(0, 12)], rodata=[(64, 80)])
    result = v1.Pipeline('str("ClearScripts") -> xrefs -> before("E8 rel32(callee)", within=0) -> capture("callee") -> unique').run(image)
    assert result.values[0].value == 60


def test_before_large_image_uses_compiled_extent():
    data = b'\x90' * 1000010 + bytes.fromhex('E8 00 00 00 00 CC')
    assert v1.Pipeline('bytes("CC") -> before("E8 rel32(x)", within=0)').run(v1.Image(data)).matches[0].offset == 1000010


def test_after_rejects_conflicting_instruction_lengths():
    image = v1.Image(b'\xAA\xBB\xCC', instructions=[(0, 1), (0, 2)])
    with pytest.raises(v1.CompileError, match='Conflicting instruction'):
        v1.Pipeline('bytes("AA") -> after("CC", within=1)').run(image)


def test_before_follow_uses_final_cursor_and_rolls_back_captures():
    image = v1.Image(bytes.fromhex('E8 01 00 00 00 90 CC DD'))
    query = v1.Pipeline('bytes("DD") -> before("E8 rel32(target):follow CC", within=0)')
    result = query.run(image)
    assert result.matches[0].capture('target').value == 6
    query = v1.Pipeline('bytes("DD") -> before("(E8 @(discard) | E8 [6] @(kept))", within=0)')
    result = query.run(image)
    assert result.matches[0].capture('discard') is None
    assert result.matches[0].capture('kept').value == 7
