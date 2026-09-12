import pytest
from maml import v1


def test_contains_returns_enclosing_starts_once_case_sensitive():
    data = b'PrefixNeedleNeedle\0OtherNeedleSuffix\0needleLower\0'
    image = v1.Image(data, base=0x1000, rodata=[(0,len(data))])
    result = v1.Pipeline('str("Needle", match="contains")').run(image)
    assert [v.value for v in result.values] == [0x1000, 0x1013]
    assert not v1.Pipeline('str("Needle")').run(image).ok
    assert v1.Pipeline('str("PrefixNeedleNeedle", match="exact")').run(image) == v1.Pipeline('str("PrefixNeedleNeedle")').run(image)
    assert v1.PipelineBuilder().str('Needle', match_mode='contains').build().run(image) == result


def test_contains_xrefs_targets_start_not_substring():
    data = bytearray(b'\x90' * 80)
    data[0:7] = bytes.fromhex('48 8D 05') + (32-7).to_bytes(4,'little',signed=True)
    data[32:57] = b'PrefixClearScriptsSuffix\0'
    image = v1.Image(data, code=[(0,7)], rodata=[(32,57)])
    result = v1.Pipeline('str("ClearScripts", match="contains") -> xrefs').run(image)
    assert [v.value for v in result.values] == [0]


@pytest.mark.parametrize('source', ['str("", match="contains")','str("abc", match="fuzzy")','str("abc", fuzzy=True)','str("abc", match="exact", match="contains")'])
def test_invalid_string_modes(source):
    with pytest.raises(v1.CompileError):
        v1.Pipeline(source)


def test_contains_preserves_index_requirements():
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('str("abc", match="contains")').run(v1.Image(b'abcdef\0'))
    image = v1.Image(b'abc\0abcdef\0', rodata=[(0,11)])
    assert [v.value for v in v1.Pipeline('str("abc", match="contains")').run(image).values] == [4]


def test_exact_empty_is_compatible_and_python_mode_is_keyword_only():
    image = v1.Image(b'abcdef\0', rodata=[(0,7)])
    for source in ('str("")', 'str("", match="exact")'):
        assert not v1.Pipeline(source).run(image).ok
    assert not v1.PipelineBuilder().str('').build().run(image).ok
    with pytest.raises(TypeError):
        v1.PipelineBuilder().str('abc', 'contains')
    query = v1.PipelineBuilder().str('abc', match_mode='unknown')
    with pytest.raises(v1.CompileError):
        query.build()
