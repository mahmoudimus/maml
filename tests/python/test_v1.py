"""Semantic frontend acceptance tests; the JSON fixtures supply independent answers."""
import importlib
import json
from pathlib import Path
import pytest


def api():
    assert importlib.util.find_spec('maml.v1') is not None, 'MAML v1 frontend is missing'
    return importlib.import_module('maml.v1')


def test_relative_capture_and_follow():
    v1 = api()
    image = v1.Image(bytes.fromhex('E8 01 00 00 00 90 CC'))
    hit = v1.Pattern('E8 rel32(callee) 90').find(image)
    assert hit.offset == 0 and hit.capture('callee').value == 6
    assert v1.Pattern('E8 rel32(callee):follow CC').find(image).capture('callee').value == 6
    with pytest.raises(v1.SchemaError):
        hit.capture('typo')


def test_pipeline_records_projection_and_prevalidation():
    v1 = api()
    image = v1.Image(bytes.fromhex('E8 05 00 00 00 E8 00 00 00 00 CC'), funcs=[(0, 11)])
    matches = v1.Pipeline('bytes("E8 rel32(callee)")').run(image)
    assert len(matches.matches) == 2
    result = v1.Pipeline('bytes("E8 rel32(callee)") -> capture("callee") -> unique').run(image)
    assert [v.value for v in result.values] == [10]
    with pytest.raises(v1.CardinalityError):
        v1.Pipeline('bytes("E8 rel32(callee)") -> unique').run(image)
    with pytest.raises(v1.SchemaError):
        v1.Pipeline('bytes("FF @(real)") -> capture("typo")')


def test_pipeline_string_xref_func_find():
    v1 = api()
    data = bytearray(64)
    data[:12] = bytes.fromhex('48 8D 05 19 00 00 00 E8 04 00 00 00')
    data[16] = 0xCC
    data[32:40] = b'Example\0'
    image = v1.Image(data, code=[(0, 24)], rodata=[(32, 40)], funcs=[(0, 12),(16,24)])
    result = v1.Pipeline('str("Example") -> xrefs -> func -> find("E8 rel32(init)") -> capture("init") -> unique').run(image)
    assert result.values[0].value == 16


def test_seeded_matches_equal_exhaustive():
    import random
    v1 = api()
    rng = random.Random(302)
    for text in ['AA ?? BB', '(AA | BB) [0..3] @(x) CC', 'E8 rel32(x):follow CC', '?? @(x)', 'AA [2] BB', 'AA rel8(x) BB']:
        pattern = v1.Pattern(text)
        for _ in range(30):
            image = v1.Image(bytes(rng.choice([0xAA,0xBB,0xCC,0xE8,0,1,0xFF]) for _ in range(40)))
            assert pattern.find_all(image) == pattern.find_all(image, exhaustive=True)


CASES = json.loads((Path(__file__).parents[2] / 'conformance/v1.json').read_text())['cases']
@pytest.mark.parametrize('case', CASES, ids=lambda c:c['id'])
def test_conformance(case):
    api()
    from maml.v1_adapter import execute
    actual = execute(case['request'])
    expected = case['expect']
    if 'schema' in actual:
        actual['schema'] = sorted(actual['schema'])
        expected = dict(expected, schema=sorted(expected['schema']))
    if 'values' in actual:
        key = lambda x:(x['value'], x['kind'], x['space'])
        actual['values'] = sorted(actual['values'],key=key)
        expected = dict(expected,values=sorted(expected['values'],key=key))
    assert actual == expected

@pytest.mark.parametrize('text', ['?', '[5..2]', '(AA |)', 'rel32(x, width=8)', 'AA:follow', 'rel8(x):follow:follow'])
def test_rejects_malformed_patterns(text):
    v1=api()
    with pytest.raises(v1.CompileError):
        v1.Pattern(text)


def test_full_width_pipeline_captures_and_branch_absence():
    v1=api()
    image=v1.Image(bytes.fromhex('89 FF FF FF FF FF FF FF FF'))
    result=v1.Pipeline('bytes("(88 @(a) | 89 ptr64(b))") -> capture("b") -> unique').run(image)
    assert result.values == (v1.CaptureValue(0xffffffffffffffff,'AbsolutePointerValue','absolute'),)
    assert v1.Pipeline('bytes("(88 @(a) | 89 ptr64(b))") -> capture("a")').run(image).values == ()
    with pytest.raises(v1.CompileError, match='not implicitly mapped'):
        v1.Pipeline('bytes("89 ptr64(b)") -> capture("b") -> func').run(image)


def test_empty_input_still_validates_pipeline_schema():
    v1=api()
    with pytest.raises(v1.SchemaError):
        v1.Pipeline('str("Absent") -> func -> find("@(real)") -> capture("wrong")')


def test_pipeline_selection_read_and_callers_with_base():
    v1=api()
    image=v1.Image(bytes.fromhex('E8 01 00 00 00 90 CC'),base=0x1000,code=[(0,7)],funcs=[(0,6),(6,7)])
    result=v1.Pipeline('bytes("CC") -> func -> callers -> nth(0) -> read(1) -> unique').run(image)
    assert result.values[0].value==0xE8
    assert v1.Pipeline('bytes("??") -> limit(2)').run(image).matches[-1].offset==1
    assert v1.Pipeline('bytes("??") -> nth(99)').run(image).matches==()


def test_scope_find_can_explicitly_follow_outside_function():
    v1=api()
    image=v1.Image(bytes.fromhex('E8 01 00 00 00 90 CC'),funcs=[(0,5)])
    result=v1.Pipeline('bytes("E8") -> func -> find("E8 rel32(x):follow CC") -> unique').run(image)
    assert result.matches[0].capture('x').value==6


def test_parser_resource_limits():
    v1=api()
    with pytest.raises(v1.ExecutionError,match='nesting'):
        v1.Pattern('('*66+'AA'+')'*66)
    with pytest.raises(v1.ExecutionError,match='65536'):
        v1.Pipeline('str("'+'A'*65536+'")')


def test_capture_only_at_image_end_and_zero_length_image():
    v1=api()
    hits=v1.Pattern('@(x)').find_all(v1.Image(b'',base=0x1000))
    assert hits[0].capture('x').value==0x1000
    assert v1.Pattern('AA').find_all(v1.Image(b''))==[]


def test_compile_error_carries_native_position():
    v1=api()
    with pytest.raises(v1.CompileError) as error:
        v1.Pattern('AA GG')
    assert error.value.code=='InvalidSyntax'
    assert error.value.position==4


def test_captures_and_checkpoints_are_bounded():
    v1=api()
    with pytest.raises(v1.ExecutionError,match='256 captures'):
        v1.Pattern(' '.join(f'@(c{i})' for i in range(257)))
    with pytest.raises(v1.ExecutionError,match='checkpoint'):
        v1.Pattern('[0..4096] AA').match_at(v1.Image(bytes(4097)))


def test_native_cli_dialect_selection(tmp_path):
    import subprocess
    v1=api()
    root=Path(__file__).parents[2]
    def exe(name):
        candidates=[root/'build'/name,root/'build'/(name+'.exe'),root/'build/Release'/(name+'.exe'),root/'build/Debug'/(name+'.exe')]
        import os
        override=os.environ.get('MAML_SCAN' if name=='mamlscan' else 'MAML_PIPE')
        if override:
            assert Path(override).is_file(), f'Invalid CLI override: {override}'
            return override
        found=next((p for p in candidates if p.is_file()),None)
        if found is None:
            pytest.skip(f'Build {name} to run native CLI integration')
        return str(found)
    image=tmp_path/'image.bin'; image.write_bytes(bytes.fromhex('E8 01 00 00 00 90 CC'))
    ranges=tmp_path/'ranges.txt'; ranges.write_text('size 7\ncode 0 7\nfunc 0 7\n')
    scan=subprocess.run([exe('mamlscan'),'--dialect','maml-v1',str(image),'E8 rel32(x):follow CC','--capture','x'],capture_output=True,text=True)
    assert scan.returncode==0,scan.stderr+scan.stdout
    assert '6' in scan.stdout
    pipe=subprocess.run([exe('mamlpipe'),'--dialect','maml-v1',str(image),'--ranges',str(ranges),'bytes("E8 rel32(x)") -> capture("x") -> unique'],capture_output=True,text=True)
    assert pipe.returncode==0,pipe.stderr+pipe.stdout
    assert 'ResolvedRelativeTarget' in pipe.stdout and '6' in pipe.stdout
