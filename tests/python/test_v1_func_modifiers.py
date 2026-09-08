import pytest
from maml import v1


def test_loose_is_func_alias_and_trace_names_modifier():
    image=v1.Image(bytes.fromhex('90 AA AA'),funcs=[(0,3)])
    plain=v1.Pipeline('bytes("AA") -> func').run(image)
    loose=v1.Pipeline('bytes("AA") -> func:loose').run(image)
    assert loose.values==plain.values
    assert loose.trace[-1].stage=='func:loose'


@pytest.mark.parametrize('pattern',['90','??'])
def test_strict_rejects_interior_even_when_entry_is_present(pattern):
    image=v1.Image(bytes.fromhex('90 90'),funcs=[(0,2)])
    with pytest.raises(v1.ExecutionError,match='known function entry') as error:
        v1.Pipeline(f'bytes("{pattern}") -> func:strict').run(image)
    assert error.value.code=='NotFunctionEntry'


def test_strict_accepts_entries_and_projected_addresses_with_base():
    image=v1.Image(bytes.fromhex('AA 90 AA 90'),base=0x1000,funcs=[(0,2),(2,4)])
    result=v1.Pipeline('bytes("@(entry) AA") -> capture("entry") -> func:strict').run(image)
    assert [v.value for v in result.values]==[0x1000,0x1002]
    assert result.trace[-1].stage=='func:strict'


def test_strict_rejects_uncovered_addresses_but_loose_drops_them():
    image=v1.Image(bytes.fromhex('AA BB'),funcs=[(0,1)])
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('bytes("BB") -> func:strict').run(image)
    assert not v1.Pipeline('bytes("BB") -> func:loose').run(image).ok


def test_empty_input_and_missing_metadata_are_distinct():
    pipeline=v1.Pipeline('bytes("FF") -> func:strict')
    assert not pipeline.run(v1.Image(b'\x90',funcs=[(0,1)])).ok
    with pytest.raises(v1.ExecutionError,match='function ranges'):
        pipeline.run(v1.Image(b'\x90'))


@pytest.mark.parametrize('stage',['func:typo','func:strict0','func:strict:loose','func:loose:loose','unique:strict','find("AA"):loose','func:','func: strict','func :strict'])
def test_invalid_modifiers_are_compile_errors(stage):
    with pytest.raises(v1.CompileError) as error:
        v1.Pipeline('bytes("AA") -> '+stage)
    assert error.value.code=='InvalidModifier'
