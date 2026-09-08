import pytest
from maml import v1


def builder():
    assert hasattr(v1,'PipelineBuilder'), 'PipelineBuilder is missing'
    return v1.PipelineBuilder()


def test_builder_matches_multiline_text_with_capture_and_strict_func():
    image=v1.Image(bytes.fromhex('E8 01 00 00 00 90 CC'),funcs=[(0,6),(6,7)])
    text='''bytes("E8 rel32(target):follow CC")
        -> capture("target")
        -> func:strict
        -> unique'''
    expected=v1.Pipeline(text).run(image)
    actual=(builder().bytes('E8 rel32(target):follow CC').capture('target')
            .func(strict=True).unique().build().run(image))
    assert actual==expected


def test_builder_reuses_immutable_prefix_and_same_validation():
    base=builder().bytes('AA')
    one=base.unique()
    none=base.limit(0)
    image=v1.Image(bytes.fromhex('AA AA'))
    assert len(base.build().run(image).matches)==2
    assert not none.build().run(image).ok
    with pytest.raises(v1.CardinalityError): one.build().run(image)
    with pytest.raises(v1.SchemaError): builder().bytes('@(here)').capture('typo').build()
    with pytest.raises(v1.CompileError): builder().read(3).build()
    with pytest.raises(v1.CompileError): builder().build()


def test_builder_quotes_arguments_without_injecting_stages():
    text='say "hello" -> unique \\ end'
    query=builder().str(text).unique()
    image=v1.Image(text.encode()+b'\0',rodata=[(0,len(text)+1)])
    result=query.build().run(image)
    assert result.values[0].value==0
    assert len(result.trace)==2
    assert '\\"' in query.source and '\\\\' in query.source
    builder().str('\n\t\x01').build()


def test_builder_all_transforms_and_loose_mode():
    image=v1.Image(bytes.fromhex('E8 01 00 00 00 90 CC'),code=[(0,7)],funcs=[(0,6),(6,7)])
    for step in ('xrefs','callers'):
        prefix=builder().bytes('CC').func(strict=False)
        query=getattr(prefix,step)().nth(0).read(1).unique()
        assert query.build().run(image).values[0].value==0xE8
    image=v1.Image(bytes.fromhex('AA BB'),funcs=[(0,2)])
    query=builder().bytes('AA').func().find('BB').unique()
    assert query.build().run(image).matches[0].offset==1


@pytest.mark.parametrize('method',['nth','limit','read'])
def test_builder_rejects_invalid_numeric_arguments(method):
    with pytest.raises(ValueError): getattr(builder().bytes('AA'),method)(-1)


def test_newline_does_not_replace_pipeline_separator():
    with pytest.raises(v1.CompileError): v1.Pipeline('bytes("AA")\nunique')
