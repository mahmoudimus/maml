import pytest
from maml import v1


def test_all_nibble_masks_over_every_byte():
    image=v1.Image(bytes(range(256)))
    seeded_image=v1.Image(b"".join(bytes([0xAA,x,0xBB]) for x in range(256)))
    for nibble in range(16):
        for text,want in [(f'{nibble:X}?',[x for x in range(256) if x>>4==nibble]),
                          (f'?{nibble:X}',[x for x in range(256) if x&15==nibble])]:
            pattern=v1.Pattern(text)
            assert [h.offset for h in pattern.find_all(image)]==want
            assert pattern.find_all(image)==pattern.find_all(image,exhaustive=True)
            anchored=v1.Pattern("AA "+text+" BB")
            assert [h.offset for h in anchored.find_all(seeded_image)]==[3*x for x in want]
            assert anchored.find_all(seeded_image)==anchored.find_all(seeded_image,exhaustive=True)
            for x in range(256):
                assert (pattern.match_at(image,x) is not None)==(x in want)
    assert [h.offset for h in v1.Pattern('??').find_all(image)]==list(range(256))
    assert v1.Pattern('??').match_at(v1.Image(b'')) is None


def gen():
    assert hasattr(v1,'generate'), 'v1 generator is missing'
    return v1.generate


def make(callee,site,tail):
    data=bytearray(b'\xCC'*256)
    data[callee:callee+8]=bytes.fromhex('48 89 E5 55 41 53 90 C3')
    data[site:site+5]=b'\xE8'+(callee-site-5).to_bytes(4,'little',signed=True)
    data[site+5:site+5+len(tail)]=tail
    return v1.Image(data,code=[(0,256)],funcs=[(callee,callee+8),(site,site+5+len(tail))])


def test_generated_references_have_dialect_and_named_target():
    g=gen();image=make(16,64,bytes.fromhex('4C 8B D0 48'))
    cs=g.candidates(image,16)
    ref=next(c for c in cs if c.target_capture)
    assert ref.dialect=='maml-v1' and ref.target_capture=='target'
    assert 'rel32(target)' in ref.pattern
    assert not hasattr(ref,'save_index')
    assert v1.Pattern(ref.pattern).find(image).capture('target').value==16
    assert g.resolve_consensus(image,[ref])[0].address==16


def test_verified_generates_nibbles_and_checks_both_builds():
    g=gen()
    a=make(16,64,bytes.fromhex('4C 8B D1 48'))
    b=make(32,96,bytes.fromhex('4C 8B D7 48'))
    cs=g.verified(a,16,b,32,g.Options(nibble_wildcards=True,prefer_short=False))
    masked=[c for c in cs if 'D?' in c.pattern]
    assert masked
    for image,target in [(a,16),(b,32)]:
        assert g.resolve_consensus(image,masked)[0].address==target
    exact=g.verified(a,16,b,32,g.Options(nibble_wildcards=False,prefer_short=False))
    assert all('D?' not in c.pattern for c in exact)


def test_verification_does_not_accept_ambiguous_masked_pattern():
    g=gen()
    a=make(16,64,bytes.fromhex('4C 8B D1 48'))
    b=make(32,96,bytes.fromhex('4C 8B D7 48'))
    data=bytearray(b.data)
    data[160:169]=b'\xE8'+(32-165).to_bytes(4,'little',signed=True)+bytes.fromhex('4C 8B D3 48')
    b=v1.Image(data,code=[(0,256)],funcs=b.funcs+((160,169),))
    cs=g.verified(a,16,b,32,g.Options(nibble_wildcards=True,prefer_short=False))
    assert not any('D?' in c.pattern for c in cs)

@pytest.mark.parametrize('left,right,expected',[('A1','B1','?1'),('A1','B2','??')])
def test_generated_low_nibble_and_full_byte_masks(left,right,expected):
    g=gen();a=make(16,64,bytes.fromhex('4C 8B '+left+' 48'));b=make(32,96,bytes.fromhex('4C 8B '+right+' 48'))
    cs=g.verified(a,16,b,32,g.Options(prefer_short=False))
    masked=[c for c in cs if '4C 8B '+expected+' 48' in c.pattern]
    assert masked
    for image,target in [(a,16),(b,32)]:
        assert g.resolve_consensus(image,masked)[0].address==target


def test_rip_immediate_adjustment_and_string_anchor():
    g=gen()
    data=bytearray(b'\xCC'*1024)
    site,target=0x100,0x300
    data[site:site+11]=bytes.fromhex('48 C7 05')+(target-site-11).to_bytes(4,'little')+bytes.fromhex('01 00 00 00')
    image=v1.Image(data,code=[(0,0x300)],rodata=[(0x300,0x310)],funcs=[(0x100,0x200)])
    ref=next(c for c in g.candidates(image,target) if c.strategy.name=='RipRef')
    assert 'rel32(target, target_add=4)' in ref.pattern
    assert g.resolve_consensus(image,[ref])[0].address==target
    data=bytearray(b'\xCC'*1024)
    data[0x300:0x30D]=b'UNIQUESTRING\0'
    data[0x110:0x117]=bytes.fromhex('48 8D 05')+(0x300-0x117).to_bytes(4,'little')
    image=v1.Image(data,code=[(0,0x300)],rodata=[(0x300,0x30D)],funcs=[(0x100,0x200)])
    anchor=next(c for c in g.candidates(image,0x180) if c.strategy.name=='StringAnchor')
    assert '?? ?? ?? ??' in anchor.pattern
    assert anchor.anchor_delta==-112 and anchor.target_capture==''
    assert g.resolve_consensus(image,[anchor])[0].address==0x180


def test_semantic_generation_rejects_wrong_dialect_and_delta_underflow():
    from dataclasses import replace
    g=gen();image=make(16,64,bytes.fromhex('4C 8B D1 48'))
    body=next(c for c in g.candidates(image,16) if c.strategy.name=='Body')
    with pytest.raises(ValueError):
        g.resolve_consensus(image,[replace(body,dialect='unknown')])
    assert g.resolve_consensus(image,[replace(body,anchor_delta=1000)])==[]
    assert g.verified(image,16,image,16)==[]


def test_one_anchor_cannot_fill_verified_budget_with_mask_variants():
    g=gen()
    a=make(16,64,bytes.fromhex('4C 8B D1 48'))
    b=make(32,96,bytes.fromhex('4C 8B D7 48'))
    data=bytearray(b.data)
    data[160:169]=b'\xE8'+(32-165).to_bytes(4,'little',signed=True)+bytes.fromhex('4C 89 D1 48')
    b=v1.Image(data,code=[(0,256)],funcs=b.funcs+((160,169),))
    cs=g.verified(a,16,b,32,g.Options(prefer_short=False))
    origins=[(c.strategy,c.anchor_site) for c in cs]
    assert len(origins)==len(set(origins))


def test_string_anchor_call_capture_uses_semantic_reference():
    g=gen()
    data=bytearray(b'\xCC'*1024)
    data[0x300:0x30D]=b'UNIQUESTRING\0'
    data[0x100:0x107]=bytes.fromhex('48 8D 05')+(0x300-0x107).to_bytes(4,'little')
    data[0x110:0x115]=b'\xE8'+(0x200-0x115).to_bytes(4,'little')
    image=v1.Image(data,code=[(0,0x300)],rodata=[(0x300,0x30D)],funcs=[(0x100,0x120),(0x200,0x210)])
    anchors=[c for c in g.candidates(image,0x200,g.Options(want=16)) if c.strategy.name=='StringAnchor' and c.target_capture]
    assert anchors
    assert all('rel32(target)' in c.pattern and '?? ?? ?? ??' in c.pattern for c in anchors)
    assert g.resolve_consensus(image,anchors)[0].address==0x200
