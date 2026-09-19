import struct
import pytest
import maml
from maml import v1
from maml._containers import Range


def split_image():
    data = bytearray(b'\x90' * 128)
    data[8:10] = b'\xAA\xBB'
    data[40:42] = b'\xAB\xCD'  # unrelated function in the gap
    data[72:74] = b'\xAB\xCD'  # parent's noncontiguous tail
    return v1.Image(data, base=0x1000, functions=[
        maml.Function(8, [(8,16),(64,80)]), maml.Function(32, [(32,48)])])


def test_func_and_find_resolve_entry_and_all_spans_without_gap():
    image = split_image()
    assert [v.value for v in v1.Pipeline('bytes("AB CD") -> func').run(image).values] == [0x1008,0x1020]
    result = v1.Pipeline('bytes("AA BB") -> find("AB CD")').run(image)
    assert [m.offset for m in result.matches] == [72]
    result = v1.Pipeline('bytes("AB CD") -> nth(1) -> find("AA BB")').run(image)
    assert [m.offset for m in result.matches] == [8]
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('bytes("AB CD") -> nth(1) -> func:strict').run(image)
    assert v1.Pipeline('bytes("AA BB") -> func:strict').run(image).values[0].value == 0x1008


def test_fragment_start_is_not_entry_and_uncovered_gap_drops():
    image=split_image()
    assert [v.value for v in v1.Pipeline('bytes("90") -> func').run(
        v1.Image(b'\x90'*16,functions=[maml.Function(0,[(0,1)])])).values] == [0]
    for at in [64,72]:
        source=f'bytes("[{at}] @(x)") -> nth(0) -> capture("x") -> func:strict'
        with pytest.raises(v1.ExecutionError): v1.Pipeline(source).run(image)
    result=v1.Pipeline('bytes("[24] @(x)") -> nth(0) -> capture("x") -> func').run(image)
    assert not result.ok


def test_range_only_function_api_is_removed():
    with pytest.raises(TypeError):
        v1.Image(b'\xAA\xBB', funcs=[(0,2)])
    with pytest.raises(TypeError):
        v1.Image(b'\xAA\xBB', functions=[Range(0,2)])


@pytest.mark.parametrize('functions', [
    [(0,[])], [(0,[(1,2)])], [(0,[(0,17)])],
    [(0,[(0,4)]),(2,[(2,8)])], [(0,[(0,2)]),(0,[(0,3)])],
])
def test_invalid_ownership_rejected(functions):
    with pytest.raises(ValueError):
        v1.Image(bytes(16),functions=[maml.Function(e,s) for e,s in functions])


def test_pdata_preserves_separated_tail_and_neighbor():
    from maml._containers import functions_from_pdata
    parent=(8,16,0x100); child=(64,80,0x120); neighbor=(32,48,0x140)
    data=bytearray(512)
    data[0x100]=data[0x140]=1
    data[0x120:0x124]=bytes([0x21,0,1,0])
    struct.pack_into('<III',data,0x128,*parent)
    raw=b''.join(struct.pack('<III',*r) for r in [child,neighbor,parent])
    functions=functions_from_pdata(raw,[Range(0,128)],data)
    assert [(f.entry,f.spans) for f in functions] == [(8,((8,16),(64,80))),(32,((32,48),))]


def test_generator_string_anchor_in_separate_span_and_tail_clamping():
    data=bytearray(b'\xCC'*512)
    data[256:269]=b'UNIQUESTRING\0'
    data[64:71]=bytes.fromhex('48 8D 05')+(256-71).to_bytes(4,'little')
    data[71:80]=bytes.fromhex('48 89 C8 48 85 C0 74 01 C3')
    image=v1.Image(data,code=[(0,128)],rodata=[(256,269)],
        functions=[maml.Function(8,[(8,16),(64,80)])])
    options=v1.generate.Options(want=16,max_len=64,prefer_short=False)
    candidates=v1.generate.candidates(image,8,options)
    anchor=next(c for c in candidates if c.strategy.name=='StringAnchor')
    assert anchor.anchor_site == 64 and anchor.anchor_delta == 56
    assert v1.generate.resolve_consensus(image,[anchor])[0].address == 8
    # This LEA plus its literal tail must stop at the span end, not enter padding.
    assert len(anchor.pattern.split()) == 16
    bodies=[c for c in candidates if c.strategy.name=='Body']
    assert all(any(lo <= c.anchor_site < hi for lo,hi in image.functions[0].spans) for c in bodies)


def test_reference_tail_at_span_end_does_not_read_gap():
    data=bytearray(b'\xCC'*128)
    data[8:13]=b'\xE8'+(64-13).to_bytes(4,'little')
    image=v1.Image(data,code=[(0,128)],functions=[maml.Function(8,[(8,13)]),maml.Function(64,[(64,72)])])
    cs=v1.generate.candidates(image,64,v1.generate.Options(want=16,prefer_short=False))
    assert not any(c.strategy.name=='Xref' for c in cs)


def test_from_pe_populates_full_metadata_and_preserves_flatten_tuple(tmp_path):
    lief=pytest.importorskip('lief')
    from test_generate import _build_pe_with_sections
    from maml._containers import flatten_pe
    from maml import _core
    path=_build_pe_with_sections(tmp_path)
    binary=lief.PE.parse(str(path))
    text=bytearray(binary.sections[0].content)
    text[8:10]=b'\xAA\xBB'; text[48:50]=b'\xAB\xCD'
    binary.sections[0].content=list(text)
    unwind=bytearray(binary.sections[1].content)
    unwind[0]=1; unwind[8:12]=bytes([0x21,0,1,0])
    parent=(0x1008,0x1010,0x2000)
    struct.pack_into('<III',unwind,16,*parent)
    binary.sections[1].content=list(unwind)
    raw=b''.join(struct.pack('<III',*r) for r in [parent,(0x1030,0x1040,0x2008)])
    binary.sections[2].content=list(raw)+[0]*(512-len(raw))
    builder=lief.PE.Builder(binary,lief.PE.Builder.config_t()); builder.build(); builder.write(str(path))
    assert len(flatten_pe(path)) == 5
    image=v1.Image.from_pe(path)
    assert image.functions[0].spans == ((0x1008,0x1010),(0x1030,0x1040))
    assert not hasattr(image, "funcs")
    assert _core.Image.from_pe(path).functions == list(image.functions)
    assert v1.Pipeline('bytes("AB CD") -> func -> unique').run(image).values[0].value == 0x1008
    assert v1.Pipeline('bytes("AA BB") -> find("AB CD") -> unique').run(image).matches[0].offset == 0x1030

    import runpy
    from pathlib import Path
    flattener = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'tools/durability/flatten.py'))
    manifest = flattener['write_build'](path, 'split', tmp_path / 'export')
    assert 'funcs' not in manifest
    assert manifest['functions'][0]['spans'] == ((0x1008,0x1010),(0x1030,0x1040))
    assert 'function 4104 4144 4160' in (tmp_path / 'export/split.txt').read_text()


def test_spans_before_entry_are_owned_without_new_entry():
    image=v1.Image(bytes.fromhex('AA 90 90 BB'), functions=[maml.Function(3,[(0,1),(3,4)])])
    assert v1.Pipeline('bytes("AA") -> func').run(image).values[0].value == 3
    assert v1.Pipeline('bytes("BB") -> find("AA")').run(image).matches[0].offset == 0
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('bytes("AA") -> func:strict').run(image)


def test_only_one_metadata_collection_exists():
    image=v1.Image(bytes.fromhex('AA 90 90 BB'),functions=[maml.Function(0,[(0,1),(3,4)])])
    assert not hasattr(image, 'funcs')
    assert not v1.Pipeline('bytes("AA") -> find("90")').run(image).ok


def test_pdata_full_metadata_rejects_conflicting_ownership():
    from maml._containers import functions_from_pdata
    data=bytearray(512); data[256]=data[272]=1
    raw=struct.pack('<IIIIII',8,32,256,16,48,272)
    with pytest.raises(ValueError,match='ownership'):
        functions_from_pdata(raw,[Range(0,128)],data)


@pytest.mark.parametrize('count', range(7))
def test_middle_signature_resolves_outermost_entry_after_more_than_eight_hops(count):
    from maml._containers import functions_from_pdata
    data=bytearray(4096)
    records=[(0x100+i*0x20,0x110+i*0x20,0x800+i*0x40) for i in range(12)]
    data[records[0][2]]=1
    for child,parent in zip(records[1:],records):
        unwind=child[2]
        data[unwind:unwind+4]=bytes([0x21,0,count,0])
        struct.pack_into('<III',data,unwind+4+2*((count+1)&~1),*parent)
    hit=records[-1][0]+5  # signature deliberately inside the deepest chunk
    data[hit:hit+4]=bytes.fromhex('DE AD BE EF')
    raw=b''.join(struct.pack('<III',*record) for record in reversed(records))
    functions=functions_from_pdata(raw,[Range(0x100,0x400)],data)
    assert len(functions)==1 and functions[0].entry==0x100
    image=v1.Image(data,base=0x140000000,functions=functions)
    result=v1.Pipeline('bytes("DE AD BE EF") -> func -> unique').run(image)
    assert result.values[0].value==0x140000100
    assert result.values[0].value != image.base + records[-1][0]


def test_cycle_never_yields_a_fragment_as_callable_entry():
    from maml._containers import functions_from_pdata
    data=bytearray(1024)
    a,b=(0x100,0x110,0x200),(0x120,0x130,0x240)
    for record,parent in [(a,b),(b,a)]:
        data[record[2]]=0x21
        struct.pack_into('<III',data,record[2]+4,*parent)
    data[0x125:0x129]=bytes.fromhex('DE AD BE EF')
    functions=functions_from_pdata(struct.pack('<IIIIII',*a,*b),[Range(0x100,0x140)],data)
    assert functions == []
    with pytest.raises(v1.ExecutionError,match='function'):
        v1.Pipeline('bytes("DE AD BE EF") -> func').run(v1.Image(data,functions=functions))


@pytest.mark.parametrize('defect', ['outside', 'header', 'codes', 'version', 'flags'])
def test_invalid_primary_unwind_does_not_promote_its_child(defect):
    from maml._containers import functions_from_pdata
    data = bytearray(1024)
    unwind = {'outside': 1024, 'header': 1022, 'codes': 1020}.get(defect, 0x200)
    parent, child = (0x100, 0x110, unwind), (0x120, 0x130, 0x240)
    if unwind < len(data):
        data[unwind] = {'version': 0, 'flags': 0x81}.get(defect, 1)
    if defect == 'codes':
        data[unwind + 2] = 2
    data[child[2]] = 0x21
    struct.pack_into('<III', data, child[2] + 4, *parent)
    raw = struct.pack('<IIIIII', *parent, *child)
    assert functions_from_pdata(raw, [Range(0x100, 0x140)], data) == []


def test_cli_rejects_range_only_function_manifest(tmp_path):
    import os
    from pathlib import Path
    import subprocess
    root = Path(__file__).resolve().parents[2]
    cli = Path(os.environ.get('MAML_PIPE', root / 'build' / 'mamlpipe'))
    if not cli.is_file():
        pytest.skip('Build mamlpipe to run native CLI integration')
    image = tmp_path / 'image.bin'
    image.write_bytes(b'\xAA\xBB')
    manifest = tmp_path / 'ranges.txt'
    manifest.write_text('size 2\nfunc 0 2\n')
    result = subprocess.run([str(cli), str(image), '--ranges', str(manifest),
                             'bytes("BB") -> func'], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'unrecognised line' in result.stderr
    manifest.write_text('size 2\nfunction 0 0 2\n')
    result = subprocess.run([str(cli), str(image), '--ranges', str(manifest),
                             'bytes("BB") -> func -> unique'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
