"""Chained x64 unwind coverage without introducing fragment entries."""
import struct
import pytest
from maml import v1
from maml._containers import Range, funcs_from_pdata


def fixture(records, links, size=0x2000):
    buf = bytearray(size)
    for begin, end, unwind in records:
        buf[unwind] = 1
    for unwind, parent, count in links:
        buf[unwind:unwind+4] = bytes([0x21, 0, count, 0])
        offset = unwind + 4 + 2 * ((count + 1) & ~1)
        struct.pack_into('<III', buf, offset, *parent)
    return buf, b''.join(struct.pack('<III', *r) for r in records)


def test_contiguous_fragment_maps_to_parent_and_find_searches_tail():
    parent, fragment = (0x200,0x235,0x1000), (0x235,0x500,0x1040)
    buf, raw = fixture([fragment,parent], [(fragment[2],parent,3)])
    buf[0x393:0x395] = b'\xAB\xCD'
    funcs = funcs_from_pdata(raw, [Range(0x200,0x500)], buf)
    assert [(f.begin,f.end) for f in funcs] == [(0x200,0x500)]
    image = v1.Image(buf, funcs=funcs)
    assert v1.Pipeline('bytes("AB CD") -> func -> unique').run(image).values[0].value == 0x200
    assert v1.Pipeline('bytes("AB CD") -> func -> find("AB CD") -> unique').run(image).matches[0].offset == 0x393
    with pytest.raises(v1.ExecutionError):
        v1.Pipeline('bytes("AB CD") -> func:strict').run(image)


def test_multilevel_chains_and_duplicate_records_are_order_independent():
    a,b,c = (0x200,0x240,0x1000),(0x240,0x280,0x1040),(0x280,0x300,0x1080)
    buf, raw = fixture([c,b,a,b], [(b[2],a,0),(c[2],b,2)])
    assert [(f.begin,f.end) for f in funcs_from_pdata(raw,[Range(0x100,0x900)],buf)] == [(0x200,0x300)]


def test_disconnected_fragments_do_not_bridge_an_unrelated_function():
    a,b,other=(0x200,0x240,0x1000),(0x300,0x340,0x1040),(0x260,0x280,0x1080)
    buf,raw=fixture([a,b,other],[(b[2],a,1)])
    assert [(f.begin,f.end) for f in funcs_from_pdata(raw,[Range(0x100,0x900)],buf)] == [(0x200,0x240),(0x260,0x280)]


@pytest.mark.parametrize('bad', ['cycle','missing_parent','truncated','conflicting_flags'])
def test_malformed_chains_never_become_entries(bad):
    a,b=(0x200,0x240,0x1000),(0x240,0x280,0x1040)
    buf,raw=fixture([a,b],[(b[2],a,0)])
    if bad == 'cycle': struct.pack_into('<III',buf,b[2]+4,*b)
    elif bad == 'missing_parent': struct.pack_into('<III',buf,b[2]+4,0x300,0x340,0x1080)
    elif bad == 'truncated':
        b=(b[0],b[1],len(buf)-4)
        buf[-4:]=bytes([0x21,0,0,0])
        raw=struct.pack('<IIIIII',*a,*b)
    else: buf[b[2]]=0x29
    assert [(f.begin,f.end) for f in funcs_from_pdata(raw,[Range(0x100,0x900)],buf)] == [(0x200,0x240)]


def test_69893_reported_layout():
    parent = (0x28292D0, 0x2829305, 0x1000)
    fragment = (0x2829305, 0x282A2A6, 0x1040)
    buf, raw = fixture([parent, fragment], [(fragment[2], parent, 1)], size=0x282A300)
    funcs = funcs_from_pdata(raw, [Range(parent[0], fragment[1])], buf)
    assert [(f.begin, f.end) for f in funcs] == [(parent[0], fragment[1])]
    assert funcs[0].begin <= 0x2829B93 < funcs[0].end


def test_chain_cannot_extend_over_another_primary_entry():
    a, b, other = (0x200,0x240,0x1000),(0x240,0x300,0x1040),(0x280,0x320,0x1080)
    buf, raw = fixture([a,b,other], [(b[2],a,0)])
    assert [(f.begin,f.end) for f in funcs_from_pdata(raw,[Range(0x100,0x900)],buf)] == [(0x200,0x240),(0x280,0x320)]


def test_chain_does_not_extend_across_nonexecutable_bytes():
    a,b=(0x200,0x240,0x1000),(0x240,0x300,0x1040)
    buf,raw=fixture([a,b],[(b[2],a,0)])
    assert [(f.begin,f.end) for f in funcs_from_pdata(raw,[Range(0x200,0x280)],buf)] == [(0x200,0x240)]
