from maml import Function, v1
import pytest


def _image():
    # movups xmm0,[rcx+0x228] (16-byte read); movss xmm0,[rcx+0x111] (4-byte read); ret
    code = "0F 10 81 28 02 00 00 F3 0F 10 81 11 01 00 00 C3"
    return v1.Image(bytes.fromhex(code), functions=[Function(0, [(0, 16)])],
                    instructions=[(0, 7), (7, 15), (15, 16)])


def test_insn_size_selects_the_right_read():
    img = _image()
    r16 = v1.Pipeline('bytes("C3") -> func -> insn("read size=16 disp(d)") -> capture("d") -> unique').run(img)
    assert [v.value for v in r16.values] == [0x228]
    r4 = v1.Pipeline('bytes("C3") -> func -> insn("read size=4 disp(d)") -> capture("d") -> unique').run(img)
    assert [v.value for v in r4.values] == [0x111]


def test_insn_size_filter_is_strict_and_capture_is_required():
    img = _image()
    none = v1.Pipeline('bytes("C3") -> func -> insn("read size=2 disp(d)") -> capture("d")').run(img)
    assert list(none.values) == []
    both = v1.Pipeline('bytes("C3") -> func -> insn("read disp(d)") -> capture("d")').run(img)
    assert sorted(v.value for v in both.values) == [0x111, 0x228]
    try:
        v1.Pipeline('bytes("C3") -> func -> insn("read size=4")')
        assert False, "expected parse error for missing capture"
    except Exception as e:
        assert "capture" in str(e)


def _window_image():
    code = (
        "8B 81 10 00 00 00 "        # 0:  mov   eax, [rcx+0x10]
        "E8 00 00 00 00 "           # 6:  call  +0  (anchor)
        "F3 0F 10 81 68 01 00 00 "  # 11: movss xmm0, [rcx+0x168]
        "8B 81 64 01 00 00 "        # 19: mov   eax, [rcx+0x164]
        "C3"                        # 25: ret
    )
    data = bytes.fromhex(code)
    return v1.Image(data, functions=[Function(0, [(0, len(data))])],
                    instructions=[(0, 6), (6, 11), (11, 19), (19, 25), (25, 26)])


def test_insn_within_scopes_decoding_to_a_cursor_window():
    img = _window_image()
    whole = v1.Pipeline('bytes("C3") -> insn("read size=4 disp(d)")').run(img)
    assert len(whole.matches) == 3
    near = v1.Pipeline('bytes("E8 ?? ?? ?? ??") -> insn("read size=4 disp(d)", within=12) -> capture("d") -> unique').run(img)
    assert [v.value for v in near.values] == [0x168]
    wide = v1.Pipeline('bytes("E8 ?? ?? ?? ??") -> insn("read size=4 disp(d)", within=13)').run(img)
    assert [m.offset for m in wide.matches] == [11, 19]


def test_insn_cursor_captures_the_displacement_bytes():
    img = _window_image()
    at = v1.Pipeline('bytes("E8 ?? ?? ?? ??") -> insn("read size=4 disp_addr(d)", within=12) -> capture("d") -> unique').run(img)
    assert [v.value for v in at.values] == [15]
    assert at.values[0].kind == "CursorAddress"
    literal = v1.Pipeline('bytes("E8 ?? ?? ?? ??") -> insn("read size=4 disp_addr(d)", within=12) -> capture("d") -> read(4)').run(img)
    assert [v.value for v in literal.values] == [0x168]


def test_insn_builder_emits_the_window_form():
    built = v1.PipelineBuilder().bytes("C3").insn("read size=4 disp(d)", within=12)
    assert built.source == 'bytes("C3") -> insn("read size=4 disp(d)", within=12)'


def _single(code, boundaries, spec='read size=4 disp(d)', **kwargs):
    data = bytes.fromhex(code)
    image = v1.Image(data, functions=[Function(0, [(0, len(data))])], instructions=boundaries)
    return v1.Pipeline(f'bytes("C3") -> insn("{spec}") -> capture("d")').run(image)


def test_insn_preserves_signed_and_zero_displacements():
    r = _single('8B 41 F8 C3', [(0, 3), (3, 4)])
    assert r.values[0] == v1.CaptureValue(-8, 'DisplacementValue', 'scalar')
    r = _single('8B 01 C3', [(0, 2), (2, 3)])
    assert r.values[0].value == 0
    assert not _single('8B 01 C3', [(0, 2), (2, 3)], 'read disp_addr(d)').values


def test_insn_field_defaults_exclude_stack_index_and_hidden_memory():
    assert not _single('8B 44 24 20 C3', [(0, 4), (4, 5)]).values
    assert not _single('8B 44 88 10 C3', [(0, 4), (4, 5)]).values
    assert _single('8B 44 24 20 C3', [(0, 4), (4, 5)], 'read size=4 base=stack disp(d)').values[0].value == 32
    assert _single('8B 44 88 10 C3', [(0, 4), (4, 5)], 'read size=4 index=any disp(d)').values[0].value == 16
    assert not _single('50 C3', [(0, 1), (1, 2)], 'write disp(d)').values
    # PUSH writes [rsp] after updating rsp; that implicit operand has zero displacement.
    assert _single('50 C3', [(0, 1), (1, 2)], 'write base=stack operand=any disp(d)').values[0].value == 0


def test_insn_filters_register_operand_and_mnemonic():
    code = '8B 41 20 C3'
    boundaries = [(0, 3), (3, 4)]
    assert _single(code, boundaries, 'read base=rcx operand=1 mnemonic=mov disp(d)').values[0].value == 32
    for spec in ('read base=rdx disp(d)', 'read operand=0 disp(d)', 'read mnemonic=add disp(d)'):
        assert not _single(code, boundaries, spec).values


def test_insn_conditional_writes_count_as_writes():
    # cmpxchg [rcx+0x20], eax conditionally writes memory.
    assert _single('0F B1 41 20 C3', [(0, 4), (4, 5)], 'write size=4 disp(d)').values[0].value == 32


def test_insn_requires_boundaries_and_never_decodes_inside_an_immediate():
    data = bytes.fromhex('48 B8 8B 41 20 00 00 00 00 00 C3')
    image = v1.Image(data, functions=[Function(0, [(0, 11)])], instructions=[(0, 10), (10, 11)])
    q = v1.Pipeline('bytes("8B 41 20") -> insn("read disp(d)", within=0)')
    with pytest.raises(v1.ExecutionError, match='boundary'):
        q.run(image)
    bare = v1.Image(data, functions=[Function(0, [(0, 11)])])
    with pytest.raises(v1.ExecutionError, match='instruction metadata'):
        q.run(bare)
    assert not v1.Pipeline('bytes("C3") -> insn("read disp(d)")').run(image).matches


def test_insn_linear_decode_is_explicit_and_stops_on_failure():
    data = bytes.fromhex('06 8B 41 20 C3')
    image = v1.Image(data, functions=[Function(0, [(0, 5)])])
    assert not v1.Pipeline('bytes("C3") -> insn("read disp(d)", decode="linear")').run(image).matches
    q = v1.PipelineBuilder().bytes('8B 41 20').insn('read disp(d)', within=0, decode='linear').build()
    assert q.run(image).matches[0].offset == 1


def test_insn_rejects_wrong_and_overlapping_instruction_metadata():
    for boundaries in ([(0, 2), (2, 4)], [(0, 3), (1, 4)]):
        with pytest.raises(v1.ExecutionError):
            _single('8B 41 20 C3', boundaries)


@pytest.mark.parametrize('spec', [
    'read size=16 size=4 disp(d)', 'lea size=32 disp(d)',
    'read @(d)', 'read cursor disp(d)', 'read disp(1bad)',
    'read base=unknown disp(d)', 'read index=unknown disp(d)',
    'read operand=unknown disp(d)', 'read mnemonic=unknown disp(d)',
    'read base=rcx base=rdx disp(d)', 'read disp(d) disp_addr(a)', 'access=read disp(d)',
])
def test_insn_rejects_ambiguous_or_invalid_specs(spec):
    with pytest.raises(v1.CompileError):
        v1.Pipeline(f'bytes("C3") -> insn("{spec}")')


def test_insn_uniqueness_can_assert_sites_or_distinct_displacements():
    data = bytes.fromhex('8B 41 20 8B 51 20 C3')
    image = v1.Image(data, functions=[Function(0, [(0, 7)])], instructions=[(0, 3), (3, 6), (6, 7)])
    prefix = 'bytes("C3") -> insn("read disp(d)")'
    with pytest.raises(v1.CardinalityError):
        v1.Pipeline(prefix + ' -> unique').run(image)
    assert v1.Pipeline(prefix + ' -> capture("d") -> unique').run(image).values[0].value == 32


def test_insn_keeps_all_memory_operands_and_explicit_operand_selection():
    image = v1.Image(bytes.fromhex('A4 C3'), functions=[Function(0, [(0, 2)])], instructions=[(0, 1), (1, 2)])
    result = v1.Pipeline('bytes("C3") -> insn("mem operand=any disp(d)")').run(image)
    assert len(result.matches) == 2  # MOVSB has both destination and source memory.
    result = v1.Pipeline('bytes("C3") -> insn("read operand=1 disp(d)")').run(image)
    assert len(result.matches) == 1


def test_insn_supports_avx512_width_and_decodes_compressed_displacement():
    # vmovups zmm0, [rcx+64]: encoded disp8=1, semantic displacement=64.
    result = _single('62 F1 7C 48 10 41 01 C3', [(0, 7), (7, 8)], 'read size=64 disp(d)')
    assert result.values[0].value == 64
    addr = _single('62 F1 7C 48 10 41 01 C3', [(0, 7), (7, 8)], 'read size=64 disp_addr(d)')
    assert addr.values[0].value == 6


def test_insn_windows_stop_at_function_spans_and_deduplicate_overlaps():
    code = bytes.fromhex('8B 41 10 90 8B 41 20 90 8B 41 30 C3')
    image = v1.Image(code, functions=[Function(0, [(0, 3), (8, 12)])],
                    instructions=[(0, 3), (4, 7), (8, 11), (11, 12)])
    result = v1.Pipeline('bytes("C3") -> insn("read disp(d)")').run(image)
    assert [m.offset for m in result.matches] == [0, 8]
    result = v1.Pipeline('bytes("8B 41 10") -> insn("read disp(d)", within=100)').run(image)
    assert [m.offset for m in result.matches] == [0]
    image = v1.Image(code, instructions=[(0, 3), (4, 7), (8, 11), (11, 12)])
    result = v1.Pipeline('bytes("8B 41 ??") -> insn("read disp(d)", within=100)').run(image)
    assert [m.offset for m in result.matches] == [0, 4, 8]


@pytest.mark.parametrize('suffix', [', decode="bogus"', ', decode="linear", decode="metadata"',
                                     ', within=1, within=2', ', within=-1'])
def test_insn_rejects_invalid_or_repeated_options(suffix):
    with pytest.raises(v1.CompileError):
        v1.Pipeline('bytes("C3") -> insn("read disp(d)"' + suffix + ')')


def test_insn_cli_preserves_signed_values_and_requires_boundaries(tmp_path, cli_executable):
    import subprocess
    image = tmp_path / 'field.bin'
    image.write_bytes(bytes.fromhex('8B 41 F8 C3'))
    manifest = tmp_path / 'ranges.txt'
    manifest.write_text('size 4\nfunction 0 0 4\ninstruction 0 3\ninstruction 3 4\n')
    query = 'bytes("C3") -> insn("read size=4 disp(field)") -> capture("field") -> unique'
    command = [cli_executable('mamlpipe'), str(image), '--ranges', str(manifest), query, '--trace']
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '-8:DisplacementValue:scalar' in result.stdout
    assert 'insn 1 -> 1' in result.stderr
    manifest.write_text('size 4\nfunction 0 0 4\n')
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0
    assert 'instruction metadata' in result.stdout


def test_signed_projection_orders_values_consistently_with_python_projection():
    data = bytes.fromhex('8B 41 F8 8B 01 8B 41 20 C3')
    image = v1.Image(data, functions=[Function(0, [(0, 9)])],
                    instructions=[(0, 3), (3, 5), (5, 8), (8, 9)])
    matches = v1.Pipeline('bytes("C3") -> insn("read disp(d)")').run(image)
    projected = v1.Pipeline('bytes("C3") -> insn("read disp(d)") -> capture("d")').run(image)
    assert list(projected.values) == v1.project(matches.schema, matches.matches, 'd')
    assert [v.value for v in projected.values] == [-8, 0, 32]


def test_insn_checks_instruction_ownership_even_when_anchor_is_outside_functions():
    image = v1.Image(bytes.fromhex('90 8B 41 20 C3'),
                    functions=[Function(1, [(1, 3)])], instructions=[(0, 1), (1, 4), (4, 5)])
    query = v1.Pipeline('bytes("90") -> insn("read disp(d)", within=4)')
    with pytest.raises(v1.ExecutionError, match='span boundary'):
        query.run(image)
    # An instruction beginning in uncovered bytes cannot extend into a function.
    image = v1.Image(bytes.fromhex('8B 41 20 C3'),
                    functions=[Function(1, [(1, 4)])], instructions=[(0, 3), (3, 4)])
    with pytest.raises(v1.ExecutionError, match='span boundary'):
        v1.Pipeline('bytes("8B") -> insn("read disp(d)", within=4)').run(image)
