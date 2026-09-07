"""Container parsing, deliberately outside the C++.

DESIGN_generate.md: maml "has deliberately never parsed a container format
-- it takes a span." So PE/ELF knowledge lives here, behind the maml[pe]
extra, and the core install has no dependencies.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Range:
    begin: int
    end: int
    name: str = ""
    executable: bool = False


UNW_FLAG_CHAININFO = 0x4


def funcs_from_pdata(raw, code, buf):
    """Function starts from a raw .pdata blob.

    Extracted so it is testable without building a PE: every defect found here
    -- the name-based filter, the missing chain resolution -- needed a specific
    binary shape to show, and a test that cannot construct one cannot pin it.

    `raw` is the .pdata bytes, an array of 12-byte RUNTIME_FUNCTION records
    (`<III` = begin RVA, end RVA, unwind-info RVA). `code` is the executable
    ranges; `buf` is the whole RVA-indexed image, needed to read unwind info.
    """
    import struct
    out = []
    n = (len(raw) // 12) * 12          # whole records only
    for off in range(0, n, 12):
        begin, fend, unwind = struct.unpack_from("<III", raw, off)
        if begin == 0 and fend == 0:
            continue
        # Inside any EXECUTABLE range, not inside a section literally named
        # ".text". Keying on the name meant a PE whose executable section is
        # called something else disabled the filter entirely -- a record
        # pointing outside every section was accepted -- while a PE with .text
        # plus a second executable section silently dropped every function in
        # the second one.
        if not any(c.begin <= begin < c.end for c in code):
            continue
        if fend <= begin or fend > len(buf):
            continue
        # CHAIN RESOLUTION. generate.hpp states this as a precondition in bold:
        # UNW_FLAG_CHAININFO fragments are NOT function starts, "a trap this
        # project walked into four separate times". A hot/cold-split function
        # has several .pdata records and only one is the entry; admitting the
        # fragments makes enclosing_func() report a fragment as the function,
        # so StringAnchor's depth-0 test fails whenever a lea and its target
        # land in different fragments of one real function, and clamp_to_func
        # truncates tails at fragment boundaries. Silently weaker patterns, on
        # exactly the optimised MSVC binaries this tool exists for.
        #
        # UNWIND_INFO byte 0 is Version:3 | Flags:5. The parent's own record is
        # already in this table, so dropping the fragment loses nothing.
        if unwind < len(buf) and ((buf[unwind] >> 3) & UNW_FLAG_CHAININFO):
            continue
        out.append(Range(begin=begin, end=fend, name="", executable=True))
    return out


def flatten_pe(path):
    """(flat RVA-indexed bytes, [Range] sections, [Range] code, [Range] rodata,
    [Range] funcs) for a PE on disk.

    Each section is copied to its virtual address, so an RVA indexes the buffer
    directly -- the same shape the C++ and the offline tooling expect.

    `code` holds every executable section; `rodata` every initialised,
    non-executable data section (maml.generate's Options.deep_anchor and
    string-anchor scanning key on these, not on `sections`).

    `funcs` comes from `.pdata` when the PE has one: an array of 12-byte
    RUNTIME_FUNCTION records (`<III` = begin RVA, end RVA, unwind-info RVA),
    filtered to entries whose begin address falls inside `.text` -- that gives
    a complete function list with no symbols needed. `.pdata` is x64-specific
    (table-based SEH) and PE32 images do not have one; `funcs` is left empty
    when it is absent, which is a documented no-op for maml.generate, not
    a failure.
    """
    try:
        import lief
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError(
            "Image.from_pe needs the optional extra: pip install 'maml[pe]'"
        ) from exc

    binary = lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError("not a PE image: %s" % path)

    end = max((s.virtual_address + max(s.virtual_size, len(s.content))
               for s in binary.sections), default=0)
    buf = bytearray(end)
    ranges = []
    code = []
    rodata = []
    pdata_range = None
    for s in binary.sections:
        content = bytes(s.content)
        va = s.virtual_address
        buf[va:va + len(content)] = content
        r_end = va + max(s.virtual_size, len(content))
        executable = s.has_characteristic(
            lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        r = Range(begin=va, end=r_end, name=s.name, executable=executable)
        ranges.append(r)

        writable = s.has_characteristic(
            lief.PE.Section.CHARACTERISTICS.MEM_WRITE)
        if executable:
            code.append(r)
        elif (s.has_characteristic(
                lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA)
              and not writable and s.name not in (".pdata", ".rsrc", ".reloc")):
            # Read-only initialised data only. Taking every non-executable
            # initialised section swept in `.data` (writable, so its contents
            # move), `.pdata` (the function table itself) and `.rsrc` (version
            # resources, which change every single build) -- all of it becoming
            # StringAnchor substrate. verified() filters most of the damage,
            # but candidates() was quietly polluted, which is worse: it is the
            # surface a caller inspects when verified() returns nothing.
            rodata.append(r)

        if s.name == ".pdata":
            pdata_range = (va, r_end)

    funcs = []
    if pdata_range is not None:
        pstart, pend = pdata_range
        funcs = funcs_from_pdata(bytes(buf[pstart:pend]), code, buf)

    return bytes(buf), ranges, code, rodata, funcs
