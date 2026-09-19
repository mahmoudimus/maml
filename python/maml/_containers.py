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
    """Primary function ranges with contiguous resolved chained coverage.

    Extracted so it is testable without building a PE: every defect found here
    -- the name-based filter, the missing chain resolution -- needed a specific
    binary shape to show, and a test that cannot construct one cannot pin it.

    `raw` is the .pdata bytes, an array of 12-byte RUNTIME_FUNCTION records
    (`<III` = begin RVA, end RVA, unwind-info RVA). `code` is the executable
    ranges; `buf` is the whole RVA-indexed image, needed to read unwind info.
    """
    import bisect
    import struct
    records = set()
    for off in range(0, len(raw) - 11, 12):
        record = struct.unpack_from("<III", raw, off)
        begin, end, _ = record
        if (0 <= begin < end <= len(buf)
                and any(c.begin <= begin < c.end for c in code)):
            records.add(record)

    # Win64 UNWIND_INFO stores CountOfCodes two-byte slots after its four-byte
    # header. Round the slot count up to an even number before reading the
    # embedded RUNTIME_FUNCTION. It may itself point to another chained record.
    parents = {}
    roots = set()
    for record in records:
        begin, end, unwind = record
        flags = buf[unwind] >> 3 if unwind < len(buf) else 0
        if not flags & UNW_FLAG_CHAININFO:
            roots.add(record)
            continue
        parents[record] = None
        if (unwind + 4 > len(buf) or (buf[unwind] & 7) not in (1, 2)
                or flags & ~UNW_FLAG_CHAININFO):
            continue
        tail = unwind + 4 + 2 * ((buf[unwind + 2] + 1) & ~1)
        if tail + 12 > len(buf):
            continue
        parent = struct.unpack_from("<III", buf, tail)
        # Only attach coverage to an actual table record. Invalid links never
        # turn fragments into independent function starts.
        if parent in records and any(c.begin <= begin < end <= c.end for c in code):
            parents[record] = parent

    resolved = {root: root for root in roots}
    for record in records:
        path, seen = [], set()
        current = record
        while current is not None and current not in resolved and current not in seen:
            seen.add(current)
            path.append(current)
            current = parents.get(current)
        root = resolved.get(current)
        for item in path:
            resolved[item] = root

    spans = {root: [] for root in roots}
    for record, root in resolved.items():
        if root is not None:
            spans[root].append(record[:2])

    # Existing consumers accept one contiguous range per function. Coalesce
    # only connected coverage after the real entry, never a bounding box over
    # a gap or an interval owned by another primary function.
    ordered_roots = sorted(roots)
    starts = [r[0] for r in ordered_roots]
    max_ends = []
    for _, end, _ in ordered_roots:
        max_ends.append(max(end, max_ends[-1] if max_ends else 0))
    out = []
    for root in ordered_roots:
        begin, end, _ = root
        for lo, hi in sorted(spans[root]):
            if lo < begin or lo > end or hi <= end:
                continue
            index = bisect.bisect_left(starts, hi) - 1
            if index >= 0 and max_ends[index] > end:
                # Includes another root whose original coverage intersects
                # the proposed extension; fail closed on conflicting ownership.
                continue
            end = hi
        out.append(Range(begin=begin, end=end, name="", executable=True))
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
    filtered to executable ranges. Valid contiguous chained spans extend their
    primary entry's coverage; disconnected spans are not yet representable.
    This is unwind-derived coverage, not a complete function list. `.pdata` is x64-specific
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
