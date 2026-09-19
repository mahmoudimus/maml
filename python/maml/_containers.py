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


@dataclass(frozen=True)
class Function:
    """One buffer-relative entry with disjoint, half-open coverage spans."""
    entry: int
    spans: tuple

    def __post_init__(self):
        def address(v):
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 0xffffffffffffffff:
                raise ValueError("Function addresses must be unsigned 64-bit integers")
            return v
        address(self.entry)
        ranges = []
        for item in self.spans:
            lo, hi = (item.begin, item.end) if hasattr(item, 'begin') else item
            address(lo)
            address(hi)
            if lo >= hi:
                raise ValueError("Function spans must be nonempty")
            ranges.append((lo, hi))
        merged = []
        for lo, hi in sorted(ranges):
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
            else:
                merged.append((lo, hi))
        if not any(lo <= self.entry < hi for lo, hi in merged):
            raise ValueError("Function entry must be covered by its spans")
        object.__setattr__(self, 'spans', tuple(merged))


def validate_functions(functions, size):
    """Snapshot function ownership; reject ambiguous cross-function coverage."""
    functions = tuple(functions)
    if any(not isinstance(f, Function) for f in functions):
        raise TypeError("functions must contain Function(entry, spans) records")
    functions = tuple(sorted(functions, key=lambda f: f.entry))
    if len({f.entry for f in functions}) != len(functions):
        raise ValueError("Duplicate function entries")
    intervals = sorted((lo, hi, f.entry) for f in functions for lo, hi in f.spans)
    end = 0
    for lo, hi, entry in intervals:
        if lo < end:
            raise ValueError("Conflicting function span ownership")
        if hi > size:
            raise ValueError("Function span outside image")
        end = hi
    return functions


UNW_FLAG_CHAININFO = 0x4


def _resolved_pdata(raw, code, buf):
    """Resolve primary ownership of validated .pdata records.

    Extracted so it is testable without building a PE: every defect found here
    -- the name-based filter, the missing chain resolution -- needed a specific
    binary shape to show, and a test that cannot construct one cannot pin it.

    `raw` is the .pdata bytes, an array of 12-byte RUNTIME_FUNCTION records
    (`<III` = begin RVA, end RVA, unwind-info RVA). `code` is the executable
    ranges; `buf` is the whole RVA-indexed image, needed to read unwind info.
    """
    import struct
    records = set()
    for off in range(0, len(raw) - 11, 12):
        record = struct.unpack_from("<III", raw, off)
        begin, end, _ = record
        if (0 <= begin < end <= len(buf)
                and any(c.begin <= begin < end <= c.end for c in code)):
            records.add(record)

    # Win64 UNWIND_INFO stores CountOfCodes two-byte slots after its four-byte
    # header. Round the slot count up to an even number before reading the
    # embedded RUNTIME_FUNCTION. It may itself point to another chained record.
    parents = {}
    roots = set()
    for record in records:
        begin, end, unwind = record
        # An unreadable or malformed header is unknown ownership, never a root.
        if unwind + 4 > len(buf) or (buf[unwind] & 7) not in (1, 2):
            continue
        flags = buf[unwind] >> 3
        if flags & ~0x7:
            continue
        tail = unwind + 4 + 2 * ((buf[unwind + 2] + 1) & ~1)
        if tail > len(buf):
            continue
        if not flags & UNW_FLAG_CHAININFO:
            if flags & 0x3 and tail + 4 > len(buf):
                continue
            roots.add(record)
            continue
        parents[record] = None
        if flags & ~UNW_FLAG_CHAININFO or tail + 12 > len(buf):
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

    return roots, spans


def functions_from_pdata(raw, code, buf):
    """Resolve full chained coverage, retaining one entry per primary function."""
    roots, spans = _resolved_pdata(raw, code, buf)
    by_entry = {}
    for root in roots:
        by_entry.setdefault(root[0], []).extend(spans[root])
    return list(validate_functions([Function(entry, coverage)
                for entry, coverage in by_entry.items()], len(buf)))


def flatten_pe(path):
    """Return (RVA-indexed bytes, sections, code, rodata, functions).

    Functions contain one primary entry and all resolved coverage spans.
    Missing .pdata yields no function metadata; leaf functions may be absent.
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

    functions = []
    if pdata_range is not None:
        pstart, pend = pdata_range
        functions = functions_from_pdata(bytes(buf[pstart:pend]), code, buf)
    return bytes(buf), ranges, code, rodata, functions
