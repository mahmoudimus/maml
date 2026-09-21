# Design: absolute-pointer table traversal

Status: implemented in the working tree; validation is recorded in
[build validation](build-validation.md). The objective is
to locate callbacks stored beside name pointers using composable pipeline
operations. This is separate from code-reference discovery and from renaming
through an analysis adapter.

## Example and address model

```text
str("PitchUpStart")
    -> ptrrefs
    -> unique
    -> offset(8)
    -> read_ptr
    -> func:strict
    -> unique
```

For a record `{const char* name; void* callback;}`, `ptrrefs` yields the storage
address of the name pointer. The callback is in the adjacent slot; a second
`xrefs` does not express that relationship. This proposal leaves `xrefs` and
`callers` unchanged and introduces no registration-specific syntax.

Image metadata uses buffer-relative offsets. Pipeline address values use
logical addresses, including `image.base`. Raw absolute pointer values are a
separate domain. With base `0x140000000`, string offset `0x100`, record offset
`0x200`, callback offset `0x300`, and these bytes:

```text
[0x200] = uint64_le(0x140000100)
[0x208] = uint64_le(0x140000300)
```

the result is logical address `0x140000300`. Its RVA is `0x300`. Supply mappings
`0x140000100 -> 0x140000100` and `0x140000300 -> 0x140000300` explicitly for this
synthetic image. For an image with logical base zero, the same raw values map to
`0x100` and `0x300` instead.

## Stages

### `ptrrefs`

Accept logical image-address values, rejecting scalars and unmapped absolute
pointer captures. Search the union of explicit `data` and `rodata` scan ranges,
excluding code coverage. Missing eligible metadata is `MissingMetadata`, not a
successful empty lookup. Empty input with valid metadata yields empty output.

Examine every byte-aligned position with eight readable bytes wholly inside an
eligible range. No implicit eight-byte alignment assumption is permitted.
Normalize overlapping ranges and visit each position once. Decode little-endian
uint64, map it through the active pointer mapper, and compare its logical
address to the input target set. Return matching storage addresses as
`CursorAddress` values in image space, sorted and deduplicated. Distinct slots
remain distinct even if they store the same pointer.

Unmapped or out-of-image destinations are skipped and counted in trace
statistics. Never truncate to 32 bits, subtract a guessed base, or accept a raw
value merely because it fits inside the buffer. Scan once for the target set,
not once per target. No match is normal empty output.

### `offset(N)`

`N` is a signed decimal int64 literal, including negative values. Out-of-range
literals are compile errors. Accept logical image-address values and preserve
each value's kind and address space while applying checked signed addition.
Reject other value types. Match records must first be projected to addresses;
this stage does not silently discard their capture schemas.

Underflow, overflow, and results outside the image are execution errors; do not
silently drop an invalid record and let a later `unique` pass on the survivors.
One-past-end is outside the image. Sort and deduplicate resulting values.

### `read_ptr`

Accept logical image-address values. Read eight bytes little-endian at each
address and map the full uint64 through the same mapper used by `ptrrefs` and
`ptr64(...):follow`. Return `MappedPointerAddress` values in image space so
`func`, `callers`, `find`, and subsequent address stages can consume them.

A truncated read, missing mapping, or mapped destination outside the image is
an execution error. Return no successful partial result. This deliberately
fails more strictly than scanning arbitrary bytes in `ptrrefs`: these slots
were explicitly selected for dereference. Sort and deduplicate outputs;
multiple selected records may resolve to one callback. Use `unique` before
`read_ptr` when record identity must be unique.

Terminal `read(8)` remains a scalar read. `ptr64(name)` remains a raw absolute
capture. Neither acquires implicit mapping behavior.

## Metadata and integration

Add explicit non-code `data` scan ranges alongside existing `rodata` metadata
in C++, Python, and the Cython bridge. Writable data must not be added to
`rodata`: doing so would also change string discovery and generation. Validate
bounds, normalize overlapping scan ranges, and exclude executable coverage.
A flat buffer's padding is not evidence of a mapped data section.

The existing pointer map is authoritative: absence of an entry means unmapped.
Factor its lookup and destination validation into a shared helper without
changing `ptr64(...):follow` semantics. Custom mappings override any mappings
constructed by a loader. Invalid explicit destinations are errors, not a
reason to fall back to another mapping.

The PE loader must supply data ranges and mappings from stored absolute VAs to
logical addresses. For disk images, derive the source address space from the
PE preferred image base and mapped section extents. For relocated memory
images, require the actual loaded base from the caller. Never guess between
preferred and loaded bases. Only destinations in mapped sections are eligible.
Construct mappings for candidate slots in eligible data ranges; document this
scope rather than implying every arbitrary raw value has a mapping.

Expose loader output through a named metadata result instead of adding another
positional item to `flatten_pe`'s five-item tuple. This is an explicit loader
API migration: update all repository consumers, document field names, and
rebuild native bindings. The result contains bytes, sections, code, rodata,
data, functions, logical base, source image base, and pointer mappings.

Both typed builders gain `.ptrrefs()`, `.offset(N)`, and `.read_ptr()` with the
same grammar and validation as text. CLI manifests gain decimal `data BEGIN
END`, `base N`, and `pointer RAW LOGICAL` records. Missing `base` retains zero.
Conflicting duplicate mappings or base records are errors. The durability
flattener emits this metadata so the CLI can reproduce loader behavior.

Trace retains existing stage/input/output counts and adds optional structured
statistics for pointer traversal: normalized searched ranges (buffer offsets),
candidate slots inspected, mapped slots, unmapped slots, invalid destinations,
and output count. A candidate means a complete eight-byte scan position, not
an aligned or already matching pointer. Expose the same statistics through C++,
Python/Cython, and `mamlpipe --trace`. Execution errors identify the stage and
input address; do not print a normal empty-result trace as success.

## Acceptance

Synthetic regressions must cover:

- The example above at zero and nonzero logical bases, explicit custom mapping,
  and raw pointer values above 4 GiB.
- Multiple distinct records retained by `ptrrefs`; `unique` rejects them before
  dereference, even when callbacks are equal.
- Writable data, rodata, unaligned slots, overlapping ranges, excluded code,
  section boundaries, truncated slots, and empty/missing metadata.
- Unmapped pointers never becoming addresses; selected unreadable or unmapped
  slots causing `read_ptr` errors; mapper destinations outside the image.
- Positive, zero, negative, int64-minimum, overflowing, and out-of-image offsets;
  invalid literals and scalar inputs rejected.
- `func:strict` accepting callback entries and rejecting interior addresses,
  including callbacks with noncontiguous owned spans.
- Text/builders, C++/Python/Cython, CLI execution, and trace statistics agreeing.
  Existing `xrefs`, `callers`, and matcher conformance vectors remain unchanged;
  extend the conformance protocol with pointer/data metadata for new cases.

Real-image acceptance targets for WowB 1.60.1.69893 (verified against the
devirtualized PE; see build validation for identity and results):

| String | Record RVA | Callback RVA |
| --- | ---: | ---: |
| `PitchUpStart` | `0x5727720` | `0x2232530` |
| `PitchUpStop` | `0x5727730` | `0x22328D0` |
| `PitchDownStart` | `0x5727740` | `0x2232C60` |
| `PitchDownStop` | `0x5727750` | `0x2233000` |

Record the exact binary path, hash, preferred/loaded base, mapping policy, and
per-stage results. Compare final results after converting logical addresses to
RVAs. A fixture passing is not evidence that this specific binary passes.

## Scope choices

Explicit traversal is preferred over broadening `xrefs`, which would change
existing selection/cardinality behavior, or adding a registration-only stage,
which would bake one table layout into the language. The Python image field is named `data_ranges` to distinguish it from the byte
buffer `data`. The named loader result is `PEImage`, with `source_base` for the
source image base. C++ execution accepts data ranges after `instructions`, as the sixth argument
including the image.

Initial scope is 64-bit
little-endian pointers. Pointer-size options, automatic table discovery,
argument-flow analysis, namespaces, and renaming actions remain separate work.
