# MAML

MAML stands for **Mahmoud’s Address Matching Language**, a byte-oriented binary
matching language.
Patterns describe bytes, gaps, captures, and references. Pipelines transform
matches and address sets. Cursor-machine mechanics stay below compilation.

**Status:** the C++ engine, generator, Cython bindings, and Python APIs are
available. The agreed MAML v1 semantic contracts are frozen;
the introductory examples describe the new dialect, which is not implemented
yet. The current runtime syntax and runnable examples are documented separately.

```text
E8 rel32(callee) [3..5] 4C 8B D0 48 85 C0 74 ??
```

This captures the call's resolved target and continues after its displacement.
Following the reference is explicit:

```text
E8 rel32(callee):follow 48 89 5C 24 ??
```

Pipeline composition uses `->`:

```text
str("GetActivePlayerObj")
    -> xrefs
    -> func
    -> find("E8 rel32(init) [3..5] 48 85 C0")
    -> capture("init")
    -> unique
```

See [build validation](docs/build-validation.md) for the current verification
results. Passing the current tests does not establish v1 conformance.

The language remains byte-oriented. Instruction-aware constructs such as
`call(callee)` and `mov(...)` are outside v1.

## Contents

- [Current pattern language](#current-runtime-language)
- [Current locator pipelines](#current-locator-pipelines)
- [Scanning APIs and CLI](#current-scanning-apis-and-mamlscan)
- [Pattern generation and resolution](#generating-and-resolving-patterns)
- [Normative v1 semantics](#maml-v1-semantics)
- [Build and run](#build-and-run)
- [Project layout and validation](#project-layout-and-validation)

## Current runtime language

The installed `Pattern`, scanner, generator, and pipeline APIs currently use
this grammar. The [v1 contract](#maml-v1-semantics) below describes the replacement
frontend; its function-call spellings and named captures are not accepted yet.

| Syntax | Current behavior |
| --- | --- |
| `48 8B C4` | Literal bytes |
| `?` | One wildcard byte; `??` currently means two bytes |
| `FFEE & F0F0` | A byte sequence matched under a same-length mask |
| `[4]` | Skip exactly four bytes |
| `[3-5]` | Skip three through five bytes |
| `(8B \| 89)` | Alternation |
| `'` | Save the current cursor in the next positional capture slot |
| `$` | Follow a signed rel32 at the cursor |
| `%` | Follow a signed rel8 at the cursor |
| `*` | Follow a 64-bit absolute pointer through the match target's address mapping |
| `$ { ... }` | Follow a reference, execute the block, then resume after the operand; also supported with `%` and `*` |
| `r1`, `r2`, `r4` | Read and save a little-endian value, consuming 1, 2, or 4 bytes |
| `// ...`, `/* ... */` | Comments; put whitespace before `//` |

For example:

```text
E8 $ { ' } [3-5] 4C 8B D0 48 85 C0 74 ?
```

This matches a call, captures the resolved target, resumes after its four-byte
operand, skips three to five bytes, and matches the tail. Save slot zero is the
match offset; slot one is the first explicit capture. Current core capture
storage is 32-bit; the full-width typed captures in v1 are a separate requirement.

A rel32 is resolved from the end of its operand, not automatically from the end
of an x86 instruction. If a RIP-relative displacement precedes a trailing
immediate, adjust the captured cursor inside the block:

```text
48 69 15 $ { [4] ' } 98 00 00 00
```

The four-byte adjustment accounts for the immediate after the displacement.
Use one byte for a trailing imm8. Omitting it can produce a unique match with a
wrong target. In v1 this becomes an explicit `target_add` parameter.

## Current locator pipelines

A pipeline starts with `str` or `bytes`, then transforms a set of addresses.
Both source stages are restricted to the first position. Every completed stage
sorts and deduplicates its output; positional selection is ascending address
order, not discovery order.

```text
str "GetActivePlayerObj" -> xref -> func -> unique
bytes "48 89 5C 24 08 57" -> func -> callers -> nth 0
```

| Stage | Input / requirement | Output |
| --- | --- | --- |
| `str "text"` | Source; requires rodata ranges | Starts of matching NUL-terminated strings in the derived string table |
| `bytes "pattern"` | Source | Pattern match offsets across the entire image |
| `find "pattern"` | Addresses; requires function ranges | Matches within each enclosing function, or the first capture when the pattern contains `'` |
| `xref` | Addresses covered by code or rodata ranges; requires code ranges | Call sites for code targets, or indexed RIP-relative reference sites for rodata targets |
| `callers` | Target addresses; requires code ranges | Direct call sites targeting those addresses |
| `func` | Addresses; requires function ranges | Enclosing function entries; addresses outside known functions are dropped |
| `func:loose` | Same as `func` | Explicit spelling of the default behavior |
| `func:strict` | Same as `func` | Enclosing entries, but fails if any resulting entry was not already in the input set |
| `unique` | Address set | Same set if its size is exactly one; otherwise an error |
| `nth K` | Address set | Zero-based K-th address; out-of-range selection yields an empty result |
| `limit N` | Address set | First N addresses in ascending order |
| `read N` | Addresses; N is 1, 2, 4, or 8 | Little-endian values loaded at those addresses; must be the last stage |

Separate stages with `->`. Strings use double quotes and support `\"`, `\\`,
`\n`, `\t`, and `\xHH`. `strict` and `loose` attach to `func` without spaces around
`:`, and are rejected on other stages. Numeric stage arguments are non-negative
decimal integers.

`str` matches a whole string exactly, not a substring. The current string table
contains maximal printable ASCII runs (`0x20` through `0x7E`) of at least six
bytes, with a NUL terminator inside a rodata range. Short strings, UTF-16
strings, and unterminated runs are not indexed.

`bytes` searches the whole image. `find` searches each enclosing function once,
so a short pattern can be useful within that scope even when it repeats elsewhere.
Currently the function's byte subspan is the matching target too; following a
reference outside it does not get access to the whole image. Also, adding `'`
to a `find` pattern changes its output to the first capture. These current
constraints must not be confused with v1's explicit match-record projection.

`xref` is an indexed byte-analysis operation, not a complete disassembler xref
query. On a code target it uses the call graph, so a `lea` taking a function's
address is not found through that route. A target in neither code nor rodata
is an error rather than an assumed data reference.

`func` locates an enclosing entry; it does not prove that its input was already
an entry. Use `func:strict` to assert that property, and inspect `trace.moved`.
After `xref` or `callers`, moving from a reference site to its containing entry
is normally intended, so plain `func` is the appropriate operation. The strict
check compares sets; it is not a per-input proof when inputs already contain
an enclosing entry alongside a mid-function address.

### Reading values and understanding results

```text
bytes "F7 80" -> func -> find "F7 80 ' ? ? 00 00" -> read 4
```

This captures the field immediately after `F7 80` and reads its four-byte value.
`read` drops out-of-bounds reads instead of truncating them. Values are sorted
and deduplicated too, so multiple addresses containing the same number yield
one result. No stage, including `unique`, may follow `read` in the current parser.

| Result field | Meaning |
| --- | --- |
| `ok` | At least one result remains and no stage failed |
| `error` | Nonempty for parse errors, missing metadata, failed assertions, or execution errors |
| `failed_stage` | Zero-based stage index; `None` in Python or `SIZE_MAX` in C++ when no stage failed |
| `kind` | Python `"address"` / `"value"`; C++ `ResultKind::Address` / `Value` |
| `addresses` | Result storage, containing values instead when `kind` is `value` |
| `trace` | Stage names, input/output counts, and the number of newly introduced output addresses (`moved`) |

An ordinary miss is `ok == false` with an empty `error`. It is different from
missing function or section metadata. Python also exposes `result.failed` and
`result.values`; accessing `.values` on an address result raises `ValueError`.
Python trace entries use `into` for the C++ field named `in`.

A failed `unique` points back to the start of the current run of stages whose
output count was not one. It need not point at `unique` itself. The trace helps
locate where ambiguity or an empty result first appeared; do not infer the
failed-stage index from trace length. A rejected `func:strict` includes its
movement counts in the trace.

### Pipeline APIs

This Python example is self-contained and works with the current runtime:

```python
from maml import Image, Range, pipeline

img = Image.from_bytes(bytes.fromhex("90 F7 80 58 1C 00 00 90"))
img.code = [Range(0, 8)]
img.funcs = [Range(0, 8)]
r = pipeline.run(img,
    "bytes \"F7 80\" -> func -> find \"F7 80 ' ? ? 00 00\" -> read 4")
assert r.ok and r.kind == "value" and r.values == [0x1C58]
for stage in r.trace:
    print(stage.stage, stage.into, stage.out, stage.moved)
```

For real PE inputs, `Image.from_pe(path)` populates section metadata and available
function ranges. Check errors when those ranges are absent.

In C++, include the pipeline header explicitly:

```cpp
#include <maml/pipeline.hpp>
#include <array>

int main() {
    const std::array<uint8_t, 8> bytes{0x90, 0xF7, 0x80, 0x58, 0x1C, 0, 0, 0x90};
    const std::array<maml::generate::Range, 1> funcs{{{0, 8}}};
    const maml::generate::Image img{bytes, funcs, {}, funcs};
    const auto r = maml::pipeline::run(img,
        "bytes \"F7 80\" -> func -> find \"F7 80 ' ? ? 00 00\" -> read 4");
    return r.ok && r.kind == maml::pipeline::ResultKind::Value &&
           r.addresses == std::vector<uint64_t>{0x1C58} ? 0 : 1;
}
```

For repeated C++ pipelines on the same image, `maml::pipeline::Session` reuses
the derived indexes. Call `preload_string_targets()` before a collection of
string-based jobs to index their references together. Keep the backing bytes
and ranges alive and unchanged for the session.

For the v1 spelling, `str "text"` becomes `str("text")`, `xref` becomes `xrefs`,
and arguments such as `nth 0` become `nth(0)`. The more important change is
`find(...) -> capture("name")`: v1 returns matches first and projects explicitly.
Those spellings describe the design; they are not aliases accepted today.

### mamlpipe CLI and range manifests

```sh
mamlpipe image.bin --ranges ranges.txt 'bytes "48 8B C4" -> unique' --trace
mamlpipe --batch pipelines.tsv --image image.bin --ranges ranges.txt
```

A manifest describes half-open ranges using decimal offsets:

```text
size 4096
code 0 2048
rodata 2048 4096
func 0 128
func 128 256
```

The image must be flat: file offset zero corresponds to image-relative address
zero. These are not section offsets in a raw PE file. Batch pipeline jobs contain
`name<TAB>pipeline`; each job uses the supplied image and manifest.

Single-shot output is space-separated, for example `OK addrs=1 1`, or
`OK vals=1 1c58` after a value read. Address/value numbers are hexadecimal.
Batch output is tab-separated with columns `name`, `status`, `count`, results,
failed stage, detail, trace, and kind (`addr` or `value`). Exit status zero means
all requested pipelines ended with at least one result and no errors.

## Current scanning APIs and mamlscan

Python `Pattern` compiles once without an image. `prime(image)` chooses a seed
for that particular pattern/image pair; reuse the primed object for repeated
searches, but prime separately for each image.

```python
from maml import Image, Pattern

img = Image.from_bytes(bytes.fromhex("90 48 8B C4 90"))
scan = Pattern("48 8B C4").prime(img)
hit = scan.find()
assert hit.offset == 1 and hit.value == 1
assert len(scan.find_all(limit=2)) == 1
```

`find()` returns the first match, not a uniqueness assertion. Use
`find_all(limit=2)` and require exactly one result when uniqueness matters.
Use `save_index=1` to retrieve the first positional capture instead of slot zero.
`Hit.offset` still identifies the match site; `Hit.value` is the selected slot.
`candidates` counts seed candidates examined and `verified` counts candidates
sent to the full matcher after fixed-byte filtering. These are search-work
counters, not proof of a correct target or a performance improvement.

Invalid patterns raise `PatternError` with `kind`, `start`, and `end` identifying
the parser error and source span. C++ exposes `ParseException`; use
`maml::locate::compile`, `prime`, `find`, and `find_all` for reusable scanning.

```sh
mamlscan flat.bin '48 8B C4' --expect 1
mamlscan flat.bin "E8 $ { ' }" --save-index 1 --limit 2
mamlscan --batch scans.tsv
```

`--expect` takes a hexadecimal image-relative address. A scan job file contains:

```text
name<TAB>image-path<TAB>expected-rva-hex<TAB>save-index<TAB>pattern
```

| Status | Meaning | Exit |
| --- | --- | --- |
| `OK` | Exactly one match and, if supplied, it equals `--expect` | 0 |
| `MISS` | One match at a different address than expected | 1 |
| `MULTI` | More than one match | 1 |
| `NONE` | No matches | 1 |
| `ERR` | Invalid pattern or another reported input error | 1 |

Argument/usage errors use exit status 2. The default CLI limit is 32; the scanner
collects up to one extra hit to detect excess matches and displays at most the
limit. Use a positive limit. Single-shot output uses spaces (`OK hits=1 1`); batch output uses tabs. Image paths refer
to flat files, not raw PE sections. Batch scanning loads each distinct image
once. A unique hit alone does not certify function identity.

### Image loading, Python threads, and SIMD

Install the local package with `pip install .`, or `pip install '.[pe]'` for
PE loading through LIEF. `Image.from_file(path)` loads a flat file;
`Image.from_bytes(buffer, base=0)` pins a supplied buffer without copying it.
`Image.base` is metadata; current scan offsets remain relative to the buffer.
`Image.from_pe(path)` lays out sections by RVA, fills code/data ranges, and
derives function ranges from x64 `.pdata` when present. It currently leaves
`base` at zero; set `image.base` explicitly before using `to_va()` if you need
virtual addresses.
The C++ library itself does not parse executable file formats or disassemble.

Scanning, generation, and pipeline execution release the Python GIL. The image
keeps its buffer alive; callers must also keep mutable buffer contents stable
while other threads scan them. GIL release permits concurrent execution but
is not, by itself, a measured scaling claim.

The scanner chooses among provably fixed literal runs using occurrence counts,
then uses fixed-byte filtering before full matching. NEON or SSE2 accelerate
literal scanning when available; a scalar fallback remains functional. Inspect
`maml.simd_backend()` (`neon`, `sse2`, or `scalar`) and use `mamlbench` to measure
the build on the actual host rather than carrying over timing figures.

## Generating and resolving patterns

The generator takes an image plus code, rodata, and optional function ranges.
Ranges are image-relative and half-open. Supplied function ranges must already
represent actual functions rather than unresolved chained unwind fragments.
Without function ranges, generation uses bounded byte windows where supported;
that does not supply function metadata to pipeline `func` or `find` stages.

| Strategy | Anchor |
| --- | --- |
| `Body` | Bytes at or inside the target function |
| `Xref` | A call site, capturing its target |
| `StringAnchor` | A string reference and nearby call/function context |
| `RipRef` | A RIP-relative operand referring to a global |

`generate.candidates(image, target)` emits candidates from one image.
`generate.verified(a, target_a, b, target_b)` keeps candidates that resolve
uniquely to the supplied target in both independent images. Those target
correspondences are caller inputs, not something the generator proves. Returning
fewer candidates than requested, including none, is normal.

```python
from maml import Image, generate

def resolve_next_build(path_a, target_a, path_b, target_b, path_c):
    a = Image.from_pe(path_a)
    b = Image.from_pe(path_b)
    c = Image.from_pe(path_c)
    candidates = generate.verified(a, target_a, b, target_b)
    groups = generate.resolve_consensus(c, candidates)
    if len(groups) == 1 and len(groups[0].anchors) >= 2:
        return groups[0].address
    return None
```

The example uses a conservative agreement policy: two or more supporting
anchors and no competing resolved group. Agreement is useful evidence, not
proof that a later build's address has the intended function identity.

A `Candidate` carries `pattern`, `strategy`, `save_index`, and signed
`anchor_delta`, as well as literal/seed information. For a noncapturing candidate:

```text
target = match_offset - anchor_delta
```

The delta may be negative. For a capturing candidate, resolve using its
`save_index` instead of subtracting a delta. Do not infer the resolution rule
from the strategy alone. `resolve_consensus` handles those rules and groups
successful resolutions by target address.

`Options` defaults are `max_len=64`, `want=4`, `prefer_short=True`, and
`deep_anchor=True`. `prefer_short` trims a trailing literal run; `deep_anchor`
controls the body-anchor search at deeper offsets. The flags are independent.
The C++ API is available through `<maml/generate.hpp>` with the same conceptual
image, candidate, options, verification, and consensus operations.

## MAML v1 semantics

This section is the normative language contract. MUST and MUST NOT state
requirements for implementers. It describes the new frontend, not functionality
already provided by the current engine. The language-neutral
[conformance vectors and adapter protocol](conformance/README.md) exercise these
contracts independently of C++, Cython, or Python.

### Pattern operations

| Syntax | Meaning |
| --- | --- |
| `48 8B C4` | Literal bytes |
| `??` | Exactly one wildcard byte |
| `F?` | One byte with a fixed high nibble |
| `[4]` | Skip exactly four bytes |
| `[3..5]` | Skip three through five bytes, inclusive |
| `(8B \| 89)` | Alternation |
| `@(here)` | Capture the current address without consuming bytes |
| `rel8(name)` | Decode a signed 8-bit relative target and capture it |
| `rel32(name)` | Decode a signed little-endian 32-bit relative target and capture it |
| `ptr64(name)` | Read and capture a little-endian unsigned 64-bit pointer value |
| `:follow` | Continue at the preceding reference's target |

A reference consumes its encoded operand. Without `:follow`, matching continues
immediately after that operand. With `:follow`, matching continues at the target
and MUST NOT implicitly return. Unknown or repeated modifiers and modifiers on
non-reference operations MUST be compile errors. No operation infers an opcode
or decodes a complete instruction.

### References and address spaces

Relative references use the operand's end address as their base. The optional
`target_add` is a signed 64-bit integer, defaults to zero, and changes only the
resolved target:

```text
target = checked_add(
    checked_add(operand_end, signed_displacement),
    target_add
)
```

Each addition, including computing operand end, MUST be checked. Any underflow
or overflow fails that matching path, even if a later adjustment would cancel
it. Arithmetic MUST NOT wrap. A truncated operand also fails the path.

For an instruction with an immediate after its displacement, the adjustment
is explicit:

```text
48 C7 05 rel32(global, target_add=4) 01 00 00 00
```

The matcher still resumes directly after the displacement and matches the
immediate there. `rel32(global, target_add=4):follow` captures the same target
but continues at that target. `target_add` is not a v1 parameter of `ptr64`.

Cursor addresses and relative targets use the active matcher address space.
The address model MUST identify whether that space represents image-relative
addresses or virtual addresses; provenance alone cannot determine this.
Addresses and pointer captures MUST preserve all 64 bits independently of host
`size_t` or JSON number precision.

`ptr64(foo)` succeeds without mapping or dereferencing its captured value.
`ptr64(foo):follow` requires the active mapper to translate that absolute value
into a readable matcher location. Missing or unsuccessful mapping fails the
path. It MUST NOT truncate the pointer or assume it is an image offset. The
capture retains the original absolute value, not the mapped location.

A relative target need not be readable when only captured. Following either
kind of reference requires a readable location. Following does not perform an
extra implicit pointer dereference.

Capture data MUST retain its value, address space, and kind: `CursorAddress`,
`ResolvedRelativeTarget`, or `AbsolutePointerValue`. A convenience API may
return just a 64-bit value, but the implementation must retain that metadata.

### Capture schema and backtracking

A capture identifier MUST be declared exactly once syntactically in a pattern,
including across mutually exclusive alternatives. Repeated names are compile
errors; they imply neither overwriting nor equality constraints.

```text
( E8 rel32(target) | FF 15 rel32(slot) )    valid: two declaration sites
( E8 rel32(target) | E9 rel32(target) )    invalid: duplicate name
```

The compiler builds the union of all declared names. A match contains only the
captures produced by its successful path. Looking up a declared but absent name
returns an optional empty result; an undeclared name is a schema error. The
conceptual C++ shape is `std::optional<address_t> hit->capture("target")`, where
`address_t` preserves 64 bits. Other languages may use their own equivalent API.

Capture state MUST be transactional. Every alternative or backtracking
checkpoint records the state; failure restores it before another path runs.
Failed alternatives, nested branches, gap retries, and failed references MUST
NOT leak captures into a successful result.

### Pipelines and uniqueness

Pipelines compose stages with `->`; arguments use parentheses. `find(pattern)`
produces match records with offsets and captures. Adding a capture MUST NOT
change its output into a captured address.

`capture("name")` validates against the input schema before execution, including
when there are no input matches. An unknown name is a construction error. For
a declared name, projection drops records where it is absent and retains the
value, kind, and address space of present captures. It MUST NOT implicitly map
absolute pointers.

`unique` asserts exactly one element at its stage. Zero or several elements
are errors; it never means taking the first. After `find`, it counts match
records. After projection and deduplication, it counts distinct capture values.
Distinctness includes kind and address space, not just equal integer bits.
Thus two call sites sharing a target fail `find(...) -> unique` but can satisfy
`find(...) -> capture("callee") -> unique`.

### Compilation and implementation boundary

```text
pattern text
    -> semantic AST
    -> capture-schema, reference-policy, and modifier validation
    -> compiled matcher IR
         -> matching
         -> seed and rarity analysis
```

Matching and seed analysis MUST consume the same compiled representation.
Neither seed selection nor pipeline capture selection may reinterpret source
punctuation. Optimized matching MUST preserve the exhaustive matcher's results,
including captures. Cursor stacks and checkpoints are private execution details.

Reference encoding policies own width, signedness, endianness, decoding, and
result width. Valid policies are `SignedRelative8LE`, `SignedRelative32LE`, and
`AbsolutePointer64LE`. Construction MUST reject inconsistent policies rather
than represent combinations such as a relative 32-bit encoding with width eight.
Relative references use an operand-end base; absolute pointers have no relative
base or adjustment. `:follow` selects target continuation instead of sequential
continuation in the IR.

Compilation and persisted artifacts MUST identify the dialect explicitly as
`maml-v1`. Automatic dialect guessing is prohibited. The current engine treats
`??` as two bytes; MAML v1 treats it as one, so patterns require explicit migration.

The full lexical grammar, match enumeration and gap preference, pipeline
ordering and record identity, concrete mapper API, serialization, and resource
limits still need specification before a complete v1 release. Conformance
vectors avoid depending on those unsettled choices. Instruction recognition,
implicit equality captures, and public cursor-stack operations are outside v1.

## Build and run

Requires CMake 3.19+, a C++20 compiler, and Python 3.10+ for the bindings.

```sh
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python -e '.[pe]' pytest build
.venv/bin/python tools/build.py --python-tests --artifacts
```

On Windows, use `.venv/Scripts/python.exe` instead. CMake alone builds the
C++ library consumers, tools, and tests:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 4
ctest --test-dir build -C Release --output-on-failure
```

Python:

```python
from maml import Image, Pattern, generate

image = Image.from_bytes(bytes.fromhex("90 48 8B C4 90"))
hit = Pattern("48 8B C4").find(image)
assert hit.offset == 1
# Generation: generate.candidates / verified / resolve_consensus.
```

C++ consumers link `maml::maml`, using either `add_subdirectory(maml)` or
`find_package(maml CONFIG REQUIRED)` after `cmake --install build --prefix ...`:

```cpp
#include <maml.hpp>
#include <maml/generate.hpp>
#include <array>

int main() {
    const std::array<unsigned char, 5> image{0x90, 0x48, 0x8B, 0xC4, 0x90};
    auto hit = maml::locate::find(image, "48 8B C4");
    return hit && hit->offset == 1 ? 0 : 1;
}
```

`build/mamlscan` and `build/mamlpipe` expose scanning and pipelines. The wheel
verification script checks an installed artifact and its expected SIMD backend:

```sh
python /path/to/maml/tools/verify_wheel.py --expect-simd neon
```

Use `sse2` for supported x86-64 builds. Run it with the wheel's interpreter
outside the source tree. GitHub workflows cover C++, Python, wheel builds,
and opt-in publishing; local checks do not establish remote CI success.

CMake options `MAML_BUILD_TESTS` and `MAML_BUILD_TOOLS` default to enabled when
MAML is the top-level project and disabled when embedded with `add_subdirectory`.
`MAML_CLANG_TIDY=ON` enables clang-tidy during compilation.

## Project layout and validation

| Path | Purpose |
| --- | --- |
| `include/maml.hpp` | Public umbrella header |
| `include/maml/maml.hpp` | Pattern parser and matching engine |
| `include/maml/mamlscan.hpp` | Reusable scanner, seed selection, and filtering |
| `include/maml/generate.hpp` | Generation, cross-image verification, and consensus |
| `include/maml/pipeline.hpp` | Locator pipeline parser and execution |
| `python/maml/` | Cython extension and Python interfaces |
| `tools/` | Scanner, pipeline, benchmark, build, and package verification tools |
| `tools/durability/` | Cross-build measurement and resolution tools |
| `tests/` | C++ and Python runtime tests |
| `conformance/` | Language-neutral v1 vectors and adapter protocol |
| `.github/workflows/` | CI, wheels, and opt-in release publishing |

Runtime tests include crowded images with decoy instructions and varied bytes,
not only tiny fixtures where almost any literal is unique. Structural checks
exercise strategy coverage and search cost as well as returned addresses.
These tests validate the current implementation; the
[conformance adapter protocol](conformance/README.md) is the separate path for
checking a v1 implementation in any language.

For durability measurements, generate on one build, verify against a second,
and resolve on an independent third build with known target correspondences.
Report correct targets separately from unique matches, and include misses,
ambiguity, and conflicting consensus groups. The
[durability tools](tools/durability/README.md) require external binaries and
metadata; their availability is not evidence of a particular success rate.

## License

Dual-licensed under BSL-1.0 or MIT; see [LICENSE](LICENSE).
