# MAML

MAML stands for **Mahmoud’s Address Matching Language**, a byte-oriented binary
matching language.
Patterns describe bytes, gaps, captures, and references. Pipelines transform
matches and address sets. Cursor-machine mechanics stay below compilation.

**Status:** v1 is the language. Patterns, pipelines, generation, and the CLIs
use `maml::v1` / `maml.Pattern` / `maml.Pipeline`. There is no unversioned
dialect and no `--dialect` switch.

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
str("SomeStringAnchor")
    -> xrefs
    -> func
    -> find("E8 rel32(init) [3..5] 48 85 C0")
    -> capture("init")
    -> unique
```

See [build validation](docs/build-validation.md) for the current verification
results. The implementation passes all 60 supplied v1 conformance vectors;
those finite cases do not establish complete language coverage.

The language remains byte-oriented. Instruction-aware constructs such as
`call(callee)` and `mov(...)` are outside v1.

## Contents

- [Using MAML v1](#using-maml-v1)
- [Current pattern language](#current-runtime-language)
- [Current locator pipelines](#current-locator-pipelines)
- [Scanning APIs and CLI](#current-scanning-apis-and-mamlscan)
- [Semantic generation and nibble masks](#semantic-generation-and-nibble-masks)
- [Pattern generation and resolution](#generating-and-resolving-patterns)
- [Normative v1 semantics](#maml-v1-semantics)
- [Build and run](#build-and-run)
- [Project layout and validation](#project-layout-and-validation)

## Using MAML v1

Python selects the dialect by importing `maml.v1`. Both patterns and pipelines
compile on construction; unknown capture projections fail before any image is
searched. Matching and pipeline execution run in C++ with the GIL released.

```python
from maml import v1

image = v1.Image(bytes.fromhex("E8 01 00 00 00 90 CC"))
hit = v1.Pattern("E8 rel32(callee) 90").find(image)
assert hit.offset == 0
assert hit.capture("callee").value == 6

result = v1.Pipeline(
    'bytes("E8 rel32(callee):follow CC") -> capture("callee") -> unique'
).run(image)
assert result.ok and result.values[0].value == 6
```

`Pattern.schema` is the union of declared names. `match_at(image, offset)` tests
exactly that buffer offset; `find(image)` returns the first match;
`find_all(image, limit=0)` returns all matches. `exhaustive=True` disables seed
selection for differential checks. A match contains its buffer offset and an
immutable dictionary of present captures. `capture(name)` returns a
`CaptureValue(value, kind, space)` or `None` for a declared absent capture;
unknown names raise `SchemaError`.

`v1.Image(data, base=0, pointer_map={}, code=(), rodata=(), funcs=(), instructions=())` takes an
immutable byte snapshot. Ranges are half-open buffer offsets, supplied as
`(begin, end)` pairs or `maml.Range` objects. Captured cursor and relative
addresses include `base`; match offsets do not. `pointer_map` explicitly maps
absolute pointer values to logical image addresses. `from_file()` reads a flat
image; `from_pe()` supplies flattened bytes and metadata using the optional PE
loader. Supply `base=` explicitly when a virtual-address model is needed.

C++ uses the same compiled program:

```cpp
#include <maml/v1_pipeline.hpp>
#include <array>

int main() {
    const std::array<uint8_t, 7> bytes{0xE8, 1, 0, 0, 0, 0x90, 0xCC};
    const maml::v1::Image image{bytes};
    const maml::v1::Pattern pattern("E8 rel32(callee):follow CC");
    const auto hit = pattern.find(image);
    return hit && hit->capture("callee")->value == 6 ? 0 : 1;
}
```

C++ images borrow their backing bytes. `Image::pointer_map` maps absolute values
to logical addresses. `Pattern::match_at`, `find`, and `find_all` mirror the
Python operations. `Pipeline::run(image, code, rodata, funcs)` accepts spans of
`maml::generate::Range` for metadata. Keep backing bytes and ranges alive and
unchanged during calls. Compiled patterns and pipelines are immutable and can
be shared between threads.

### V1 pipeline stages

| Stage | Result |
| --- | --- |
| `str("text")` | Exact indexed string addresses; requires rodata |
| `str("text", match="contains")` | Starts of indexed strings containing the text; requires rodata |
| `bytes("pattern")` | Match records across the image |
| `find("pattern")` | Match records starting within enclosing functions; requires function ranges |
| `before("pattern", within=N)` | All matches ending 0..N bytes before each anchor |
| `after("pattern", within=N)` | All matches starting 0..N bytes after each anchor instruction ends |
| `capture("name")` | Present named values, deduplicated by value, kind, and space |
| `xrefs` | Indexed reference sites; requires code and target classification |
| `func` | Enclosing function entries; requires function ranges |
| `func:loose` | Explicit alias for `func` |
| `func:strict` | Requires every input to already be a known function entry |
| `callers` | Direct call sites; requires code |
| `unique` | Exactly one current record or value; otherwise an error |
| `nth(N)` | Zero-based selection; out-of-range yields no results |
| `limit(N)` | First N results |
| `read(N)` | Little-endian scalars of width 1, 2, 4, or 8 |

`func:strict` checks every input before mapping or deduplication. An interior
address fails even when its function entry is also present in the input;
an address outside all known functions fails too. The failure raises
`ExecutionError` with code `NotFunctionEntry`. Empty input remains empty, but
missing function metadata is still an error. `func:loose` retains plain `func`'s
behavior of mapping interiors and dropping uncovered addresses. Modifiers must
attach without whitespace around `:`. Unknown, repeated, or misplaced pipeline
modifiers are compile errors, and successful traces retain the modifier name.

A pipeline starts with exactly one `str` or `bytes` source. `bytes` and `find`
produce records regardless of whether their patterns declare captures. Address
transforms use record offsets; `capture` explicitly selects a named value.
`nth`, `limit`, and `unique` preserve the current type and capture schema.
Unlike the unversioned pipeline, `read` may be followed by selectors such as
`unique`; its output has kind `ReadValue` and space `scalar`. Scalars and absolute
pointer captures cannot feed address transforms without explicit conversion.

String indexing and xref discovery use the same byte-analysis helpers as the
[current pipeline](#current-locator-pipelines), including the six-byte printable
ASCII string minimum. `find` searches each eligible start once, using the whole
image as its address space so that an explicit `:follow` can leave the function.
The function range constrains start positions, not the reference destination or
final cursor. Metadata ranges do not constitute disassembler proof.

Results have `kind` (`matches` or `values`), `schema`, `matches`, `values`, and a
`trace` of stage/input/output counts. `ok` means a nonempty result. Ordinary
misses return empty results; malformed input raises `CompileError`, unknown
captures raise `SchemaError`, and failed `unique` raises `CardinalityError`.
Missing metadata and resource exhaustion raise `ExecutionError`. Compiler
errors carry a `code` and native parser `position`. C++ reports `maml::v1::Error`
with the same code and position.

### String matching modes

`str("text")` defaults to `match="exact"`. Use `match="contains"` for a
case-sensitive substring search within the existing indexed strings:

```text
str("DeferredInputEventChange", match="contains")
    -> xrefs
    -> nth(0)
    -> func
    -> unique
```

Both modes return each matching **enclosing string's start** once, sorted by
address (including the image base). They never return the substring's interior
address. Repeated occurrences within one string still produce one result, so
`xrefs` searches references to the enclosing start. Empty needles are rejected
only for `match="contains"`; exact-mode `str("")` remains valid and returns no
indexed strings. Unknown modes are compile errors. Substrings cannot span
separate indexed strings.

This does not change string discovery: the existing printable-ASCII indexing,
minimum indexed length of six bytes, and `rodata` requirements still apply.
The needle itself may be shorter than six bytes. `match="exact"` is also accepted
explicitly; no case folding or approximate matching is performed.

```text
string_source := "str" "(" quoted_text ["," "match" "=" ("\"exact\"" | "\"contains\"")] ")"
```

Python uses keyword-only `match_mode="exact"` (the pipeline text retains
`match=`). C++ uses `StringMatch::Exact` (the default) or `StringMatch::Contains`. Unknown textual modes, including modes
provided through the Python builder, are rejected during pipeline compilation:

```python
query = (v1.PipelineBuilder()
         .str("DeferredInputEventChange", match_mode="contains")
         .xrefs().nth(0).func().unique().build())
```

```cpp
const auto query = maml::v1::PipelineBuilder()
    .str("DeferredInputEventChange", maml::v1::StringMatch::Contains)
    .xrefs().nth(0).func().unique().build();
```

### Directional searches

```text
str("ClearScripts")
    -> xrefs
    -> before("E8 rel32(callee)", within=32)
```

This returns all matching call-site records, sorted by offset. It does not select
only the nearest call. `within` is required, is an unsigned 64-bit integer, and
measures the intervening byte distance, inclusively. `within=0` requires
adjacency. Append `-> capture("callee")` to project called targets; append
`-> unique` at the desired stage to require one match or one projected value.

The grammar additions are:

```text
directional_stage := ("before" | "after") "(" quoted_pattern "," "within" "=" uint64 ")"
```

For an anchor offset `A`, `before` accepts a match whose final cursor `E`
satisfies `E <= A` and `A - E <= within`. Its start may precede the window by
the pattern's length. End bounds participate in backtracking: an alternative or
gap may try another path when its first endpoint is outside the window.

For an anchor instruction range `[A, B)`, `after` accepts starts `S` satisfying
`S >= B` and `S - B <= within`. The matched pattern may extend beyond the window.
Supply instruction ranges via Python `v1.Image(..., instructions=[(A, B)])`, the
fifth argument to C++ `Pipeline::run(image, code, rodata, funcs, instructions)`,
or `instruction A B` lines in the `mamlpipe` manifest. These ranges are half-open
buffer offsets, not virtual addresses. `after` requires a known instruction at
every input anchor and raises `MissingMetadata` otherwise; it does not guess a
length from the pattern that produced the anchor. Conflicting lengths, empty
instruction ranges, and ranges outside the image are errors.

Both stages use record offsets or image-address values as anchors, replace the
capture schema with the searched pattern's schema, and preserve captures from
successful paths. Scalars and unmapped absolute-pointer values are invalid
anchors. Results are deduplicated by match start and sorted ascending. For a start
eligible through multiple anchors, ascending anchor order determines the first
successful path; each start yields at most one record, as in ordinary scanning.
Empty input produces empty output. Zero-width patterns may match at image edges.

Searches use the full image address space and do not implicitly stop at function
or basic-block boundaries. They match bytes, not decoded call instructions.
Explicit `:follow` remains supported: for `before`, the endpoint is the final
cursor after following, not a contiguous source extent. The full matched path
need not lie inside the byte window. Use sequential patterns for ordinary local
call-site searches.

Directional stages allow at most 1,000,000 candidate-start attempts per stage,
with existing per-match execution limits. Exceeding the budget raises
`ResourceLimit`, not a partial successful result. Sequential extent bounds come
from the compiled IR; followed patterns may require a broader search.

Equivalent builder calls:

```python
query = (v1.PipelineBuilder().str("ClearScripts").xrefs()
         .before("E8 rel32(callee)", within=32).build())
# .after("E8 rel32(callee)", within=32) requires anchor instruction ranges.
```

```cpp
const auto query = maml::v1::PipelineBuilder().str("ClearScripts").xrefs()
    .before("E8 rel32(callee)", 32).build();
// .after("E8 rel32(callee)", 32) requires anchor instruction ranges.
```

### Multiline pipelines and declarative builders

The pipeline separator `->` is exactly two ASCII characters: hyphen-minus (`-`)
followed immediately by greater-than (`>`). A Unicode arrow is not accepted.
Newlines and indentation are whitespace outside quoted arguments; `->` is still
required between stages. A newline alone does not connect stages.

Python uses a triple-quoted string to preserve the newlines:

```python
from maml import v1

query = v1.Pipeline("""
    str("SomeStringAnchor")
        -> xrefs
        -> func:loose
        -> find("E8 rel32(init) [3..5] 48 85 C0")
        -> capture("init")
        -> unique
""")
# result = query.run(image)  # image supplies code, rodata, and function ranges
```

C++ uses a raw string literal; the custom `pipeline` delimiter allows the
quoted function arguments to appear unchanged:

```cpp
#include <maml/v1_pipeline.hpp>

const auto query = maml::v1::Pipeline(R"pipeline(
    str("SomeStringAnchor")
        -> xrefs
        -> func:loose
        -> find("E8 rel32(init) [3..5] 48 85 C0")
        -> capture("init")
        -> unique
)pipeline");
// auto result = query.run(image, code, rodata, funcs);
```

The equivalent Python builder avoids textual separators:

```python
from maml import v1

query = (
    v1.PipelineBuilder()
    .str("SomeStringAnchor")
    .xrefs()
    .func(strict=False)
    .find("E8 rel32(init) [3..5] 48 85 C0")
    .capture("init")
    .unique()
    .build()
)
# result = query.run(image)  # image supplies code, rodata, and function ranges
```

The equivalent C++ builder:

```cpp
#include <maml/v1_pipeline.hpp>

const auto query = maml::v1::PipelineBuilder()
    .str("SomeStringAnchor")
    .xrefs()
    .func(maml::v1::FunctionMode::Loose)
    .find("E8 rel32(init) [3..5] 48 85 C0")
    .capture("init")
    .unique()
    .build();
// auto result = query.run(image, code, rodata, funcs);
```

Both builders also expose `bytes`, `callers`, `nth`, `limit`, and `read`.
Python `.func()` selects plain `func`, `strict=True` selects `func:strict`,
and `strict=False` selects `func:loose`. C++ uses `FunctionMode::Default`,
`Strict`, or `Loose`. Each method returns a new builder, so prefixes can be
reused without mutation. `.build()` invokes the existing v1 compiler and its
schema validation. Python `.source` and C++ `.source()` expose safely quoted
canonical text, which can also be passed to `mamlpipe`. Execution semantics
and metadata requirements are identical to textual pipelines.

### V1 command-line examples

```sh
mamlscan image.bin 'E8 rel32(callee):follow CC' --capture callee
mamlpipe image.bin --ranges ranges.txt \
    'bytes("E8 rel32(callee)") -> capture("callee") -> unique'
mamlpipe --batch pipelines.tsv --image image.bin --ranges ranges.txt
python tools/check_conformance.py --adapter python -m maml.v1_adapter
```

The v1 scanner accepts single-image jobs, `--limit N`, `--expect HEX`, and an
optional `--capture name`. Without projection it reports match offsets. Capture
selection drops absent values and counts the remaining matches; it does not
deduplicate equal targets. Use a pipeline for deduplicated projection.
The pipeline CLI labels records as `matches` and projections as `values`, and
prints capture kind and address space alongside values. Both CLIs use flat
images with base zero; custom pointer maps and nonzero bases use the APIs.
Pipeline manifests and input batch files keep the formats documented below.
V1 batch output prefixes each result with the job name and a tab.

### Enumeration, grammar, and execution bounds

The frontend accepts whitespace-separated operations, two-nibble bytes (`??`,
`F?`, and `?F` included), parenthesized alternatives, and the operations in the
[normative table](#pattern-operations). Capture names use letters/underscores
followed by letters, digits, or underscores. Gap bounds are unsigned decimal;
`target_add` is signed decimal with an optional minus. Pipeline strings support
`\"`, `\\`, `\n`, `\t`, and `\xHH`. Comments and punctuation from the unversioned
grammar are not aliases in v1.

Search visits start offsets in ascending order, including the end offset for
zero-width patterns. Each start yields its first successful path, trying
alternatives left to right and gaps shortest first. Match records are distinct
by start offset within a scan; address/value stages sort and deduplicate typed
values. Seed selection is conservative: it derives fixed literal runs from the
compiled instructions up to uncertain control flow and uses the existing SIMD
scanner. Patterns without a usable seed fall back to exhaustive starts.

Patterns and pipelines are limited to 65,536 UTF-8 source bytes; patterns allow
64 nested groups and 256 declared captures. A match attempt permits 1,000,000
instruction steps and 1,024 pending checkpoints. Exceeding a bound raises a
resource error, never a normal miss. C++ callers may override the instruction
budget passed to `match_at`. There is no wall-clock or whole-scan time guarantee.

`v1.generate` emits semantic patterns, verifies them in both supplied builds,
and can infer nibble masks; see [semantic generation](#semantic-generation-and-nibble-masks).
Portable compiled-pattern persistence is not implemented; retain source text.

## Legacy byte grammar

The old unversioned `?` / `$ { ' }` grammar is gone. v1 is the only dialect;
`??` is one wildcard byte, and references use `rel32(name)`.

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
str "SomeStringAnchor" -> xref -> func -> unique
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
#include <maml/v1_pipeline.hpp>
#include <array>

int main() {
    const std::array<uint8_t, 8> bytes{0x90, 0xF7, 0x80, 0x58, 0x1C, 0, 0, 0x90};
    const std::array<maml::generate::Range, 1> funcs{{{0, 8}}};
    maml::v1::Image image{bytes};
    const auto r = maml::v1::Pipeline(
        "bytes(\"F7 80\") -> func -> find(\"F7 80 @(x) ?? ?? 00 00\") -> read(4)")
        .run(image, funcs, {}, funcs);
    return r.ok() && !r.is_matches && r.values.size() == 1 &&
           r.values[0].value == 0x1C58 ? 0 : 1;
}
```

v1 pipeline spelling uses `str("text")`, `xrefs`, and `nth(0)`. `find(...) -> capture("name")`
returns matches first and projects named captures explicitly.

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

Python `Pattern` compiles once and searches an `Image` with `find` / `find_all`.

```python
from maml import Image, Pattern

img = Image.from_bytes(bytes.fromhex("90 48 8B C4 90"))
hits = Pattern("48 8B C4").find_all(img, limit=2)
assert hits[0].offset == 1
```

`find()` returns the first match, not a uniqueness assertion. Use
`find_all(limit=2)` and require exactly one result when uniqueness matters.
Named captures use `rel32(name)` / `@(name)` and are read with `Match.capture`.

Invalid patterns raise `CompileError` with `code` and `position`. C++ throws
`maml::v1::Error`. Scan with `v1::Pattern::find_all`.

```sh
mamlscan flat.bin '48 8B C4' --expect 1
mamlscan flat.bin "E8 rel32(target)" --capture target --limit 2
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
`base` at zero. For a nonzero base, construct an image from the flattened bytes
with `Image.from_bytes(data, base=...)` before using `to_va()`.
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

## Semantic generation and nibble masks

Use `maml.v1.generate` in Python or `<maml/v1_generate.hpp>` and
`maml::v1::generate` in C++. The existing anchor discovery strategies emit v1
syntax directly: call references use `rel32(target)`, RIP-relative operands
with trailing immediates use `rel32(target, target_add=N)`, and skipped string
reference operands use four `??` bytes. Verification and consensus compile and
execute that semantic program, not the unversioned parser.

```python
from maml import v1

# A known call to the supplied target in each synthetic build.
def call_image(target, site, tail):
    data = bytearray(b"\xCC" * 256)
    data[site:site + 5] = b"\xE8" + (target - site - 5).to_bytes(4, "little", signed=True)
    data[site + 5:site + 9] = bytes.fromhex(tail)
    return v1.Image(data, code=[(0, 256)], funcs=[(site, site + 9)])

a = call_image(16, 64, "4C 8B D1 48")
b = call_image(32, 96, "4C 8B D7 48")
options = v1.generate.Options(prefer_short=False, nibble_wildcards=True)
candidates = v1.generate.verified(a, 16, b, 32, options)
assert any("D?" in c.pattern for c in candidates)
```

The common call pattern in that example is:

```text
E8 rel32(target) 4C 8B D? 48
```

Nibble inference preserves a nibble only when both aligned programs fix it to
the same value: `D1` and `D7` become `D?`, `A1` and `B1` become `?1`, and
`A1` and `B2` become `??`. Existing references and their arithmetic policies
must agree. The implementation compares compiled linear instructions, not
text substrings, and does not guess instruction alignment across insertions,
deletions, or different control flow.

`v1.generate.Options` defaults to `max_len=64`, `want=4`, `prefer_short=True`,
`deep_anchor=True`, and `nibble_wildcards=True`. Exact candidates are preferred;
when the requested budget has room, verification tries generalized pairs with
full tails of matching structure. Every generalized candidate must still match
exactly once and resolve to the supplied target in **both** images. Two sites
capturing the same target are still two matches and fail this check. Set
`nibble_wildcards=False` to disable inference. Single-image `candidates()` does
not infer changes it has never observed.

V1 candidates contain `pattern`, `dialect`, `target_capture`, signed
`anchor_delta`, `anchor_site`, `strategy`, and `literals` (fully fixed bytes).
They have no positional `save_index`. A nonempty `target_capture` selects the
named value; otherwise resolution computes `match.offset - anchor_delta` with
checked arithmetic. An interior anchor is not silently treated as the target.
Generated verified results contain at most one variant per source site and
strategy. Consensus reports candidate indices; callers should still inspect
source sites when judging independence across strategies or manually supplied
candidates.

Generation uses buffer-relative targets and ranges; Python requires
`image.base == 0`. The C++ generator takes `maml::generate::Image`, whose ranges
are already buffer-relative. Identical input-buffer identity is rejected by
`verified()`; callers supply the independent builds and target correspondences.

For consumers using the shared lower-level `maml.generate` interface,
`Options(dialect="maml-v1", nibble_wildcards=True)` selects the same implementation.
Its candidate transport retains a zero `save_index` field for semantic output;
`dialect` and `target_capture` are required when constructing a transport
candidate manually. Resolution never guesses the dialect from pattern text.

### Generation coverage and possible extensions

The [future generation design](docs/generation-design.md) specifies analysis
adapters, wildcard constraints, additional strategies, and verification contracts.
It is a proposal, not a description of implemented APIs.

The current strategies are `Body`, `Xref` (direct calls), `StringAnchor`
(including a nearby call anchor), and `RipRef`. Cross-build verification can
also infer nibble masks for aligned linear patterns. The following strategies
are **not generated automatically**, although the matcher supports the relevant
syntax where indicated:

| Possible strategy | Current boundary |
| --- | --- |
| Follow a reference and check destination bytes | References capture and continue sequentially; no emitted `:follow` |
| Absolute pointer, vtable, or import-slot anchors | No `ptr64` candidate discovery or pointer-chain inference |
| Jump and conditional-branch anchors | Call anchors use `E8`; no `rel8` or other branch-anchor strategy |
| Multi-hop reference walks | No repeated followed references or pointer walks; string-plus-call anchoring already exists |
| Infer variable gaps | No alignment across inserted/deleted bytes to generate `[min..max]` |
| Infer alternatives | No automatic `(A | B)` synthesis for divergent layouts |
| Synthesize locator pipelines | No search/ranking of complete `str`/`xrefs`/`func`/`find` pipelines |

These are extension opportunities, not additional v1 conformance requirements.
Instruction-level forms such as `call(...)` or `mov(...)` remain outside the
byte-oriented language. Builder APIs construct pipelines explicitly; they do
not infer a pipeline from an image.

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
requirements for implementers. The v1 frontend implements these contracts.
The language-neutral
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

The implementation's lexical, enumeration, and resource policies are described
under [Using MAML v1](#using-maml-v1). The conformance vectors deliberately avoid
depending on enumeration preferences. Portable compiled-program serialization
and instruction recognition remain outside the current implementation.
Implicit equality captures and public cursor-stack operations are outside v1.

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
#include <maml/v1.hpp>
#include <maml/generate.hpp>
#include <array>

int main() {
    const std::array<unsigned char, 5> image{0x90, 0x48, 0x8B, 0xC4, 0x90};
    auto hits = maml::v1::Pattern("48 8B C4").find_all(maml::v1::Image{image}, 2);
    return !hits.empty() && hits[0].offset == 1 ? 0 : 1;
}
```

`build/mamlscan` and `build/mamlpipe` expose scanning and pipelines. The wheel
verification script checks an installed artifact and its expected SIMD backend:

```sh
python /path/to/maml/tools/verify_wheel.py --expect-simd neon
```

Use `sse2` for supported x86-64 builds. Run it with the wheel's interpreter
outside the source tree. GitHub workflows cover C++, Python, and wheel builds;
local checks do not establish remote CI success.

Releases are tag-driven: bump the version in `pyproject.toml`, `CMakeLists.txt`,
and `include/maml/version.hpp` (the Python `__version__` is derived from the C++
macros), move the `[Unreleased]` notes in `CHANGELOG.md` into a version
section, then push a `vX.Y.Z` tag. `.github/workflows/deploy.yml` builds through
`wheels.yml` and publishes the `maml-python` distribution to PyPI with trusted
publishing -- no API token.

CMake options `MAML_BUILD_TESTS` and `MAML_BUILD_TOOLS` default to enabled when
MAML is the top-level project and disabled when embedded with `add_subdirectory`.
`MAML_CLANG_TIDY=ON` enables clang-tidy during compilation.

## Project layout and validation

| Path | Purpose |
| --- | --- |
| `include/maml.hpp` | Public umbrella header |
| `include/maml/v1.hpp` | v1 pattern parser and matching engine |
| `include/maml/mamlscan.hpp` | Reusable scanner, seed selection, and filtering |
| `include/maml/generate.hpp` | Generation, cross-image verification, and consensus |
| `include/maml/v1_pipeline.hpp` | Locator pipeline parser and execution |
| `python/maml/` | Cython extension and Python interfaces |
| `tools/` | Scanner, pipeline, benchmark, build, and package verification tools |
| `tools/durability/` | Cross-build measurement and resolution tools |
| `tests/` | C++ and Python runtime tests |
| `conformance/` | Language-neutral v1 vectors and adapter protocol |
| `.github/workflows/` | CI, wheels, and tag-triggered PyPI publishing |

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
