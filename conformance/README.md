# MAML v1 conformance vectors

[v1.json](v1.json) contains language-neutral inputs and expected outputs for the
[normative README contract](../README.md#maml-v1-semantics). It has no dependency
on a particular matcher, language, object layout, exception class, or build
system. Rust, C++, Python, JavaScript, and other implementations can consume the
same file or expose the adapter protocol below.

**Status:** all 60 supplied vectors pass against the C++ semantic frontend
through its Cython bindings and the `maml.v1_adapter` JSONL adapter. This checks
the listed contracts, not complete language coverage or performance. The
unversioned parser remains a separate dialect.

## Run

Only Python's standard library is required for the runner:

```sh
python tools/check_conformance.py
python tools/check_conformance.py --adapter python -m maml.v1_adapter
python tools/check_conformance.py --timeout 30 --adapter /path/to/maml-adapter
python tools/check_conformance.py --adapter python /path/to/adapter.py
```

The first command validates the vector format and explicitly reports that no
implementation was tested. The other commands run an implementation adapter.
`--adapter` must be the last runner option; everything following it is the
executable and its arguments, passed without a shell. Timeout covers the whole
adapter process. Exit status is zero only when every case passes. Unsupported,
missing, duplicate, unknown, malformed, or incorrect responses fail the run;
there is no skip-to-pass behavior.

## JSONL transport

The runner starts one adapter process and sends one JSON object per input line:

```json
{"id":"literal","request":{"dialect":"maml-v1","operation":"match_at","pattern":"48 8B C4","image":{"base":"0x0","bytes":"48 8B C4","pointer_map":[]},"start_offset":"0x0"}}
```

For each request the adapter returns exactly one JSON object on stdout:

```json
{"id":"literal","result":{"status":"ok","schema":[],"match":{"offset":"0x0","captures":{}}}}
```

Responses may arrive in any order. Stdout is exclusively protocol output;
write diagnostics to stderr. Requests contain no expected answers. The adapter
must execute its implementation and normalize its results into this protocol.
Error codes below are transport categories, not required host-language
exception names. Extra result fields are rejected; keep diagnostic text on
stderr rather than adding fields to the normalized result.

## Values and address model

All addresses, offsets, and captured values are canonical unsigned 64-bit hex
strings: `0x0`, `0x8`, `0xffffffffffffffff`. Lowercase digits, no leading zeroes,
and no JSON numbers. This preserves exactness in languages whose JSON numbers
use floating point. Patterns express `target_add` as signed decimal text.

An image is `{base, bytes, pointer_map}`. `bytes` is a string of space-separated
hex byte pairs. Its byte at offset `i` has logical address `base + i` in address
space `image`. A match's `offset` and `start_offset` are byte offsets into that
buffer, not logical addresses. Address arithmetic must remain checked even
near the upper boundary; fixtures deliberately place operands there.

`pointer_map` is an explicit table of `{value, address}` hex-string pairs. A
pointer value maps only if an exact entry exists. `address` is a logical address
in the image space. No entry means mapping failure, even if the pointer's bits
look like a valid offset. A mapped location must also be readable. Relative
following uses its computed logical address directly in the image space.

A capture is:

```json
{"value":"0x140000010","kind":"AbsolutePointerValue","space":"absolute"}
```

Kinds are `CursorAddress`, `ResolvedRelativeTarget`, and `AbsolutePointerValue`.
Matching uses `image` for cursor/relative addresses and `absolute` for decoded
pointers. Record-only pipeline fixtures may supply another space identifier
to check that equal bits in different spaces remain distinct.

A match record is `{offset, captures}`, where `captures` maps names to present
capture objects. Absent names are omitted. `schema` is the union of declared
names, represented as a duplicate-free list. Schema order is immaterial.

## Operations

Every request includes `dialect: "maml-v1"` and `operation`.

| Operation | Additional request fields | Successful result |
| --- | --- | --- |
| `compile` | `pattern` | `{status: "ok", schema}` |
| `match_at` | `pattern`, `image`, `start_offset` | `{status: "ok", schema, match}` |
| `project` | `name`, `schema`, `matches`, `unique` (boolean) | `{status: "ok", values}` |
| `lookup` | `name`, `schema`, `match` | `{status: "ok", value}`; `value` is a capture object or null |
| `unique_matches` | `matches` | `{status: "ok", match}` |

These are adapter operations, not mandatory public API names. An adapter can
construct equivalent stages/records using its implementation's interfaces.

`match_at` compiles and attempts matching at exactly `start_offset`; it does not
scan ahead for another start. Failure returns `{status: "no_match", schema}`.
The schema is available even when matching fails. The vectors avoid competing
successful paths and do not choose a global enumeration or gap-order policy.

`project` validates `name` against `schema` before processing any records. It
filters absent captures and deduplicates by `(value, kind, space)`. Result order
is immaterial, but duplicates are an error: the runner sorts for comparison
without silently removing repeated values. If `unique` is true, exactly one
deduplicated value must remain. Projection preserves absolute pointer values
without mapping them.

`lookup` distinguishes a declared absent capture (null) from an unknown name
(schema error). `unique_matches` counts the supplied match records directly;
fixtures use distinct match offsets so record-identity policy is not assumed.
The record-only operations exercise pipeline contracts without requiring a
binary format loader, disassembler, string index, or function-boundary provider.

## Errors

| Result | Meaning |
| --- | --- |
| `{status: "compile_error", code: "DuplicateCapture"}` | Capture name declared more than once |
| `{status: "compile_error", code: "InvalidModifier"}` | Unknown, repeated, or misplaced modifier |
| `{status: "compile_error", code: "InvalidReferencePolicy"}` | Unsupported reference policy/parameter combination |
| `{status: "compile_error", code: "InvalidArgument"}` | Argument outside its specified range |
| `{status: "schema_error", code: "UnknownCapture"}` | Name not declared in the input schema |
| `{status: "cardinality_error"}` | `unique` received zero or multiple elements |

Byte mismatch, truncated operands, arithmetic overflow/underflow, and failed
following are matching-path failures, not compiler or tool errors. If another
alternative succeeds, the result contains only that successful path's captures.

## Coverage and limits

The vectors cover literals, wildcard width, nibble masks, gaps, alternation,
relative signs and bases, sequential versus target continuation, explicit
adjustment, ordered checked arithmetic, full-width pointers, mapping, schema
union, duplicate declarations, transactional captures, projection, lookup, and
uniqueness.

They do not establish complete grammar coverage, performance, resource limits,
scan enumeration, or whole-pipeline source/transform behavior. Shared-IR use is
an architectural requirement that must also be reviewed in each implementation.
Optimized implementations must compare seeded and exhaustive matching over the
same inputs; identical outputs on these finite vectors alone do not prove that
their optimizer can never lose a match.

Additional vectors should specify all inputs and expected outputs, retain exact
64-bit values, and avoid depending on unsettled language choices. A semantic
change requires an explicit dialect/version decision rather than quietly
rewriting expected results to make an implementation pass.
