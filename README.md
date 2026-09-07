# MAML

MAML stands for **Mahmoud’s Address Matching Language**, a byte-oriented binary
matching language.
Patterns describe bytes, gaps, captures, and references. Pipelines transform
matches and address sets. Cursor-machine mechanics stay below compilation.

**Status:** the C++ engine, generator, Cython bindings, and Python APIs are
available. The agreed MAML v1 semantic contracts are frozen;
the examples below describe the new dialect, which is not implemented yet.

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
