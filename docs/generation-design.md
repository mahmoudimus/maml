# Future design: constrained generation and analysis adapters

Status: proposed design, not implemented API. This document combines the planned
generation strategies with the analysis and wildcard-policy contracts needed to
support them. It does not change the MAML v1 language contract. MUST, SHOULD, and
MAY describe requirements for this proposed extension, not claims about current
implementation. Public API names below are illustrative.

## Objective and scope

Generate patterns and locator pipelines that recover a caller-specified target
under explicit constraints, then verify those candidates against supplied images.
The ranking objective is verified target recovery with few assumptions. Pattern
length is a secondary preference, not evidence of robustness.

The current generator supplies Body, Xref, StringAnchor, and RipRef strategies,
plus optional cross-build nibble inference for aligned linear patterns. It does
not yet supply the configurable analysis-adapter and constraint layer or the
additional strategies specified here.

MAML remains byte-oriented. Analysis adapters may use disassemblers, but the
matcher does not gain instruction-level syntax such as `call(...)` or `mov(...)`.
This proposal does not promise survival on unseen builds or automatic discovery
of corresponding functions across builds.

## Architecture

```text
IDA / Binary Ninja / Ghidra / other analysis sources
    -> analysis adapter
    -> normalized analysis facts
    -> wildcard policy + architecture rules
    -> validated generation constraints
    -> bounded strategy discovery
    -> compiled pattern or pipeline candidate
    -> verification
    -> ranking and evidence report
```

| Layer | Responsibility |
| --- | --- |
| Analysis adapter | Translate tool facts into a shared model; preserve uncertainty and provenance |
| Wildcard policy | Select exactness requirements and permitted generalizations |
| Architecture rules | Translate policy into encoded field masks and validated reference policies |
| Strategy discovery | Enumerate candidate anchors, walks, alignments, or pipeline templates |
| Compiler | Validate syntax, captures, references, modifiers, and executable structure |
| Verification | Execute candidates and enforce constraints and target-selection requirements |
| Ranking | Compare verified evidence, dependencies, cost, and size |

Matching, seed analysis, generation, and verification MUST consume the same
compiled semantic representation. Seed analysis MUST NOT infer reference meaning
from punctuation. Pattern and pipeline candidates share an envelope but retain
distinct executable types.

## Analysis adapter contract

Implementations may be named `IDAAdapter`, `BinaryNinjaAdapter`, and
`GhidraAdapter`. Tool-specific operand enums, address types, and APIs MUST remain
inside each adapter. The core MUST accept normalized snapshots without requiring
any particular analysis tool to be installed.

A snapshot SHOULD identify its image, content digest, architecture, endianness,
address model, producer/version, and declared capabilities. Its facts may include:

- Instruction boundaries and raw bytes tied to the supplied image.
- Operand categories and exact encoded field locations, including discontiguous
  bit slices. All relevant operands must be representable.
- References with source operand, encoding, resolution base, target, and evidence.
- Relocations, pointer slots, string locations, code/data ranges, and functions.
- Explicit mappings between absolute pointer values and matcher locations.

Facts MUST distinguish known information from unknown information. An empty
reference list is not proof of no references unless the producer asserts coverage
for that range and reference class. Missing relocation metadata MUST NOT imply
that an operand is stable. Heuristic facts MUST be identifiable as heuristic.
Conflicting facts MUST produce diagnostics or remain explicitly unresolved.

Instruction bytes and field bounds MUST be checked against the snapshot. Invalid
or stale facts MUST NOT silently become candidate-generation authority. Adapters
supply evidence, not wildcard policy. Architecture rules MUST work on normalized
facts rather than import tool APIs.

## Wildcard and reference constraints

The caller MUST be able to express:

- Bits or fields that must remain exact when included in a candidate.
- Bits or fields that must be wildcarded when included.
- Fields in which whole-byte or nibble generalization is permitted.
- References whose decoding, capture, or continuation must be preserved.
- Required anchors or fields that a candidate must include.

Exactness and inclusion are separate constraints. A field marked exact is not
implicitly a required anchor; conversely, trimming MUST NOT remove an explicitly
required anchor merely to produce a shorter candidate.

For an included byte, let `E` be the required-exact bit mask, `W` the
required-wildcard bit mask, and `M` the candidate's comparison mask:

```text
E & W == 0
M & E == E
M & W == 0
```

The policy MUST also specify the permitted mask choices for unconstrained bits.
An unspecified permission MUST NOT authorize arbitrary weakening. Exact values
come from the corresponding source bytes. If required-exact values conflict
across corresponding builds, that common candidate is infeasible.

V1 text can represent only comparison masks `FF`, `F0`, `0F`, and `00` per byte.
Architecture facts may describe finer bit slices, but generation MUST choose a
representable mask satisfying all constraints or report that no such encoding
exists. It MUST NOT silently wildcard protected bits. Arbitrary-bit mask syntax
would require a separately designed language extension.

Semantic references are not ordinary exact-byte comparisons. A policy requiring
reference preservation permits operand bytes to vary according to the reference
encoding while retaining its resolution and target-selection semantics. A
conflicting demand to fix those same operand bytes MUST be diagnosed unless an
explicit supported representation can enforce both requirements.

Policy evaluation MUST precede candidate optimization. Nibble inference, trimming,
alternative synthesis, and ranking MUST NOT weaken hard constraints. Each
transformation MUST preserve constraint provenance through alignment and compiled
operations so final verification can check compliance.

Literal-immediate preservation is a reasonable configurable default, not proof
of cross-build stability. Unknown analysis may be rejected or handled by an
explicit conservative policy; it MUST NOT be silently treated as stable.

## Discovery approaches

| Approach | Strategies | Required evidence |
| --- | --- | --- |
| Enumerate references to a known target | Followed references, branches, pointers, multi-hop walks | Reference sites, decoding policies, mappings; readable destinations for follow |
| Compare corresponding regions | Nibbles, gaps, alternatives | Caller-supplied target correspondence and validated alignment |
| Compose locator stages | Pipeline synthesis | Strings, references, functions, and candidate execution results |

### Followed references

Enumerate incoming references and emit a source anchor followed by a reference
and discriminative destination bytes, for example:

```text
E8 rel32(target):follow 48 89 5C 24 ??
```

The reference MUST capture the intended target independently of the final cursor.
`:follow` does not imply a return. Context after the source operand cannot be
appended as if it were destination context; the strategy must respect control
flow in the compiled pattern. Unreadable destinations fail that matching path.

### Pointer anchors

Accept supplied pointer slots or discover candidates within explicit data ranges.
Emit `ptr64(target)`, optionally with `:follow` and destination checks. A raw
pointer-looking value alone does not establish vtable or import-slot identity.
Those classifications require supporting analysis facts.

Capturing an absolute pointer does not require mapping it. Following it MUST use
an explicit address-space mapper; failure MUST fail the path without truncation
or reinterpretation as an image offset. Cross-build verification MUST compare
against each build's expected target in the declared address space, not require
identical absolute values across builds.

### Branch anchors

Discover direct jumps and conditional branches using validated instruction
boundaries or decoder-backed analysis. Emit opcode bytes and the appropriate
`rel8(target)` or `rel32(target)` operation, with optional follow. Arbitrary opcode
matches inside operand bytes MUST NOT be represented as proven instructions.

### Multi-hop reference walks

Search a reference graph with explicit depth, fan-out, candidate, and execution
budgets. Reject cycles during discovery. Emit explicit followed references and
unique capture declarations; select the intended target separately from any
intermediate destinations. Walk edges MUST have supported decoding policies and
required mappings. Discovering an edge does not prove a complete walk matches.

### Variable-gap inference

Align corresponding regions using supplied instruction/field correspondence or a
validated alignment procedure. Retain stable fragments and replace permitted
intervening variation with bounded `[min..max]` gaps. Do not infer alignment from
matching byte values alone when multiple interpretations remain unresolved.

Observed lengths establish evidence for the supplied builds, not bounds on future
builds. Widening beyond observed lengths MUST be an explicit policy decision.
Gaps MUST NOT swallow required anchors or protected semantic reference operations.
Verification must account for ambiguity introduced by the gap.

### Alternative inference

Emit bounded alternatives for supported divergent variants. Limit branch count
and combined program size. Preserve v1's globally unique capture declarations:
shared captures may be factored outside alternatives only when doing so preserves
cursor and capture semantics. Otherwise use distinct names with an explicitly
supported selection rule, or reject that candidate. No implicit capture overwrite
or equality semantics may be introduced.

### Pipeline synthesis

Start with a bounded catalogue of templates such as:

```text
str("anchor") -> xrefs -> func:loose
    -> find("E8 rel32(target)") -> capture("target") -> unique
```

Construct pipelines through the builder and compile with the existing frontend.
The textual separator is the two ASCII characters `-` and `>`; newlines remain
whitespace. Builders do not independently execute or reinterpret stages.

Template applicability MUST check metadata capabilities. `func:strict` asserts
that every input is already a known entry; it MUST NOT be used as a substitute
for mapping reference sites to enclosing functions. `find` produces match records,
`capture` projects present declared captures, and `unique` applies to the current
type and set. Synthesis MUST retain those semantics.

## Configuration and candidate envelope

Illustrative configuration, not a current API:

```python
options = GenerationOptions(
    strategies={
        "body", "call_reference", "followed_reference", "branch_reference",
    },
    max_reference_hops=2,
    max_candidates=128,
)
```

Discovery configuration SHOULD include enabled strategies, walk and alignment
budgets, gap/alternative bounds, and pipeline templates. Wildcard policy and
verification requirements MUST be separate inputs. Missing capabilities for an
explicitly requested strategy MUST be reported; best-effort skipping may be
supported only when explicitly selected and recorded in the result.

Each candidate MUST carry:

- Executable kind (pattern or pipeline), dialect, and compiled program.
- Rendered source and an explicit target-selection rule.
- Target kind and address space, including any signed anchor adjustment.
- Strategy, source anchors, analysis dependencies, and constraint provenance.
- Verification results identifying builds, expected targets, observed results,
  ambiguity, execution failures, and resource exhaustion.

The envelope is conceptual; portable serialization of compiled IR is not required
by this proposal. Persisted text and metadata MUST identify their dialect and
schema versions explicitly.

## Verification, ranking, and failure behavior

Every accepted candidate MUST compile, obey constraints, and recover the expected
target under the selected verification contract. A pattern's match offset MUST
NOT be mistaken for its captured target or an interior anchor's intended entry.

Verification MUST distinguish unique matching from unique target recovery. Two
matches selecting one target fail a unique-match requirement but may satisfy an
explicit deduplicated-target requirement. Pipeline projections MUST follow their
existing value/kind/space deduplication rules. The requirement and observed counts
MUST be retained in evidence; strategies cannot silently weaken uniqueness.

Cross-build verification requires caller-supplied target correspondence. Address
comparisons MUST use each image's declared model and checked arithmetic. Missing
mappings, unknown required analysis, no match, ambiguity, compile errors, and
resource exhaustion MUST be distinguishable. A budget-exhausted search MUST NOT
claim that no solution exists or that the selected candidate is globally optimal.

Rank eligible candidates using a documented deterministic ordering that considers:

1. Successful verification across supplied builds and required constraints.
2. Strength and quantity of metadata assumptions and required capabilities.
3. Ambiguity and measured execution cost.
4. Program complexity and size.

A scalar score alone is insufficient: retain the component evidence. Candidates
sharing an anchor or reference chain MUST NOT be counted as independent votes
without an explicit independence rule. Unseen-build survival remains unproven;
held-out builds provide stronger evidence than builds used to infer masks.

## Delivery sequence and acceptance criteria

1. **Foundations:** normalized snapshot model, capabilities, constraint validation,
   explicit target-selection envelope, and address-space contract. Provide a
   synthetic adapter so core tests do not require commercial analysis tools.
2. **Followed references and branch anchors:** reuse existing reference matching;
   demonstrate correct source/destination behavior and unique target recovery.
3. **Pointer anchors:** exercise full-width captures, explicit mappings, unmapped
   captures, mapping failures, and different virtual bases across builds.
4. **Bounded multi-hop walks:** verify depth/fan-out limits, cycles, intermediate
   captures, and final target selection.
5. **Gap and alternative inference:** validate alignment, constraint preservation,
   ambiguity, capture schemas, and budget exhaustion across divergent builds.
6. **Pipeline synthesis:** verify a small template catalogue, typed stage behavior,
   metadata dependency reporting, and deterministic ranking before broader search.

Tool adapters can be delivered independently against the shared contract. Each
adapter MUST pass common normalization fixtures plus tool-specific extraction
checks; mocked fixtures alone do not establish live integration correctness.

Required core cases include conflicting exact/wildcard requirements, unknown
metadata, multiple operands, discontiguous fields, unrepresentable masks,
endianness, stale snapshots, capture rollback, duplicate declarations, required
anchor trimming, arithmetic overflow, and match-versus-target uniqueness.
Equivalent normalized snapshots SHOULD produce equivalent constrained candidates
regardless of their originating tool. Existing v1 conformance remains required.

Before implementation, settle the concrete normalized schema, conservative unknown
policy, verification modes, and deterministic ranking order. These API choices
must not relax the semantic requirements above.

## Directional-stage implementation update

`before(pattern, within=N)` and `after(pattern, within=N)` are now pipeline
operations available to future synthesis templates. Their normative grammar,
window boundaries, capture schema, and instruction-range requirements are
documented in the README's Directional searches section. They return all
matching starts, not a nearest-only selection. The analysis snapshot's instruction
ranges can supply `after` boundaries; no concrete analysis adapter is implemented
by this addition. Automatic discovery or ranking of directional templates remains
future work.
