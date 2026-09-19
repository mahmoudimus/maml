# Proposal: references to code addresses

Status: proposed contract. This document does not establish implementation or
release status. The published behavior at `6503b61` finds direct calls for code
targets and indexed RIP-relative LEAs for rodata targets.

## Motivation

Callback registration often takes a native function's address with a LEA and
passes it to a registrar. That instruction references the function without
calling it. Restricting `xrefs` on code targets to direct calls hides this common
relationship even though the existing LEA index can search for code addresses.

## Proposed contract

- `xrefs` returns all reference sites supported by the implementation for each
  input target. For code targets, the initial supported set is the union of
  direct `E8 rel32` calls and RIP-relative LEAs that resolve to the target.
- `callers` continues to return direct `E8 rel32` call sites only.
- Rodata targets retain the existing indexed RIP-relative LEA behavior.
- Results are the referencing instruction's start address, include the image
  base, and are sorted and deduplicated across targets and reference kinds.
- Existing metadata requirements, address-space checks, and errors for targets
  in neither code nor rodata remain unchanged. `callers` retains its existing
  target handling; this proposal changes only `xrefs` on code targets.
- No modifier is introduced. Textual `xrefs` and both builders' `.xrefs()` use
  the same contract. Filtering by reference kind can be considered separately
  when a concrete use case requires it.

"All" means all supported reference encodings, not a complete disassembler
cross-reference graph. The initial implementation reuses the existing indexed
x86-64 RIP-relative LEA forms. It does not add indirect calls, pointer-table
entries, immediate-address loads, jumps, conditional branches, or dataflow
analysis. Byte scanning also does not prove instruction boundaries. Analysis
adapters may supply stronger evidence in a separate extension.

## Example: native function and callback registration

Locate the implementation using its usage string:

```text
str("Usage: C_WeeklyRewards.ClaimReward", match="contains")
    -> xrefs
    -> func
    -> unique
```

`contains` returns the enclosing indexed string's start, so it can match
`Usage: C_WeeklyRewards.ClaimReward(id)`. Given an unambiguous reference in the
native implementation, `func` returns its owning entry, including references in
chained fragments. An analysis adapter can name that entry
`C_WeeklyRewards_ClaimReward`; the registration hop is not required for this
rename. Ambiguity must be inspected, not hidden with `nth(0)`.

To locate references to that implementation, append:

```text
str("Usage: C_WeeklyRewards.ClaimReward", match="contains")
    -> xrefs
    -> func
    -> unique
    -> xrefs
```

Under this proposal the second `xrefs` includes the LEA taking the function's
address for registration, as well as any supported direct calls. It returns
reference sites, not registrar call sites. Appending `func` locates the functions
containing those references; it does not identify the registrar callee.

Identifying a subsequent call as `register_lua_namespace_function` requires
additional evidence connecting the native-function address and the namespace
and function-name arguments to that call. A nearby call alone is insufficient:
register values may be overwritten and control flow may diverge. Bounded
`after(...)` searches can discover candidates when instruction metadata is
available, but do not establish argument flow. Renaming remains an explicit
analysis-adapter action after validation, not a new MAML mutation stage.

## Compatibility and implementation

This is a behavioral expansion with unchanged grammar and builder signatures.
Existing `xrefs` pipelines may produce additional results, causing `unique` to
fail or changing which address `nth(0)` selects. Consumers that specifically
need direct calls should use `callers`.

The executor should gather direct calls for code targets and include those same
targets in the existing batched LEA index lookup. It should retain final sorting
and deduplication and avoid a separate whole-image LEA scan for every target.
No pattern matcher changes or instruction-aware pattern syntax are required.

Before release, update the README's reference semantics and examples, document
the cardinality change, and verify equivalent execution through C++, Python,
both builders, and the pipeline CLI.

## Acceptance cases

1. A code target referenced by both an E8 call and a RIP-relative LEA returns
   both sites through `xrefs`; `callers` returns only the call.
2. A code target referenced only by LEA yields a nonempty `xrefs` result and an
   empty `callers` result.
3. References with positive and negative displacements and supported REX/register
   variants resolve correctly; unrelated LEAs are excluded.
4. Repeated targets or overlapping scan ranges do not duplicate output sites;
   outputs are sorted and correct with a nonzero image base.
5. Rodata string references and missing/invalid metadata retain their existing
   behavior. Truncated instructions never yield references.
6. The usage-string example reaches the native entry, then the address-taking
   registration site, including when the string reference is in a separated
   function span. Intervening functions remain distinct.
7. Adding an address-taking reference can make `xrefs -> unique` fail, while
   `callers -> unique` still succeeds when there is exactly one direct call.
8. Native pipeline execution, Python execution, textual/builder equivalents,
   and CLI integration agree on returned addresses and cardinality.
