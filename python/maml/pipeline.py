"""maml.pipeline -- a small language for FINDING an address.

Composed from the substrate `maml.generate` already derives: the string
table, the rip-relative index, the call graph, and function bounds. Every
stage maps a set of addresses to a set of addresses, and a pipeline is stages
composed left to right with `->`:

    from maml import Image, pipeline

    img = Image.from_pe("Wow.exe")          # fills code / rodata / funcs
    r = pipeline.run(img, 'str "GetActivePlayerObj" -> xref -> func -> unique')
    if r.ok:
        address = r.addresses[0]

Stages: `str "text"`, `bytes "<pattern>"`, `find "<pattern>"`, `xref`,
`callers`, `func`, `unique`, `nth K`, `limit N`, `read N`. See
include/maml/pipeline.hpp for the semantics
-- in particular that `ok` means "ended with at least one address" (finding
nothing is not an error, while a failing `unique` is), and that `trace`
carries the set size after every stage so a caller can see whether its single
answer was ever one of several.

`find` is the filter `bytes` is not: it searches only the function enclosing
each incoming address, so its pattern need only be unique THERE. `read N`
loads N little-endian bytes at each address and is terminal -- the result is
values, and `r.kind` says so:

    r = pipeline.run(img, 'str "Aura" -> xref -> func '
                          '-> find "F7 80 \' ? ? 00 00" -> read 4')
    assert r.kind == "value"
    offset = r.addresses[0]                 # a structure field offset

This is a discovery aid: it finds an address to hand to `generate.verified()`.
Nothing here says how a pipeline holds up across a rebuild; that is
unmeasured.
"""

from maml._core import (
    PipelineResult,
    StageResult,
    pipeline_run as run,
)

__all__ = ["PipelineResult", "StageResult", "run"]
