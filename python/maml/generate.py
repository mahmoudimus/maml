"""maml.generate -- the inverse of matching.

Given an image and a target address, emit patterns that find that address
again in a later, independent compilation. This is a thin re-export of the
Cython/C++ glue in `maml._core` (which is where the buffer pinning and
the C++ struct marshalling actually happen) under its own submodule, kept
separate from the top-level `maml` namespace: `maml.Range` and
`maml.Image` are reused as-is (Image gained `code`, `rodata` and `funcs`
attributes for this), everything else generation-specific lives here.

    from maml import generate
    cands = generate.candidates(image, target)
    verified = generate.verified(image_a, target_a, image_b, target_b)
    groups = generate.resolve_consensus(image_b, verified)

See include/maml/generate.hpp for the semantics -- in particular why
`verified()` is the one to use (72% durability against a build one minor
version away, vs. 33% for `candidates()` alone) and why `resolve_consensus()`
is the shape a caller should read by default rather than a bare address
(two or more anchors agreeing were correct 25 times out of 25 in the
measurement that motivated it; a single clean hit was wrong 5-13% of the
time).
"""

from maml._core import (
    Candidate,
    Options,
    Resolution,
    Strategy,
    generate_candidates as candidates,
    generate_resolve_consensus as resolve_consensus,
    generate_verified as verified,
)

__all__ = [
    "Candidate",
    "Options",
    "Resolution",
    "Strategy",
    "candidates",
    "resolve_consensus",
    "verified",
]
