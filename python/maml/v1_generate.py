"""Semantic pattern generation and two-build nibble generalization.

Targets and metadata are buffer-relative offsets. Nibble masks are inferred
only by verified(), and every returned candidate is checked in both images.
"""
from dataclasses import dataclass
from . import generate as _engine
from ._core import Image as _Image
from ._containers import Range

Strategy = _engine.Strategy
Resolution = _engine.Resolution


@dataclass(frozen=True)
class Options:
    max_len: int = 64
    want: int = 4
    prefer_short: bool = True
    deep_anchor: bool = True
    nibble_wildcards: bool = True


@dataclass(frozen=True)
class Candidate:
    pattern: str
    strategy: object
    anchor_site: int
    anchor_delta: int = 0
    target_capture: str = ''
    dialect: str = 'maml-v1'
    literals: int = 0


def _image(image):
    if image.base != 0:
        raise ValueError('Generation uses buffer-relative targets; image.base must be zero')
    result = _Image.from_bytes(image.data)
    for field in ('code','rodata','funcs'):
        setattr(result,field,[Range(begin,end) for begin,end in getattr(image,field)])
    return result


def _options(opt):
    if opt is None:
        opt=Options()
    if not 0 <= opt.want <= 256 or not 1 <= opt.max_len <= 65536:
        raise ValueError('want must be 0..256 and max_len must be 1..65536')
    return _engine.Options(max_len=opt.max_len,want=opt.want,prefer_short=opt.prefer_short,
                           deep_anchor=opt.deep_anchor,dialect='maml-v1',nibble_wildcards=opt.nibble_wildcards)


def _wrap(candidate):
    return Candidate(candidate.pattern,candidate.strategy,candidate.anchor_site,
                     candidate.anchor_delta,candidate.target_capture,candidate.dialect,candidate.literals)


def candidates(image,target,opt=None):
    """Generate semantic anchors from one image; no variation is inferred."""
    return [_wrap(c) for c in _engine.candidates(_image(image),target,_options(opt))]


def verified(a,target_a,b,target_b,opt=None):
    """Return candidates uniquely resolving to each supplied target in both builds."""
    return [_wrap(c) for c in _engine.verified(_image(a),target_a,_image(b),target_b,_options(opt))]


def resolve_consensus(image,candidates):
    """Group uniquely resolved semantic candidates; ambiguous matches do not vote."""
    inputs=[]
    for c in candidates:
        if c.dialect != 'maml-v1':
            raise ValueError('Expected a maml-v1 candidate')
        inputs.append(_engine.Candidate(pattern=c.pattern,save_index=0,anchor_delta=c.anchor_delta,
                                        anchor_site=c.anchor_site,strategy=c.strategy,literals=c.literals,
                                        seed=None,dialect=c.dialect,target_capture=c.target_capture))
    return _engine.resolve_consensus(_image(image),inputs)
