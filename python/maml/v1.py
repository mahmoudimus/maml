"""MAML v1: explicit semantic patterns, typed captures, and locator pipelines.

Importing this module selects the ``maml-v1`` dialect. No syntax guessing occurs.
All pattern/pipeline parsing and binary execution run in the C++ frontend.
"""
from dataclasses import dataclass
from types import MappingProxyType
from maml._core import NativePattern, NativePipeline

DIALECT = "maml-v1"

class CompileError(ValueError):
    def __init__(self, code, message, position=0):
        self.code = code
        self.position = position
        super().__init__(message)

class SchemaError(CompileError):
    pass

class CardinalityError(ValueError):
    pass

class ExecutionError(ValueError):
    def __init__(self, code, message, position=0):
        self.code = code
        self.position = position
        super().__init__(message)


def _native(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except ValueError as exc:
        if len(exc.args) != 3:
            raise
        code, message, position = exc.args
        if code == 'UnknownCapture':
            raise SchemaError(code, message, position) from exc
        if code == 'Cardinality':
            raise CardinalityError(message) from exc
        if code in {'MissingMetadata', 'ResourceLimit', 'NotFunctionEntry'}:
            raise ExecutionError(code, message, position) from exc
        raise CompileError(code, message, position) from exc


def _u64(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xffffffffffffffff:
        raise ValueError('Expected an unsigned 64-bit integer')
    return value


@dataclass(frozen=True, order=True)
class CaptureValue:
    value: int
    kind: str
    space: str

    def __post_init__(self):
        _u64(self.value)


@dataclass(frozen=True)
class Match:
    offset: int
    schema: tuple
    captures: object

    def __post_init__(self):
        _u64(self.offset)
        object.__setattr__(self, 'schema', tuple(self.schema))
        object.__setattr__(self, 'captures', MappingProxyType(dict(self.captures)))

    def capture(self, name):
        if name not in self.schema:
            raise SchemaError('UnknownCapture', f'Unknown capture: {name}')
        return self.captures.get(name)


def project(schema, matches, name, *, unique=False):
    if name not in schema:
        raise SchemaError('UnknownCapture', f'Unknown capture: {name}')
    values = sorted({m.captures[name] for m in matches if name in m.captures})
    if unique and len(values) != 1:
        raise CardinalityError('unique requires exactly one value')
    return values


def unique_matches(matches):
    if len(matches) != 1:
        raise CardinalityError('unique requires exactly one match')
    return matches[0]


def _matches(raw, schema):
    return [Match(offset, schema, {n:CaptureValue(*v) for n,v in captures.items()})
            for offset,captures in raw]


class Image:
    """Immutable byte snapshot with logical base, explicit pointer map, and RVA ranges."""
    def __init__(self, data, *, base=0, pointer_map=None, code=(), rodata=(), funcs=()):
        self.data = bytes(data)
        self.base = _u64(base)
        self.pointer_map = {_u64(k):_u64(v) for k,v in (pointer_map or {}).items()}
        def ranges(items):
            result=[]
            for item in items:
                begin,end = (item.begin,item.end) if hasattr(item,'begin') else item
                _u64(begin); _u64(end)
                if not begin <= end <= len(self.data):
                    raise ValueError('Ranges must be half-open offsets within the image')
                result.append((begin,end))
            return tuple(result)
        self.code, self.rodata, self.funcs = ranges(code), ranges(rodata), ranges(funcs)

    @classmethod
    def from_file(cls, path, **kwargs):
        with open(path, 'rb') as f:
            return cls(f.read(), **kwargs)

    @classmethod
    def from_pe(cls, path, **kwargs):
        from ._containers import flatten_pe
        data, sections, code, rodata, funcs = flatten_pe(path)
        return cls(data, code=code, rodata=rodata, funcs=funcs, **kwargs)


class Pattern:
    dialect = DIALECT
    def __init__(self, text):
        self._native = _native(NativePattern, text)

    @property
    def schema(self):
        return self._native.schema

    def match_at(self, image, start_offset=0):
        raw = _native(self._native.scan, image.data, image.base, image.pointer_map,
                      start=_u64(start_offset))
        hits = _matches(raw, self.schema)
        return hits[0] if hits else None

    def find_all(self, image, *, limit=0, exhaustive=False):
        _u64(limit)
        raw = _native(self._native.scan, image.data, image.base, image.pointer_map,
                      limit=limit, exhaustive=exhaustive)
        return _matches(raw, self.schema)

    def find(self, image):
        hits = self.find_all(image, limit=1)
        return hits[0] if hits else None


@dataclass(frozen=True)
class StageResult:
    stage: str
    into: int
    out: int


@dataclass(frozen=True)
class PipelineResult:
    kind: str
    schema: tuple
    matches: tuple
    values: tuple
    trace: tuple

    @property
    def ok(self):
        return bool(self.matches if self.kind == 'matches' else self.values)


class Pipeline:
    dialect = DIALECT
    def __init__(self, source):
        self._native = _native(NativePipeline, source)

    def run(self, image):
        is_matches,schema,raw,values,trace = _native(
            self._native.run, image.data, image.base, image.pointer_map,
            image.code, image.rodata, image.funcs)
        return PipelineResult('matches' if is_matches else 'values',schema,
                              tuple(_matches(raw,schema)),tuple(CaptureValue(*v) for v in values),
                              tuple(StageResult(*t) for t in trace))

# Keep generation under the same explicit dialect entry point.
from . import v1_generate as generate


def _quote_pipeline_argument(value):
    if not isinstance(value, str):
        raise TypeError('Pipeline arguments must be strings')
    out = ['"']
    for char in value:
        if char in ('"', '\\'):
            out.append('\\' + char)
        elif char == '\n':
            out.append('\\n')
        elif char == '\t':
            out.append('\\t')
        elif ord(char) < 32 or ord(char) == 127:
            out.append(f'\\x{ord(char):02X}')
        else:
            out.append(char)
    out.append('"')
    return ''.join(out)


@dataclass(frozen=True)
class PipelineBuilder:
    """Immutable fluent builder; build() uses the same compiler as pipeline text.

    Reuse a prefix safely: each stage method returns a new builder. Arguments
    are quoted, not interpreted as stage text. Validation occurs at build().
    """
    _stages: tuple = ()

    @property
    def source(self):
        return ' -> '.join(self._stages)

    def _append(self, stage):
        return PipelineBuilder(self._stages + (stage,))

    def str(self, text):
        return self._append('str(' + _quote_pipeline_argument(text) + ')')

    def bytes(self, pattern):
        return self._append('bytes(' + _quote_pipeline_argument(pattern) + ')')

    def find(self, pattern):
        return self._append('find(' + _quote_pipeline_argument(pattern) + ')')

    def capture(self, name):
        return self._append('capture(' + _quote_pipeline_argument(name) + ')')

    def xrefs(self):
        return self._append('xrefs')

    def callers(self):
        return self._append('callers')

    def func(self, *, strict=None):
        if strict is not None and not isinstance(strict, bool):
            raise TypeError('strict must be True, False, or None')
        return self._append('func' if strict is None else 'func:strict' if strict else 'func:loose')

    def unique(self):
        return self._append('unique')

    def nth(self, index):
        return self._append(f'nth({_u64(index)})')

    def limit(self, count):
        return self._append(f'limit({_u64(count)})')

    def read(self, width):
        return self._append(f'read({_u64(width)})')

    def build(self):
        return Pipeline(self.source)
