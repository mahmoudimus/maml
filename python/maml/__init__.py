"""Byte-pattern matching for binaries."""
from maml._core import cpp_version, simd_backend
from maml.v1 import (
    CaptureValue,
    CardinalityError,
    CompileError,
    ExecutionError,
    Image,
    Match,
    Pattern,
    Pipeline,
    PipelineBuilder,
    PipelineResult,
    SchemaError,
    StageResult,
    generate,
    project,
    unique_matches,
)
from . import v1
from maml._containers import Range, Function

__version__ = "%d.%d.%d" % cpp_version()

__all__ = [
    "CaptureValue",
    "CardinalityError",
    "CompileError",
    "ExecutionError",
    "Image",
    "Match",
    "Pattern",
    "Pipeline",
    "PipelineBuilder",
    "PipelineResult",
    "Range",
    "Function",
    "SchemaError",
    "StageResult",
    "cpp_version",
    "generate",
    "project",
    "simd_backend",
    "unique_matches",
    "v1",
    "__version__",
]
