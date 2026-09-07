"""Byte-pattern matching for binaries."""
from maml._containers import Range
from maml._core import (Hit, Image, Pattern, PatternError, Primed, Seed,
                             cpp_version, simd_backend)

__version__ = "%d.%d.%d" % cpp_version()

__all__ = ["cpp_version", "simd_backend", "Hit", "Image", "Pattern",
           "PatternError", "Primed", "Range", "Seed", "__version__"]
