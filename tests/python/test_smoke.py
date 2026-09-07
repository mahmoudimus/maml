"""The toolchain works end to end: uv -> Cython -> C++20 -> import."""
import pytest

import maml
from maml import _core


def test_cpp_version_matches_the_headers():
    # Pinned to the same values tests/test_seed_selection.cpp asserts, so the
    # two suites cannot drift about which library was compiled in.
    assert _core.cpp_version() == (0, 1, 0)


def test_package_version_is_derived_from_the_headers():
    assert maml.__version__ == "0.1.0"


def test_the_declared_version_matches_the_compiled_one():
    """pyproject.toml and the C++ macros are two sources of truth for one number.

    The other two tests compare each against a literal, which cannot catch them
    drifting from EACH OTHER. This can. It needs the package installed, which is
    what `uv pip install -e .` provides.
    """
    from importlib.metadata import PackageNotFoundError, version
    try:
        declared = version("maml")
    except PackageNotFoundError:
        pytest.skip("needs an install: uv pip install -e . --python .venv/bin/python")
    assert declared == maml.__version__


def test_simd_backend_names_a_known_backend():
    """The extension reports which vector path it compiled in.

    Not cosmetic: mamlscan.hpp falls back to a correct memchr scan when the
    preprocessor selects no vector path, so a build that lost SIMD passes every
    other test here while running ~1.9x slower. This is the only thing that can
    see the difference, and CI turns it into a per-platform assertion via
    tools/verify_wheel.py --expect-simd.
    """
    assert maml.simd_backend() in ("neon", "sse2", "scalar")


def test_simd_backend_is_exported():
    assert "simd_backend" in maml.__all__
    assert maml.simd_backend is maml._core.simd_backend
