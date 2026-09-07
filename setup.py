"""Build the maml Cython extension.

Shaped after ida-sigmaker's setup.py with two deliberate departures: there is
no IDA SDK branch (that repo's shipped extension does not use one either), and
this needs C++20. Because maml is header-only there is nothing to link, so
none of sigmaker's library_dirs / rpath handling is required.
"""

import os
import pathlib
import platform
import sys

from Cython.Build import cythonize
from setuptools import Extension, setup

ROOT = pathlib.Path(__file__).parent
DEBUG = os.environ.get("DEBUG", "0") == "1"


def compile_args() -> list[str]:
    if platform.system() == "Windows":
        return ["/std:c++20", "/EHsc"]
    args = ["-std=c++20"]
    if DEBUG:
        args += ["-O0", "-g"]
    return args


def macros() -> list[tuple[str, str | None]]:
    if not DEBUG:
        return []
    # Cython emits line-trace hooks only under these, which is what lets
    # coverage.py see inside the .pyx at all.
    m = [("CYTHON_TRACE", "1"), ("CYTHON_CLINE_IN_TRACEBACK", "1")]
    if sys.version_info >= (3, 13):
        m.append(("CYTHON_USE_SYS_MONITORING", "1"))
    if sys.version_info < (3, 12):
        m.append(("CYTHON_PROFILE", "1"))
    return m


setup(
    ext_modules=cythonize(
        Extension(
            "maml._core",
            ["python/maml/_core.pyx"],
            language="c++",
            include_dirs=[str(ROOT / "include")],
            extra_compile_args=compile_args(),
            define_macros=macros(),
        ),
        compiler_directives={
            "language_level": "3",
            "binding": True,
            "embedsignature": True,
            "boundscheck": False,
            "wraparound": False,
            "profile": DEBUG,
            "linetrace": DEBUG,
        },
        annotate=DEBUG,
    ),
)
