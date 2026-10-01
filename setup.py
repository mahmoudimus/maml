"""Build the C++20 Cython extension with an optional bundled static decoder."""

import os
import pathlib
import platform
import sys
import json

from Cython.Build import cythonize
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

ROOT = pathlib.Path(__file__).parent
DEBUG = os.environ.get("DEBUG", "0") == "1"

# Static bundled sources make wheels/sdists independent of Homebrew, rpaths,
# system packages, and external DLLs. Opt out with MAML_ENABLE_INSN=0.
ENABLE_INSN = os.environ.get("MAML_ENABLE_INSN", "1").lower() not in {"0", "off", "false"}
DECODER = ROOT / "third_party" / "zydis"
DECODER_INCLUDES = [str(DECODER / "include"), str(DECODER / "dependencies" / "zycore" / "include")]
DECODER_MACROS = [(name, "1") for name in ("ZYDIS_STATIC_BUILD", "ZYCORE_STATIC_BUILD",
                                           "ZYDIS_DISABLE_ENCODER", "ZYDIS_DISABLE_FORMATTER")]
DECODER_DEPENDS = sorted(str(p.relative_to(ROOT)) for p in DECODER.rglob('*')
                         if p.suffix in {'.h', '.inc', '.c', '.json'})
HEADER_DEPENDS = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'include').rglob('*.hpp'))
DECODER_LIBRARIES = [("maml_decoder", {
    "sources": [str(pathlib.Path("third_party/zydis") / name) for name in json.loads((DECODER / "sources.json").read_text())],
    "include_dirs": [*DECODER_INCLUDES, str(DECODER / "src")],
    "macros": DECODER_MACROS,
    "obj_deps": {'': DECODER_DEPENDS},
})] if ENABLE_INSN else []


class BuildExtension(build_ext):
    def run(self):
        # Distutils does not include changed macro/flag values in its cache key.
        stamp = pathlib.Path(self.build_lib) / '.maml-build-profile'
        profile = f'insn={int(ENABLE_INSN)};debug={int(DEBUG)}'
        if not stamp.exists() or stamp.read_text() != profile:
            self.force = True
        # Direct build_ext --inplace must work on a fresh checkout too.
        if self.distribution.has_c_libraries():
            self.run_command('build_clib')
        super().run()
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(profile)


def compile_args() -> list[str]:
    if platform.system() == "Windows":
        return ["/std:c++20", "/EHsc"]
    args = ["-std=c++20"]
    if DEBUG:
        args += ["-O0", "-g"]
    return args


def macros() -> list[tuple[str, str | None]]:
    base = [("MAML_ENABLE_INSN", "1" if ENABLE_INSN else "0")] + (DECODER_MACROS if ENABLE_INSN else [])
    if not DEBUG:
        return base
    # Cython emits line-trace hooks only under these, which is what lets
    # coverage.py see inside the .pyx at all.
    m = base + [("CYTHON_TRACE", "1"), ("CYTHON_CLINE_IN_TRACEBACK", "1")]
    if sys.version_info >= (3, 13):
        m.append(("CYTHON_USE_SYS_MONITORING", "1"))
    if sys.version_info < (3, 12):
        m.append(("CYTHON_PROFILE", "1"))
    return m


setup(
    cmdclass={'build_ext': BuildExtension},
    libraries=DECODER_LIBRARIES,
    ext_modules=cythonize(
        Extension(
            "maml._core",
            ["python/maml/_core.pyx"],
            language="c++",
            include_dirs=[str(ROOT / "include"), *(DECODER_INCLUDES if ENABLE_INSN else [])],
            extra_compile_args=compile_args(),
            define_macros=macros(),
            depends=[*HEADER_DEPENDS, *(DECODER_DEPENDS if ENABLE_INSN else [])],
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
