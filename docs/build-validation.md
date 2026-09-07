# Build validation, 2026-09-07

Host: macOS arm64, AppleClang 21, CPython 3.13.15. Package version: 0.1.0.

| Check | Result |
| --- | --- |
| CMake Release build, including tools and generator harnesses | Passed |
| C++ tests | 203 cases, 1,674 assertions passed |
| Python suite including Cython and conformance-runner tests, editable installation | 468 passed, no skips |
| Same suite, wheel built from sdist in separate environment | 468 passed, no skips |
| Installed wheel verification from `/tmp` | `site-packages` import, matching version, NEON, hit at offset 64 |
| CMake installed `find_package` consumer | Built and ran |
| CMake `add_subdirectory` consumer | Built and ran |
| GitHub workflows, `actionlint` | Passed |
| Distribution layout | One native extension, under `maml/` |
| Language-neutral conformance data | 60 vectors validate; no v1 implementation was tested |
| Conformance transport tests from extracted sdist | 17 passed |
| Renamed durability targets | All three `maml.durability.*` executables built |

Commands used:

```sh
.venv/bin/python tools/build.py --python-tests --jobs 6
./build/maml_tests --reporter compact
.venv/bin/python -m build --outdir dist
uv pip install --python .venv-wheel/bin/python --reinstall-package maml dist/maml-0.1.0.tar.gz pytest lief
cmake --install build --prefix build/install
actionlint .github/workflows/*.yml
python tools/check_conformance.py
```

The artifact environment ran `tools/verify_wheel.py --expect-simd neon` and
`python -m pytest /path/to/maml/tests/python -q -o pythonpath=` from `/tmp`.
This avoids testing the editable package in place of the installed artifact.

The [conformance vectors](../conformance/README.md) for the new semantic dialect
are separate from implementation testing. These results establish the engine,
bindings, generator, build setup, and conformance transport;
they do not claim implementation of `rel32(name):follow` or named captures.
Remote Windows/Linux CI and real-image durability runs were not executed.
