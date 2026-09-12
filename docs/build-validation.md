# Build validation, 2026-09-07

Host: macOS arm64, AppleClang 21, CPython 3.13.15. Package version: 0.1.0.

Function-modifier follow-up: the rebuilt native extension passes 572 Python
tests and 210 C++ cases (1,957 assertions), plus the 60 conformance vectors.
CLI checks confirm that `func:strict` rejects a mixed entry/interior input and
`func:loose` maps it to the enclosing entry. Package and sanitizer results below
are from the preceding generator validation, before this modifier change.

| Check | Result |
| --- | --- |
| CMake build, including scanner, pipeline, and durability tools | Passed |
| C++ suite | 209 cases, 1,949 assertions passed |
| Python suite, editable installation | 557 passed, no skips |
| Python suite, installed wheel rebuilt from the source distribution | 557 passed, no skips |
| MAML v1 JSONL adapter | All 60 unchanged conformance vectors passed in both environments |
| Native v1 tests under AddressSanitizer and UndefinedBehaviorSanitizer | 6 cases, 275 assertions passed |
| Installed wheel verification from `/tmp` | `site-packages` import, matching version, NEON, scanning and named-capture pipeline passed |
| README Python examples | Passed |
| README C++ examples against installed headers | Compiled and ran |
| GitHub workflows, `actionlint` | Passed |
| Distribution layout | One native extension; semantic headers, Python module, adapter, and Cython include shipped |
| Private file exclusion | No `_gitless` or `docs/spec` entries in distributions |

Commands used:

```sh
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
build/maml_tests --reporter compact
.venv/bin/python -m pytest tests/python -q
.venv/bin/python tools/check_conformance.py --adapter .venv/bin/python -m maml.v1_adapter
uv build --offline --out-dir /tmp/maml-v1-dist
uv pip install --offline --python /tmp/maml-v1-wheel-env/bin/python /tmp/maml-v1-dist/maml-0.1.0.tar.gz pytest lief
cmake --install build --prefix /tmp/maml-v1-install
actionlint .github/workflows/*.yml
```

The artifact environment ran `tools/verify_wheel.py --expect-simd neon`, the
full Python suite with `-o pythonpath=`, and the conformance adapter from `/tmp`.
That checks the installed artifact rather than the editable source package.

The conformance vectors exercise the semantic frontend through the native
extension. Separate tests cover complete pipelines, CLI dialect selection,
and seeded/exhaustive equivalence. These are bounded correctness checks;
they do not establish complete language coverage or real-image durability.
Semantic generation, named target selection, and paired-build nibble inference
are covered by the generator tests. Both nibble positions are tested for all
16 masks against all 256 byte values, with and without fixed literal seeds. Remote Windows/Linux CI and
cross-build durability runs were not executed during this change.

Pipeline builder follow-up: Python and C++ fluent builders use the existing v1
compiler. After rebuilding the C++ targets and Cython extension, all 580 Python
tests, 212 C++ cases (1969 assertions), and 60 conformance vectors passed.
CLI smoke checks resolved a followed reference with a nibble wildcard through
`mamlscan --dialect maml-v1`, and ran builder-generated and multiline source
through `mamlpipe --dialect maml-v1` with named projection and `func:strict`.
The installed-package and sanitizer results above predate this builder addition.

## Directional pipelines

On the checkout based on `e972280`, after rebuilding C++ tools and the Cython
extension, directional pipeline verification passed: 205 Python tests, 129 C++
cases (788 assertions), and all 60 existing conformance vectors. The 12 dedicated
Python directional tests cover both window directions, exact boundaries,
multiple results, base addresses, capture schemas, gap/alternative backtracking,
followed-reference endpoints, large-image bounded searches, invalid arguments,
and instruction metadata. CLI smoke checks returned two `after` matches and one
adjacent `before` match using an `instruction A B` manifest entry.

The conformance JSONL vectors still cover the existing matcher/projection
protocol; directional pipeline behavior is covered by the C++ and Python tests,
not those 60 vectors. Older test totals above predate removal of the unversioned
dialect. Installed-wheel and sanitizer verification were not repeated for this
change.
