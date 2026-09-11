# Changelog

All notable user-visible changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-11

### Added

- **First public release of MAML (Mahmoud's Address Matching Language).** Byte-oriented patterns describe bytes, gaps, captures, and references. Pipelines transform matches and address sets. The unversioned runtime grammar is unchanged; there is no automatic dialect detection.
- **Semantic v1 matching, generation, and pipeline APIs.** Select the dialect with `maml::v1`, `maml.v1`, or `--dialect maml-v1`. Matching and pipeline execution run in C++ with the GIL released. The implementation passes the 60 supplied v1 conformance vectors; those finite cases do not establish complete language coverage.
- **Python distribution `maml-python` on PyPI.** The import package remains `maml` (`maml` on PyPI is an unrelated project). A `vX.Y.Z` tag builds through `.github/workflows/wheels.yml` and publishes with trusted publishing from `.github/workflows/deploy.yml`.
- **C++ scanner and pipeline CLIs** (`mamlscan`, `mamlpipe`) plus SIMD seed scanning on NEON and SSE2, with a correct memchr fallback when no vector path is selected.

[Unreleased]: https://github.com/mahmoudimus/maml/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mahmoudimus/maml/releases/tag/v0.1.0
