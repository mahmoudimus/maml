# Durability tools

These executables compare pattern behavior across multiple builds of a binary:

- `maml.durability.measure`: generate patterns and measure uniqueness survival.
- `maml.durability.resolve`: resolve generated patterns against another build.
- `maml.durability.pipeline`: evaluate pipeline survival across builds.

CMake builds these tools with `MAML_BUILD_TOOLS=ON`. Execution requires external
binary images and matching metadata; those fixtures are not distributed here.
`MAML_DURABILITY_DIR` selects the fixture directory (default `/tmp/eido`).

Positional arguments:

```text
maml.durability.measure [sample=150] [want=4] [build_a=69382] [build_b=69404] [build_c=69273] [build_d=69497]
maml.durability.resolve [sample=300] [want=16] [min_confidence=0.5]
maml.durability.pipeline [cap=400] [min_confidence=0.95]
```

The resolve and pipeline harnesses currently use fixed fixture identifiers
`69404`, `69382`, and `69497deob`, plus `map.txt`. They are fixture-driven
measurement tools, not general-purpose binary loaders. On Windows the
executable filenames have the additional `.exe` suffix.
