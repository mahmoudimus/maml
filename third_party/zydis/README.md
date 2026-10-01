# Bundled instruction decoder

Zydis 4.1.1 (`a2278f1d254e492f6a6b39f6cb5d1f5d515659dc`) and its pinned
Zycore 1.5.2 (`0b2432ced0884fd152b471d97ecf0258ff4d859f`) provide the
optional x86-64 instruction stage. Sources originate from
https://github.com/zyantific/zydis and https://github.com/zyantific/zycore-c.

Headers, decoder sources, generated tables, and license notices are copied
unchanged. Encoder/formatter implementations, examples, and tools are omitted.
Decoding uses Zycore's headers without its allocator, containers, or OS APIs;
those implementations are neither bundled nor linked.
`sources.json` is shared by CMake and setuptools. Both builds disable encoder
and formatter features and link a static library, without downloading packages
or requiring a system installation. See LICENSE and dependencies/zycore/LICENSE.
