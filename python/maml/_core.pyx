# cython: language_level=3
"""Cython bindings for maml's C++ matcher."""

import enum
from dataclasses import dataclass

cimport cython

from libc.stdint cimport uint8_t, uint64_t, int64_t, SIZE_MAX
from cpython.buffer cimport (PyObject_GetBuffer, PyBuffer_Release,
                             PyBUF_SIMPLE)


cdef extern from "maml/version.hpp":
    int MAML_VERSION_MAJOR
    int MAML_VERSION_MINOR
    int MAML_VERSION_PATCH

def cpp_version():
    """(major, minor, patch) of the C++ headers this extension compiled against."""
    return (MAML_VERSION_MAJOR, MAML_VERSION_MINOR, MAML_VERSION_PATCH)


# Which vector path mamlscan.hpp actually compiled in. The scan has a working
# memchr fallback, so a build where neither macro gets defined stays CORRECT
# and merely loses ~1.9x -- every test passes and nothing says a word. That
# makes the backend invisible exactly where it matters most: in a published
# wheel, built on a machine nobody watched. Exposing it lets CI assert the
# wheel it is about to upload really carries SIMD, per platform.
#
# Read through a verbatim C++ shim rather than by editing the headers:
# mamlscan.hpp is vendored by a downstream project that copies it, so it stays
# byte-identical to what that project has.
cdef extern from *:
    """
    #include "maml/mamlscan.hpp"
    static const char* maml_simd_backend_name() {
    #if defined(MAML_SIMD_NEON)
        return "neon";
    #elif defined(MAML_SIMD_SSE2)
        return "sse2";
    #else
        return "scalar";
    #endif
    }
    """
    const char* maml_simd_backend_name()


def simd_backend():
    """The vector backend compiled into this extension: 'neon', 'sse2' or 'scalar'.

    'scalar' is a correct build, just a slower one -- it means the preprocessor
    selected no vector path for this target.
    """
    return maml_simd_backend_name().decode("ascii")


# Cython's default `except +` maps any C++ exception to RuntimeError and
# discards its payload. generate.hpp throws maml::v1::Error.
cdef extern from *:
    """
    #include <Python.h>
    #include "maml/v1.hpp"
    extern "C" void raise_pattern_error() {
        try {
            throw;
        } catch (const maml::v1::Error& e) {
            PyErr_SetString(PyExc_ValueError, e.what());
        } catch (const std::bad_alloc&) {
            PyErr_NoMemory();
        } catch (const std::exception& e) {
            PyErr_SetString(PyExc_RuntimeError, e.what());
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError, "unknown C++ exception");
        }
    }
    """
    void raise_pattern_error()


cdef class Image:
    """A flat, RVA-indexed image. Holds its buffer pinned for its lifetime."""

    def __cinit__(self):
        self._has_view = False
        self.size = 0
        self.base = 0
        self.sections = []
        self.code = []
        self.rodata = []
        self.funcs = []

    def __init__(self, *args, **kwargs):
        raise TypeError(
            "Image cannot be constructed directly; use Image.from_bytes "
            "or Image.from_file"
        )

    def __dealloc__(self):
        if self._has_view:
            PyBuffer_Release(&self._view)
            self._has_view = False

    cdef const uint8_t* _data(self) noexcept nogil:
        return <const uint8_t*>self._view.buf

    @staticmethod
    def from_bytes(buf, base=0):
        """Wrap any buffer zero-copy. The buffer is pinned until the Image dies."""
        cdef Image img = Image.__new__(Image)
        PyObject_GetBuffer(buf, &img._view, PyBUF_SIMPLE)
        img._has_view = True
        img.size = <size_t>img._view.len
        img.base = base
        return img

    @staticmethod
    def from_file(path, base=0):
        """Read a flat image from disk into memory. The common case: an
        already-flat dump."""
        with open(path, "rb") as fh:
            return Image.from_bytes(fh.read(), base)

    @staticmethod
    def from_pe(path):
        """Flatten a PE's sections to their virtual addresses. Needs maml[pe].

        Also fills `code` and `rodata` from section characteristics (executable
        -> code; initialised, non-executable data -> rodata) and `funcs` from
        `.pdata` when present -- see _containers.flatten_pe.
        """
        from maml._containers import flatten_pe
        data, ranges, code, rodata, funcs = flatten_pe(path)
        img = Image.from_bytes(data)
        img.sections = ranges
        img.code = code
        img.rodata = rodata
        img.funcs = funcs
        return img

    def to_va(self, rva):
        """Image-relative offset -> virtual address."""
        return self.base + rva

    def __len__(self):
        return self.size

    def __getitem__(self, Py_ssize_t i):
        """Byte at an image offset, read THROUGH the pinned buffer."""
        if i < 0:
            i += <Py_ssize_t>self.size
        if i < 0 or <size_t>i >= self.size:
            raise IndexError("image offset out of range")
        return self._data()[i]

    def __repr__(self):
        return "Image(size=%d, base=0x%x)" % (self.size, self.base)


class Seed:
    """The run `prime()` chose for one image.

    `count` is NOT a field on the C++ struct; reading it costs a full-image
    scan, so it is computed on first access and cached. `offset` and `bytes`
    are read-only: mutating `bytes` in place would leave a stale `_count`
    cached beside it, so both are exposed only through properties over
    private slots.

    A pattern with no fixed run at all (e.g. "? ? ? ?") has no seed to
    choose: `select_seed` returns an empty run, `bytes` is `b""`, and there is
    nothing meaningful to count -- the C++ empty-needle guard returns
    SIZE_MAX, a sentinel, not a real count. `ok` (mirroring `Seed_t::ok()`,
    `!bytes.empty()`) is how a caller distinguishes "no seed" from "seed
    counted", and `count` returns `None` rather than leaking that sentinel.
    """

    __slots__ = ("_offset", "_bytes", "_image", "_count", "_ok")

    def __init__(self, offset, data, image, ok=True):
        self._offset = offset
        self._bytes = data
        self._image = image
        self._count = None
        self._ok = ok

    @property
    def offset(self):
        return self._offset

    @property
    def bytes(self):
        return self._bytes

    @property
    def ok(self):
        """Whether a seed was actually chosen (mirrors Seed_t::ok())."""
        return self._ok

    def __bool__(self):
        return self._ok

    @property
    def count(self):
        if not self._ok:
            return None
        if self._count is None:
            self._count = _count_occurrences(self._image, self._bytes)
        return self._count

    def __repr__(self):
        return "Seed(offset=%d, bytes=%s)" % (self._offset, self._bytes.hex())


def _count_occurrences(Image img not None, bytes needle):
    cdef vector[uint8_t] n
    cdef size_t i
    for i in range(len(needle)):
        n.push_back(needle[i])
    cdef ByteSpan sp = ByteSpan(img._data(), img.size)
    cdef size_t out
    with nogil:
        out = count_up_to(sp, n, kSeedCapExact)
    return out


# ── maml.generate ──────────────────────────────────────────────────
#
# The inverse operation: given an image and a target, emit patterns that
# find it again in a later build. Everything below is glue for
# include/maml/generate.hpp; the Python-facing names live in
# python/maml/generate.py, which just re-exports the pieces here under
# `maml.generate` rather than the top-level namespace (maml.Range
# and maml.Image are reused as-is, unlike a Task 1 that would have
# duplicated Image's buffer-pinning logic in a second image type).

cdef extern from "maml/generate.hpp" namespace "maml::generate" nogil:
    cdef cppclass GenRange_t "maml::generate::Range":
        GenRange_t()
        uint64_t begin
        uint64_t end


# std::span<const Range>, the same reason ByteSpan exists in _core.pxd:
# Cython cannot spell a const template argument, so the C++ type is given
# verbatim as the name.
cdef extern from "<span>" namespace "std" nogil:
    cdef cppclass RangeSpan "std::span<const maml::generate::Range>":
        RangeSpan()
        RangeSpan(const GenRange_t*, size_t)


cdef extern from "maml/generate.hpp" namespace "maml::generate" nogil:
    cdef cppclass GenImage_t "maml::generate::Image":
        GenImage_t()
        ByteSpan bytes
        RangeSpan code
        RangeSpan rodata
        RangeSpan funcs

    cdef cppclass GenOptions_t "maml::generate::Options":
        GenOptions_t()
        string dialect
        cbool nibble_wildcards
        size_t max_len
        int want
        cbool prefer_short
        cbool deep_anchor

    # `strategy` is deliberately NOT declared here -- it is a C++11 scoped
    # enum, which does not implicitly convert to anything Cython can copy
    # out as a field access. maml_strategy_value() below reads it on the C++
    # side instead, where `static_cast` is legal, and the .strategy field is
    # never named as a Cython attribute anywhere in this file.
    cdef cppclass GenCandidate_t "maml::generate::Candidate":
        GenCandidate_t()
        string dialect
        string target_capture
        string pattern
        size_t save_index
        int64_t anchor_delta
        uint64_t anchor_site
        size_t literals
        Seed_t seed

    cdef cppclass GenResolution_t "maml::generate::Resolution":
        GenResolution_t()
        uint64_t address
        vector[size_t] anchors

    vector[GenCandidate_t] cpp_generate_candidates "maml::generate::candidates" (
        const GenImage_t&, uint64_t, const GenOptions_t&) except +raise_pattern_error
    vector[GenCandidate_t] cpp_generate_verified "maml::generate::verified" (
        const GenImage_t&, uint64_t, const GenImage_t&, uint64_t, const GenOptions_t&) except +raise_pattern_error
    vector[GenResolution_t] cpp_generate_resolve_consensus "maml::generate::resolve_consensus" (
        ByteSpan, const vector[GenCandidate_t]&) except +raise_pattern_error


cdef extern from *:
    """
    #include "maml/generate.hpp"
    static inline int maml_strategy_value(const maml::generate::Candidate& c) {
        return static_cast<int>(c.strategy);
    }
    """
    int maml_strategy_value(const GenCandidate_t&)


class Strategy(enum.Enum):
    """Which substrate a Candidate anchors on. Mirrors generate::Strategy,
    in the same order (the int value IS the C++ enum's underlying value --
    maml_strategy_value() reads it with a plain static_cast, so this order
    must not drift from generate.hpp's declaration)."""
    Body = 0
    Xref = 1
    StringAnchor = 2
    RipRef = 3


_STRATEGY_BY_VALUE = {s.value: s for s in Strategy}


@cython.dataclasses.dataclass
cdef class Options:
    """Mirrors generate::Options, field-for-field, defaults included.

    Unlike the result types, this one KEEPS its defaults, and they are not an
    oversight: they are the C++ defaults, and partial construction
    (`Options(want=8)`) is the intended use. The risk here runs the other way
    -- a field added to generate::Options with no counterpart here cannot be
    set from Python at all, and the C++ default silently applies instead. That
    is what test_binding_completeness.py checks it against.
    """
    max_len: cython.size_t = 64
    want: cython.size_t = 4
    prefer_short: cython.bint = True
    deep_anchor: cython.bint = True
    dialect: str = "maml-v1"
    nibble_wildcards: cython.bint = False


@cython.dataclasses.dataclass(frozen=True)
cdef class Candidate:
    """One anchor generate.candidates()/generate.verified() emitted.

    Read-only: a Candidate is a report about what the generator found, not
    something a caller edits and feeds back in (resolve_consensus() reads
    the pattern/save_index/anchor_delta straight off whatever is handed to
    it, so nothing stops a caller building one by hand for that -- but
    fields are still frozen, so "by hand" means a new Candidate, not editing
    the C++-built ones in place).

    anchor_delta is SIGNED and genuinely negative for some candidates (see
    generate.hpp's Candidate::anchor_delta doc) -- target = match - delta,
    done in Python's arbitrary-precision ints, which never wraps the way an
    unsigned subtraction would.

    anchor_site says where in the GENERATING image this anchor sits, and is
    how a caller checks that several candidates are independent rather than
    one instruction reported several times:

        sites = {c.anchor_site for c in cands}   # anchors
        len(cands)                               # patterns, which is not the same

    It is meaningless in any other image, and resolve_consensus() ignores it.
    """
    pattern: str
    save_index: cython.size_t
    anchor_delta: cython.longlong
    anchor_site: cython.ulonglong
    strategy: object
    literals: cython.size_t
    seed: object
    dialect: str
    target_capture: str


@cython.dataclasses.dataclass(frozen=True)
cdef class Resolution:
    """What a set of anchors resolved to in some image, and how many agreed.

    `anchors` is a list of indices into the candidate list resolve_consensus()
    was given -- see resolve_consensus()'s docstring for why the count has to
    travel with the address rather than being discarded.
    """
    address: cython.ulonglong
    anchors: list


cdef GenOptions_t _to_gen_options(opt):
    cdef GenOptions_t g  # default-constructed: the C++ defaults, untouched
    if opt is None:
        return g
    g.dialect = opt.dialect.encode()
    g.nibble_wildcards = bool(opt.nibble_wildcards)
    g.max_len = <size_t>opt.max_len
    g.want = <int>opt.want
    g.prefer_short = <cbool>bool(opt.prefer_short)
    g.deep_anchor = <cbool>bool(opt.deep_anchor)
    return g


cdef vector[GenRange_t] _ranges_to_vec(list ranges):
    cdef vector[GenRange_t] out
    cdef GenRange_t r
    for item in ranges:
        r.begin = <uint64_t><unsigned long long>item.begin
        r.end = <uint64_t><unsigned long long>item.end
        out.push_back(r)
    return out


cdef GenImage_t _to_gen_image(Image image, vector[GenRange_t]& code_v,
                               vector[GenRange_t]& rodata_v, vector[GenRange_t]& funcs_v):
    cdef GenImage_t g
    g.bytes = ByteSpan(image._data(), image.size)
    g.code = RangeSpan(code_v.data(), code_v.size())
    g.rodata = RangeSpan(rodata_v.data(), rodata_v.size())
    g.funcs = RangeSpan(funcs_v.data(), funcs_v.size())
    return g


cdef object _wrap_candidate(const GenCandidate_t& c, Image image):
    cdef bytes seed_bytes = bytes(
        [c.seed.bytes[i] for i in range(c.seed.bytes.size())])
    seed = Seed(c.seed.offset, seed_bytes, image, c.seed.ok())
    return Candidate(
        pattern=c.pattern.decode("utf-8"),
        dialect=c.dialect.decode(),
        target_capture=c.target_capture.decode(),
        save_index=c.save_index,
        anchor_delta=c.anchor_delta,
        anchor_site=c.anchor_site,
        strategy=_STRATEGY_BY_VALUE[maml_strategy_value(c)],
        literals=c.literals,
        seed=seed,
    )


cdef vector[GenCandidate_t] _candidates_to_vec(list cands):
    cdef vector[GenCandidate_t] out
    cdef GenCandidate_t c
    for item in cands:
        c.pattern = item.pattern.encode("utf-8")
        c.dialect = getattr(item,"dialect","maml-v1").encode()
        c.target_capture = getattr(item,"target_capture","").encode()
        c.save_index = <size_t>item.save_index
        c.anchor_delta = <int64_t>item.anchor_delta
        # resolve_consensus does not read this, but a round trip that dropped
        # it would make the Python Candidate a lossy copy of the C++ one.
        c.anchor_site = <uint64_t><unsigned long long>item.anchor_site
        out.push_back(c)
    return out


def generate_candidates(Image image not None, unsigned long long target, opt=None):
    """Every anchor the image affords for `target` -- single-image, unverified.

    See maml::generate::candidates(): this is the raw, un-filtered
    set (candidates() does not check uniqueness; that is what verified() is
    for). Releases the GIL for the scan itself.
    """
    cdef GenOptions_t gopt = _to_gen_options(opt)
    cdef vector[GenRange_t] code_v = _ranges_to_vec(image.code)
    cdef vector[GenRange_t] rodata_v = _ranges_to_vec(image.rodata)
    cdef vector[GenRange_t] funcs_v = _ranges_to_vec(image.funcs)
    cdef GenImage_t gimg = _to_gen_image(image, code_v, rodata_v, funcs_v)
    cdef vector[GenCandidate_t] out
    cdef uint64_t t = <uint64_t>target
    with nogil:
        out = cpp_generate_candidates(gimg, t, gopt)
    return [_wrap_candidate(out[i], image) for i in range(out.size())]


def generate_verified(Image image_a not None, unsigned long long target_a,
                       Image image_b not None, unsigned long long target_b, opt=None):
    """Anchors unique in BOTH images, resolving to their own target in each.

    See maml::generate::verified(). Handing the same image (by
    identity: same buffer pointer and size) as both `image_a` and `image_b`
    is refused by the C++ layer and returns an empty list rather than an
    error -- see generate.hpp's note on why that is a refusal, not a
    special case. Every returned Candidate's `seed` was chosen against
    `image_a` -- re-prime against `image_b` before scanning it.
    """
    cdef GenOptions_t gopt = _to_gen_options(opt)
    cdef vector[GenRange_t] a_code = _ranges_to_vec(image_a.code)
    cdef vector[GenRange_t] a_rodata = _ranges_to_vec(image_a.rodata)
    cdef vector[GenRange_t] a_funcs = _ranges_to_vec(image_a.funcs)
    cdef vector[GenRange_t] b_code = _ranges_to_vec(image_b.code)
    cdef vector[GenRange_t] b_rodata = _ranges_to_vec(image_b.rodata)
    cdef vector[GenRange_t] b_funcs = _ranges_to_vec(image_b.funcs)
    cdef GenImage_t ga = _to_gen_image(image_a, a_code, a_rodata, a_funcs)
    cdef GenImage_t gb = _to_gen_image(image_b, b_code, b_rodata, b_funcs)
    cdef vector[GenCandidate_t] out
    cdef uint64_t ta = <uint64_t>target_a
    cdef uint64_t tb = <uint64_t>target_b
    with nogil:
        out = cpp_generate_verified(ga, ta, gb, tb, gopt)
    return [_wrap_candidate(out[i], image_a) for i in range(out.size())]


def generate_resolve_consensus(Image image not None, list candidates not None):
    """What `candidates` resolve to in `image`, grouped by agreement.

    See maml::generate::resolve_consensus(). `candidates` need not be
    the exact objects generate.candidates()/generate.verified() returned --
    only .pattern, .save_index and .anchor_delta are read -- but building
    them from those functions' output is the intended use.
    """
    cdef vector[GenCandidate_t] cpp_cands = _candidates_to_vec(candidates)
    cdef ByteSpan sp = ByteSpan(image._data(), image.size)
    cdef vector[GenResolution_t] out
    with nogil:
        out = cpp_generate_resolve_consensus(sp, cpp_cands)
    result = []
    for i in range(out.size()):
        anchors = [out[i].anchors[j] for j in range(out[i].anchors.size())]
        result.append(Resolution(address=out[i].address, anchors=anchors))
    return result


# Semantic dialect shares the installed native extension.
include "_v1.pxi"
