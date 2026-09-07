# cython: language_level=3
"""Cython bindings for maml's C++ matcher."""

import enum
from dataclasses import dataclass

cimport cython

from libc.stdint cimport uint8_t, uint64_t, int64_t, SIZE_MAX
from cpython.buffer cimport (PyObject_GetBuffer, PyBuffer_Release,
                             PyBUF_SIMPLE)


cdef extern from "maml/maml.hpp":
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
# discards its payload. ParseException carries the error kind and the token
# span, which is the entire reason a bad pattern raises instead of returning
# None -- so translate it by hand.
#
# maml::to_string(ParseErrorType) does not exist in the vendored
# headers (include/maml/maml.hpp is off-limits to edit), so the
# enum-to-name mapping is a switch inlined here instead.
cdef extern from *:
    """
    #include <Python.h>
    #include "maml/maml.hpp"

    static const char* maml_parse_error_type_name(maml::ParseErrorType t) {
        switch (t) {
            case maml::ParseErrorType::UnexpectedToken: return "UnexpectedToken";
            case maml::ParseErrorType::UnexpectedEnd: return "UnexpectedEnd";
            case maml::ParseErrorType::MaskByteLenMismatch: return "MaskByteLenMismatch";
            case maml::ParseErrorType::HexValueInvalid: return "HexValueInvalid";
            case maml::ParseErrorType::HexValueIncomplete: return "HexValueIncomplete";
            case maml::ParseErrorType::GroupNotClosed: return "GroupNotClosed";
            case maml::ParseErrorType::BlockNotClosed: return "BlockNotClosed";
            case maml::ParseErrorType::RangeBoundInvalid: return "RangeBoundInvalid";
            case maml::ParseErrorType::RangeEndMustBeGraterThenStart: return "RangeEndMustBeGraterThenStart";
            case maml::ParseErrorType::SequenceTooLarge: return "SequenceTooLarge";
            case maml::ParseErrorType::InternalError: return "InternalError";
        }
        return nullptr;
    }

    static PyObject* maml_pattern_error_type = nullptr;

    extern "C" void maml_register_pattern_error(PyObject* t) {
        Py_XINCREF(t);
        Py_XSETREF(maml_pattern_error_type, t);
    }

    extern "C" void raise_pattern_error() {
        try {
            throw;
        } catch (const maml::ParseException& e) {
            const char* kind = maml_parse_error_type_name(e.type);
            PyObject* args = Py_BuildValue(
                "(snn)", e.what(),
                (Py_ssize_t)e.position.first, (Py_ssize_t)e.position.second);
            PyObject* kw = Py_BuildValue("{s:s}", "kind", kind ? kind : "Unknown");
            if (args && kw && maml_pattern_error_type) {
                PyObject* exc = PyObject_Call(maml_pattern_error_type, args, kw);
                if (exc) { PyErr_SetObject(maml_pattern_error_type, exc); Py_DECREF(exc); }
            }
            Py_XDECREF(args);
            Py_XDECREF(kw);
            // The three-way guard above (args && kw && maml_pattern_error_type)
            // has failure branches -- OOM building args/kw, or this function
            // called before maml_register_pattern_error runs -- that fall
            // through without ever calling PyErr_SetObject/PyErr_SetString.
            // Cython treats "returned from except+ handler" as "translated,
            // a Python exception is now pending"; returning here with none
            // set is undefined downstream, not a clean no-op. Guarantee this
            // catch clause never returns without one pending.
            if (!PyErr_Occurred()) {
                PyErr_SetString(PyExc_RuntimeError,
                                "maml: pattern parse failed and the error type "
                                "was unavailable");
            }
        } catch (const std::bad_alloc&) {
            PyErr_NoMemory();
        } catch (const std::exception& e) {
            PyErr_SetString(PyExc_RuntimeError, e.what());
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError, "unknown C++ exception");
        }
    }
    """
    void maml_register_pattern_error(object)
    void raise_pattern_error()


# `Compiled` (a real struct in mamlscan.hpp: offset + a std::vector<uint8_t>)
# gets copy-assigned in Pattern.prime() to seed a fresh Primed. A bare `dst =
# src` at the Cython level is a plain C++ assignment with no `except +`
# anywhere near it; the vector's copy constructor can throw bad_alloc, and an
# exception with no handler in scope reaches std::terminate instead of
# becoming a Python exception. Route the assignment through a tiny helper
# that Cython DOES wrap in `except +`.
cdef extern from *:
    """
    static inline void maml_assign_compiled(
            maml::locate::Compiled& dst,
            const maml::locate::Compiled& src) {
        dst = src;
    }
    """
    void maml_assign_compiled(Compiled&, const Compiled&) except +


class PatternError(ValueError):
    """A pattern that did not parse, with the span the parser blamed."""

    def __init__(self, message, start=0, end=0, kind="Unknown"):
        super().__init__(message)
        self.kind = kind
        self.start = start
        self.end = end


maml_register_pattern_error(PatternError)


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


cdef class Pattern:
    """A parsed pattern, independent of any image. Parse once, prime per image."""

    def __cinit__(self, text):
        self.text = text
        self._c = cpp_compile(text.encode("utf-8"))

    def __repr__(self):
        return "Pattern(%r)" % (self.text,)

    def prime(self, Image image not None, cbool exact=True):
        """Choose a seed for THIS image. Reusable; re-prime for another image."""
        cdef Primed p = Primed.__new__(Primed)
        maml_assign_compiled(p._c, self._c)
        p._img = image
        cdef ByteSpan sp = ByteSpan(image._data(), image.size)
        cdef size_t cap = kSeedCapExact if exact else kSeedCapLoadTime
        with nogil:
            cpp_prime(p._c, sp, cap)
        # Built eagerly, here, while `p` is still thread-local and no other
        # thread can hold a reference to it yet. `Primed.seed` used to build
        # this lazily in pure Python with a check-then-build-then-store
        # sequence; two threads racing the first `.seed` access could both
        # see `self._seed is None`, both build a `Seed`, and the loser's
        # write would win, breaking `p.seed is p.seed` identity. Doing it
        # here removes the race instead of guarding it with a lock. The
        # expensive part, `count`, stays lazy on `Seed` itself.
        cdef const Seed_t* s = &p._c.seed
        cdef bytes seed_bytes = bytes(
            [s.bytes[i] for i in range(s.bytes.size())])
        p._seed = Seed(s.offset, seed_bytes, image, s.ok())
        return p

    def find(self, Image image not None, size_t save_index=0):
        """One-shot. Equals prime(image).find(save_index)."""
        return self.prime(image).find(save_index)


@cython.dataclasses.dataclass(frozen=True)
cdef class Hit:
    """One match, and what it cost to find.

    A cdef dataclass rather than a plain one: the fields are C-typed storage,
    and -- the reason it matters -- NONE of them has a default. A bound field
    with a default accepts being omitted at the construction site and yields a
    plausible zero, which is exactly how StageResult::moved went missing. With
    no defaults, omitting one is a TypeError on the first call.
    """
    offset: cython.size_t
    value: cython.size_t
    candidates: cython.size_t
    verified: cython.size_t


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


cdef class Primed:
    """A pattern with a seed chosen for one specific image.

    Not constructible directly -- `Pattern.prime()` is the only supported
    way to get one. `__cinit__` stays permissive (no `_img` guard there) so
    `Primed.__new__(Primed)` still works from `Pattern.prime`; `__init__` is
    what a bare `Primed()` call from Python hits, and that is rejected.
    `Primed.__new__(Primed)` from OUTSIDE `Pattern.prime` still bypasses
    `__init__` entirely, though, leaving `_img` as None -- so every method
    below additionally guards on `self._img is None` and raises instead of
    dereferencing it.
    """

    def __cinit__(self):
        self._seed = None

    def __init__(self, *args, **kwargs):
        raise TypeError(
            "Primed is not constructible directly; use Pattern.prime(image)")

    def find(self, size_t save_index=0):
        if self._img is None:
            raise TypeError("Primed must come from Pattern.prime(image)")
        cdef ByteSpan sp = ByteSpan(self._img._data(), self._img.size)
        cdef optional[Hit_t] r
        with nogil:
            r = cpp_find(sp, self._c, save_index)
        if not r.has_value():
            return None
        return Hit(r.value().offset, r.value().value,
                   r.value().candidates, r.value().verified)

    def find_all(self, size_t save_index=0, size_t limit=0):
        """Every match, in increasing offset. limit=0 is unbounded.

        Hit.candidates and Hit.verified accumulate across the scan: each element
        carries the running totals as of when it was verified, so the last
        element carries them as of the last SUCCESSFUL match -- not necessarily
        the whole scan, if candidates were rejected after it.
        """
        if self._img is None:
            raise TypeError("Primed must come from Pattern.prime(image)")
        cdef ByteSpan sp = ByteSpan(self._img._data(), self._img.size)
        cdef vector[Hit_t] out
        cdef size_t i
        with nogil:
            out = cpp_find_all(sp, self._c, save_index, limit)
        return [Hit(out[i].offset, out[i].value, out[i].candidates, out[i].verified)
                for i in range(out.size())]

    @property
    def seed(self):
        # Built eagerly in Pattern.prime(), before this Primed was published
        # to any thread -- so this is a plain read, not a
        # check-then-build-then-store race. See prime() for why. Still
        # guarded: a `Primed.__new__(Primed)` from outside `Pattern.prime`
        # never ran that construction, so `_seed` would otherwise silently
        # read back as None instead of raising.
        if self._img is None:
            raise TypeError("Primed must come from Pattern.prime(image)")
        return self._seed


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


# ── maml.pipeline ──────────────────────────────────────────────────
#
# The locator pipeline: compose the substrate above into a search for an
# address ("str \"x\" -> xref -> func"). Glue for
# include/maml/pipeline.hpp; the Python-facing names live in
# python/maml/pipeline.py, which re-exports them under
# `maml.pipeline` rather than the top-level namespace, the same way
# `maml.generate` does.

cdef extern from "maml/pipeline.hpp" namespace "maml::pipeline" nogil:
    # `in` is a keyword in both Python and Cython, so the member is spelled
    # `in_` here and mapped to the real C++ name by the quoted string.
    cdef cppclass PipeStageResult_t "maml::pipeline::StageResult":
        PipeStageResult_t()
        string stage
        size_t in_ "in"
        size_t out
        size_t moved

    cdef cppclass PipeResult_t "maml::pipeline::PipelineResult":
        PipeResult_t()
        cbool ok
        vector[uint64_t] addresses
        vector[PipeStageResult_t] trace
        size_t failed_stage
        string error


# run() is overloaded (source text, or an already-parsed program). Route
# through a shim rather than relying on overload resolution across Cython's
# std::string -> std::string_view conversion.
#
# `kind` travels through a predicate rather than as a bound enum: it is a
# scoped enum (`enum class ResultKind`), and a bool over the wire needs no
# Cython enum declaration to stay in step with the C++ one.
cdef extern from * nogil:
    """
    #include <string>
    #include "maml/pipeline.hpp"
    static inline maml::pipeline::PipelineResult maml_pipeline_run(
            const maml::generate::Image& img, const std::string& src) {
        return maml::pipeline::run(img, std::string_view(src));
    }
    static inline bool maml_pipeline_is_value(
            const maml::pipeline::PipelineResult& r) {
        return r.kind == maml::pipeline::ResultKind::Value;
    }
    """
    PipeResult_t maml_pipeline_run(const GenImage_t&, const string&) except +raise_pattern_error
    cbool maml_pipeline_is_value(const PipeResult_t&)


@cython.dataclasses.dataclass(frozen=True)
cdef class StageResult:
    """Set cardinality into and out of one stage.

    `into`/`out` rather than the C++ `in`/`out`: `in` is a Python keyword.
    """
    stage: str
    into: cython.size_t
    out: cython.size_t

    # Outputs that were NOT in this stage's input. On `xref` that is nearly
    # everything and says little; on `func` it is the count of addresses
    # REPLACED by an enclosing entry, which is how a caller sees that a
    # mid-function target was silently collapsed to a function start.
    moved: cython.size_t


@cython.dataclasses.dataclass(frozen=True)
cdef class PipelineResult:
    """What a pipeline found, and how the set narrowed on the way.

    `ok` means "ended with at least one address" -- an empty result is not an
    error, and comes back with `error` empty and `failed_stage` None. A
    failing `unique`, a parse error, or a stage whose substrate the Image
    lacks sets `error`.

    `trace` is not decoration. A caller that takes `addresses[0]` without
    looking at it is making the mistake this project measured: 5-13% of
    patterns resolving to exactly one address in a later build resolve to the
    WRONG one, with nothing marking the answer suspect.

    `failed_stage` is None when nothing failed (the C++ SIZE_MAX sentinel
    does not travel). For `unique` it names the stage that INTRODUCED the
    ambiguity, which is earlier than the `unique` itself -- see
    include/maml/pipeline.hpp.

    `kind` is "address" for every pipeline but one ending in `read`, which
    yields the VALUES it loaded and reports "value". The two are not
    interchangeable: a consumer that took a structure field displacement for
    an address would dereference garbage, and nothing else in the result
    would say otherwise. `addresses` carries either -- one list rather than
    two, since every stage but the terminal one produces addresses.
    """
    ok: cython.bint
    addresses: list
    trace: list
    failed_stage: object
    error: str
    kind: str

    @property
    def failed(self):
        """Whether something went wrong, as opposed to simply finding nothing."""
        return bool(self.error)

    @property
    def values(self):
        """The loaded values, for a pipeline that ended in `read`.

        Raises rather than returning `addresses` for an address result: the
        point of `kind` is that reading one as the other is a mistake, and a
        property that quietly obliged would reintroduce it.
        """
        if self.kind != "value":
            raise ValueError(
                "this pipeline produced addresses, not values; it does not "
                "end in a `read` stage")
        return self.addresses


def pipeline_run(Image image not None, str source not None):
    """Run a pipeline against `image`. Never raises for a bad pipeline.

    A malformed pipeline comes back as a PipelineResult with `ok` False and
    `error` set, so a jobfile of them can be run without a try/except per
    line. `image.code`, `image.rodata` and `image.funcs` are the substrate;
    a stage that needs one the Image lacks fails with a message naming it,
    rather than quietly answering empty.
    """
    cdef vector[GenRange_t] code_v = _ranges_to_vec(image.code)
    cdef vector[GenRange_t] rodata_v = _ranges_to_vec(image.rodata)
    cdef vector[GenRange_t] funcs_v = _ranges_to_vec(image.funcs)
    cdef GenImage_t gimg = _to_gen_image(image, code_v, rodata_v, funcs_v)
    cdef string src = source.encode("utf-8")
    cdef PipeResult_t out
    with nogil:
        out = maml_pipeline_run(gimg, src)
    trace = [StageResult(out.trace[i].stage.decode("utf-8"),
                         out.trace[i].in_, out.trace[i].out,
                         out.trace[i].moved)
             for i in range(out.trace.size())]
    addresses = [out.addresses[i] for i in range(out.addresses.size())]
    failed_stage = None if out.failed_stage == SIZE_MAX else out.failed_stage
    return PipelineResult(ok=out.ok, addresses=addresses, trace=trace,
                          failed_stage=failed_stage,
                          error=out.error.decode("utf-8"),
                          kind="value" if maml_pipeline_is_value(out) else "address")
