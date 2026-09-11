# cython: language_level=3
from libc.stdint cimport uint8_t
from cpython.buffer cimport Py_buffer
from libcpp cimport bool as cbool
from libcpp.string cimport string
from libcpp.vector cimport vector


cdef class Image:
    cdef Py_buffer _view
    cdef bint _has_view
    cdef readonly size_t size
    cdef readonly unsigned long long base
    # Section ranges (Range objects, from _containers.py). Empty for a flat
    # image. A plain Python attribute, but `cdef class` needs it declared
    # here to carry it at all.
    cdef public list sections

    # What maml.generate needs that the bytes alone do not say: executable
    # ranges, read-only-data ranges, and (optionally) resolved function
    # ranges. Same shape as `sections` -- a plain list of `maml.Range`,
    # empty by default -- declared here for the same reason `sections` is.
    cdef public list code
    cdef public list rodata
    cdef public list funcs

    cdef const uint8_t* _data(self) noexcept nogil


# std::span<const uint8_t> named explicitly: Cython cannot spell a const
# template argument, so the C++ type is given verbatim as the name.
cdef extern from "<span>" namespace "std" nogil:
    cdef cppclass ByteSpan "std::span<const uint8_t>":
        ByteSpan()
        ByteSpan(const uint8_t*, size_t)



cdef extern from *:
    void raise_pattern_error()


cdef extern from "maml/mamlscan.hpp" namespace "maml::locate" nogil:
    const size_t kSeedCapExact
    const size_t kSeedCapLoadTime

    # Named with a _t suffix so the Python-visible `Hit` and `Seed` classes
    # added in Task 4 can keep the unqualified names. The string gives the real
    # C++ type, so this is purely a Cython-side alias.
    cdef cppclass Seed_t "maml::locate::Seed":
        Seed_t()
        size_t offset
        vector[uint8_t] bytes
        cbool ok()

    size_t count_up_to(ByteSpan, const vector[uint8_t]&, size_t) except +


