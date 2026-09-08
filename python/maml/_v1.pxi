# cython: language_level=3
"""Native execution bridge for the explicit MAML v1 dialect."""
from libc.stdint cimport uint8_t, uint64_t
from libcpp cimport bool as cbool
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map

cdef extern from *:
    """
    #include <Python.h>
    #include "maml/v1_pipeline.hpp"
    static void maml_v1_error() {
        try { throw; }
        catch (const maml::v1::Error& e) {
            PyObject* args = Py_BuildValue("(ssK)", e.code.c_str(), e.what(),
                static_cast<unsigned long long>(e.position));
            if (args) { PyErr_SetObject(PyExc_ValueError, args); Py_DECREF(args); }
        }
        catch (const std::exception& e) { PyErr_SetString(PyExc_RuntimeError, e.what()); }
        catch (...) { PyErr_SetString(PyExc_RuntimeError, "Unknown native error"); }
    }
    static maml::v1::Image maml_v1_image(const uint8_t* bytes, size_t size, uint64_t base,
            const std::map<uint64_t,uint64_t>& mapper) {
        return {std::span<const uint8_t>(bytes,size),base,mapper};
    }
    static std::vector<maml::v1::Match> maml_v1_match_at(const maml::v1::Pattern& pattern,
            const maml::v1::Image& image, uint64_t start) {
        auto hit=pattern.match_at(image,start);
        if (hit) return {*hit};
        return {};
    }
    static maml::v1::PipelineResult maml_v1_pipeline_run(const maml::v1::Pipeline& pipeline,
            const maml::v1::Image& image, const std::vector<maml::generate::Range>& code,
            const std::vector<maml::generate::Range>& rodata, const std::vector<maml::generate::Range>& funcs) {
        return pipeline.run(image,code,rodata,funcs);
    }
    """
    void maml_v1_error()
    CImage maml_v1_image(const uint8_t*, size_t, uint64_t, const map[uint64_t,uint64_t]&) except +maml_v1_error nogil
    vector[CMatch] maml_v1_match_at(const CPattern&, const CImage&, uint64_t) except +maml_v1_error nogil
    CResult maml_v1_pipeline_run(const CPipeline&, const CImage&, const vector[CRange]&, const vector[CRange]&, const vector[CRange]&) except +maml_v1_error nogil

cdef extern from "maml/v1_pipeline.hpp" namespace "maml::v1" nogil:
    cdef cppclass CValue "maml::v1::Value":
        uint64_t value
        string kind
        string space
    cdef cppclass CCapture "maml::v1::NamedCapture":
        string name
        CValue data
    cdef cppclass CMatch "maml::v1::Match":
        uint64_t offset
        vector[string] schema
        vector[CCapture] captures
    cdef cppclass CImage "maml::v1::Image":
        CImage()
    cdef cppclass CPattern "maml::v1::Pattern":
        CPattern(const string&) except +maml_v1_error
        const vector[string]& schema()
        vector[CMatch] find_all(const CImage&, size_t, cbool) except +maml_v1_error
    cdef cppclass CTrace "maml::v1::Trace":
        string stage
        size_t into
        size_t out
    cdef cppclass CResult "maml::v1::PipelineResult":
        CResult()
        cbool is_matches
        vector[string] schema
        vector[CMatch] matches
        vector[CValue] values
        vector[CTrace] trace
    cdef cppclass CPipeline "maml::v1::Pipeline":
        CPipeline(const string&) except +maml_v1_error

cdef extern from "maml/generate.hpp" namespace "maml::generate" nogil:
    cdef cppclass CRange "maml::generate::Range":
        CRange()
        uint64_t begin
        uint64_t end

cdef object value(const CValue& v):
    return (v.value, v.kind.decode(), v.space.decode())

cdef list matches(const vector[CMatch]& items):
    return [(items[i].offset, {items[i].captures[j].name.decode():value(items[i].captures[j].data)
             for j in range(items[i].captures.size())}) for i in range(items.size())]

cdef vector[CRange] ranges(object items):
    cdef vector[CRange] out
    cdef CRange r
    for begin,end in items:
        r.begin=begin
        r.end=end
        out.push_back(r)
    return out

cdef class NativePattern:
    cdef CPattern* ptr
    def __cinit__(self, str text):
        self.ptr = new CPattern(text.encode())
    def __dealloc__(self):
        del self.ptr
    @property
    def schema(self):
        return tuple(s.decode() for s in self.ptr.schema())
    def scan(self, bytes data, uint64_t base, mapping, start=None, size_t limit=0, cbool exhaustive=False):
        cdef map[uint64_t,uint64_t] mapper=mapping
        cdef const uint8_t* buf=data
        cdef CImage image=maml_v1_image(buf,len(data),base,mapper)
        cdef vector[CMatch] result
        cdef uint64_t at=0 if start is None else start
        if start is None:
            with nogil:
                result=self.ptr.find_all(image,limit,exhaustive)
        else:
            with nogil:
                result=maml_v1_match_at(self.ptr[0],image,at)
        return matches(result)

cdef class NativePipeline:
    cdef CPipeline* ptr
    def __cinit__(self, str text):
        self.ptr=new CPipeline(text.encode())
    def __dealloc__(self):
        del self.ptr
    def run(self, bytes data, uint64_t base, mapping, code, rodata, funcs):
        cdef map[uint64_t,uint64_t] mapper=mapping
        cdef const uint8_t* buf=data
        cdef CImage image=maml_v1_image(buf,len(data),base,mapper)
        cdef vector[CRange] c=ranges(code), r=ranges(rodata), f=ranges(funcs)
        cdef CResult result
        with nogil:
            result=maml_v1_pipeline_run(self.ptr[0],image,c,r,f)
        return (result.is_matches, tuple(s.decode() for s in result.schema),
                matches(result.matches), [value(v) for v in result.values],
                [(t.stage.decode(),t.into,t.out) for t in result.trace])
