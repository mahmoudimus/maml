#include "maml/v1_pipeline.hpp"
// mamlpipe -- run a locator pipeline against an image and report the addresses.
//
// A pipeline composes the substrate generate.hpp derives from image bytes:
//
//     str "GetActivePlayerObj" -> xref -> func -> unique
//
// See include/maml/pipeline.hpp for the stages. This is a discovery aid -- it finds an address so a caller
// can hand it to generate::verified(); it makes no claim about surviving a
// rebuild.
//
// Usage:  mamlpipe <image> --ranges <manifest> "<pipeline>" [--trace]
//         mamlpipe --batch <jobfile> --image <image> --ranges <manifest>
//
// The manifest is the line format tools/durability/flatten.py emits:
//     size N
//     code A B
//     rodata A B
//     func A B
// Addresses are RVAs into a flat image (offset 0 in the file is RVA 0), not a
// PE on disk.
//
// Jobfile: one job per line, `name <TAB> pipeline`.
//
// OUTPUT SHAPE, and it differs between the two modes on purpose, matching
// mamlscan: single-shot output is SPACE separated, batch output is TAB
// separated. A parser that splits batch output on spaces, or single-shot
// output on tabs, sees the wrong number of fields -- that has bitten here.
#include "maml/pipeline.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace maml;

namespace {

    std::vector<uint8_t> load(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f)
            return {};
        const std::streamsize n = f.tellg();
        f.seekg(0);
        std::vector<uint8_t> buf(static_cast<size_t>(n));
        f.read(reinterpret_cast<char*>(buf.data()), n);
        return buf;
    }

    struct Manifest {
        bool ok = false;
        uint64_t size = 0; // 0 = the manifest did not say
        std::vector<generate::Range> code, rodata, funcs;
        std::string error;
    };

    // Deliberately strict: a manifest line this does not understand is an error,
    // not a line skipped. A silently dropped `rodata` line would turn every `str`
    // stage into a clean, wrong "not found".
    Manifest read_manifest(const std::string& path) {
        Manifest m;
        std::ifstream f(path);
        if (!f) {
            m.error = "cannot open " + path;
            return m;
        }
        std::string line;
        size_t lineno = 0;
        while (std::getline(f, line)) {
            ++lineno;
            if (line.empty() || line[0] == '#')
                continue;
            char kind[32] = { 0 };
            unsigned long long a = 0, b = 0;
            const int got = sscanf(line.c_str(), "%31s %llu %llu", kind, &a, &b);
            const std::string k(kind);
            if (got == 2 && k == "size") {
                m.size = a;
            } else if (got == 3 && k == "code") {
                m.code.push_back({ a, b });
            } else if (got == 3 && k == "rodata") {
                m.rodata.push_back({ a, b });
            } else if (got == 3 && k == "func") {
                m.funcs.push_back({ a, b });
            } else {
                m.error = path + ":" + std::to_string(lineno) + ": unrecognised line";
                return m;
            }
        }
        m.ok = true;
        return m;
    }

    std::string join(const std::vector<uint64_t>& v, size_t cap) {
        std::string s;
        for (size_t i = 0; i < v.size() && i < cap; ++i) {
            char b[24];
            snprintf(b, sizeof b, "%llx", (unsigned long long)v[i]);
            if (i)
                s += ",";
            s += b;
        }
        return s;
    }

    // `str "x" 0>1;xref 1>2;func 2>1` -- semicolon separated so it survives as one
    // TAB-separated field.
    std::string join_trace(const std::vector<pipeline::StageResult>& t) {
        std::string s;
        for (size_t i = 0; i < t.size(); ++i) {
            if (i)
                s += ";";
            s += t[i].stage + " " + std::to_string(t[i].in) + ">" + std::to_string(t[i].out);
        }
        return s;
    }

    // Addresses and VALUES are not interchangeable, and the difference has to
    // survive the print: `read` yields what the bytes said, not where they
    // are, and a consumer that fed a structure field displacement back in as
    // an RVA would dereference garbage. Single-shot says `vals=` where it
    // otherwise says `addrs=`; batch carries a trailing `kind` column.
    bool is_values(const pipeline::PipelineResult& r) {
        return r.kind == pipeline::ResultKind::Value;
    }

    const char* kind_of(const pipeline::PipelineResult& r) {
        return is_values(r) ? "value" : "addr";
    }

    const char* status_of(const pipeline::PipelineResult& r) {
        if (pipeline::failed(r))
            return "ERR";
        return r.ok ? "OK" : "NONE";
    }

    // The stage index, or "" when nothing failed. It is the whole point of the
    // trace: `str -> xref -> func -> unique` failing at 1 says the STRING was
    // referenced from several places, which is a different problem from the
    // function having several callers.
    std::string stage_field(const pipeline::PipelineResult& r) {
        return r.failed_stage == SIZE_MAX ? std::string()
                                          : std::to_string(r.failed_stage);
    }

    generate::Image make_image(const std::vector<uint8_t>& bytes, const Manifest& m) {
        generate::Image img;
        img.bytes = std::span<const uint8_t>(bytes.data(), bytes.size());
        img.code = m.code;
        img.rodata = m.rodata;
        img.funcs = m.funcs;
        return img;
    }

    void print_trace(const pipeline::PipelineResult& r) {
        for (size_t i = 0; i < r.trace.size(); ++i)
            fprintf(stderr, "stage %zu %s in=%zu out=%zu\n", i, r.trace[i].stage.c_str(),
                r.trace[i].in, r.trace[i].out);
    }

    int run_batch(const std::string& jobfile, const generate::Image& img) {
        std::ifstream jf(jobfile);
        if (!jf) {
            fprintf(stderr, "cannot open %s\n", jobfile.c_str());
            return 2;
        }
        // One Session for the whole file, with the lea index built up front.
        // Calling pipeline::run() per job rebuilds the substrate every time:
        // measured on a 42MB image, 200 jobs took 3,471 ms that way against
        // 19 ms here, and the gap grows with the file. It is the same shape as
        // the defect that cost StringAnchor 71 minutes per target.
        pipeline::Session session(img);
        session.preload_string_targets();

        std::string line;
        bool all_ok = true;
        while (std::getline(jf, line)) {
            if (line.empty())
                continue;
            const size_t tab = line.find('\t');
            if (tab == std::string::npos) {
                printf("%s\tERR\t0\t\t\tmalformed job (want name <TAB> pipeline)\t\taddr\n",
                    line.c_str());
                all_ok = false;
                continue;
            }
            const std::string name = line.substr(0, tab);
            const std::string src = line.substr(tab + 1);
            const pipeline::PipelineResult r = session.run(src);
            // `kind` is APPENDED rather than inserted: every existing column
            // keeps its index, so a parser reading fields 0..6 is unaffected
            // and one that wants the distinction reads field 7.
            printf("%s\t%s\t%zu\t%s\t%s\t%s\t%s\t%s\n", name.c_str(), status_of(r),
                r.addresses.size(), join(r.addresses, 32).c_str(),
                stage_field(r).c_str(), r.error.c_str(), join_trace(r.trace).c_str(),
                kind_of(r));
            fflush(stdout);
            if (!r.ok)
                all_ok = false;
        }
        return all_ok ? 0 : 1;
    }

    void usage() {
        fprintf(stderr,
            "v1: add --dialect maml-v1 for str(\"text\"), bytes(\"pattern\"), xrefs, capture(\"name\")\n"
            "usage: mamlpipe <image> --ranges <manifest> \"<pipeline>\" [--trace]\n"
            "       mamlpipe --batch <jobfile> --image <image> --ranges <manifest>\n"
            "\n"
            "stages: str \"text\" | bytes \"<pattern>\" | find \"<pattern>\"\n"
            "        | xref | callers | func | unique | nth K | limit N\n"
            "        | read (1|2|4|8),  composed with ->\n"
            "modifiers: func:strict fails if func REPLACED an address rather\n"
            "        than located it; func:loose is the default, spelled out.\n"
            "        NOT after xref/callers -- those yield reference SITES,\n"
            "        mid-function by definition, so it rejects ~everything.\n"
            "manifest lines: size N | code A B | rodata A B | func A B\n"
            "\n"
            "`find` searches only the function enclosing each address, so its\n"
            "pattern need only be unique THERE. `read N` is terminal: it loads\n"
            "N little-endian bytes and yields VALUES, printed as `vals=` in\n"
            "single-shot and marked `value` in the batch kind column.\n"
            "\n"
            "single-shot output is SPACE separated; --batch output is TAB\n"
            "separated (name status count addrs stage detail trace kind).\n"
            "exit 0 only when the pipeline ended with at least one address.\n");
    }

} // namespace

int main(int argc, char** argv) {
    std::string image, ranges, jobfile, source;
    bool batch = false, trace = false, semantic = false;
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--dialect") {
            if (semantic || i + 1 == argc || std::string(argv[++i]) != "maml-v1") {
                fprintf(stderr, "Expected exactly one --dialect maml-v1\n");
                return 2;
            }
            semantic = true;
        } else if (a == "--batch" && i + 1 < argc) {
            batch = true;
            jobfile = argv[++i];
        } else if (a == "--image" && i + 1 < argc) {
            image = argv[++i];
        } else if (a == "--ranges" && i + 1 < argc) {
            ranges = argv[++i];
        } else if (a == "--trace") {
            trace = true;
        } else if (a == "-h" || a == "--help") {
            usage();
            return 2;
        } else if (!a.empty() && a[0] == '-' && a != "-") {
            fprintf(stderr, "unknown option %s\n", a.c_str());
            usage();
            return 2;
        } else {
            positional.push_back(a);
        }
    }

    if (batch) {
        if (image.empty() && !positional.empty())
            image = positional[0];
    } else {
        if (positional.size() >= 1)
            image = positional[0];
        if (positional.size() >= 2)
            source = positional[1];
    }

    if (image.empty() || ranges.empty() || (batch ? jobfile.empty() : source.empty())) {
        usage();
        return 2;
    }

    const Manifest m = read_manifest(ranges);
    if (!m.ok) {
        fprintf(stderr, "%s\n", m.error.c_str());
        return 2;
    }
    const std::vector<uint8_t> bytes = load(image);
    if (bytes.empty()) {
        fprintf(stderr, "cannot read %s\n", image.c_str());
        return 2;
    }
    // A manifest describing a different image than the one loaded would put
    // every range at the wrong place, and the pipeline would answer cleanly
    // and wrongly. Say so rather than proceeding silently.
    if (m.size && m.size != bytes.size())
        fprintf(stderr, "warning: manifest says size %llu, %s is %zu bytes\n",
            (unsigned long long)m.size, image.c_str(), bytes.size());

    const generate::Image img = make_image(bytes, m);

    if (semantic) {
        auto execute = [&](const std::string& text, const std::string& name) {
            try {
                const auto result = v1::Pipeline(text).run(v1::Image{ bytes }, img.code, img.rodata, img.funcs);
                if (!name.empty())
                    printf("%s\t", name.c_str());
                printf("%s %s=%zu", result.ok() ? "OK" : "NONE", result.is_matches ? "matches" : "values",
                    result.is_matches ? result.matches.size() : result.values.size());
                for (const auto& match : result.matches) {
                    printf(" %llx", (unsigned long long)match.offset);
                    for (const auto& c : match.captures)
                        printf("{%s=%llx:%s:%s}", c.name.c_str(), (unsigned long long)c.data.value, c.data.kind.c_str(), c.data.space.c_str());
                }
                for (const auto& value : result.values)
                    printf(" %llx:%s:%s", (unsigned long long)value.value, value.kind.c_str(), value.space.c_str());
                printf("\n");
                if (trace)
                    for (const auto& t : result.trace)
                        fprintf(stderr, "%s %zu -> %zu\n", t.stage.c_str(), t.into, t.out);
                return result.ok();
            } catch (const std::exception& e) {
                printf("%s%sERR %s\n", name.c_str(), name.empty() ? "" : "\t", e.what());
                return false;
            }
        };
        if (!batch)
            return execute(source, "") ? 0 : 1;
        std::ifstream jobs(jobfile);
        if (!jobs) {
            fprintf(stderr, "Cannot open %s\n", jobfile.c_str());
            return 2;
        }
        std::string line;
        bool ok = true;
        while (std::getline(jobs, line)) {
            if (line.empty())
                continue;
            const size_t tab = line.find('\t');
            if (tab == std::string::npos) {
                printf("ERR malformed pipeline job\n");
                ok = false;
                continue;
            }
            if (!execute(line.substr(tab + 1), line.substr(0, tab)))
                ok = false;
        }
        return ok ? 0 : 1;
    }

    if (batch)
        return run_batch(jobfile, img);

    const pipeline::PipelineResult r = pipeline::run(img, source);
    std::string detail;
    if (!r.error.empty())
        detail = " stage=" + stage_field(r) + " " + r.error;
    printf("%s %s=%zu %s%s\n", status_of(r), is_values(r) ? "vals" : "addrs",
        r.addresses.size(), join(r.addresses, 64).c_str(), detail.c_str());
    if (trace)
        print_trace(r);
    return r.ok ? 0 : 1;
}
