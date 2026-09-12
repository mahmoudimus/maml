#include "maml/v1_pipeline.hpp"
// mamlpipe -- run a locator pipeline against an image and report the addresses.
//
// A pipeline composes the substrate generate.hpp derives from image bytes:
//
//     str("text") -> xrefs -> func -> unique
//
// Discovery aid: find an address so a caller can hand it to generate::verified().
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
#include "maml/generate.hpp"
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
        std::vector<generate::Range> code, rodata, funcs, instructions;
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
            } else if (got == 3 && k == "instruction") {
                m.instructions.push_back({ a, b });
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

    generate::Image make_image(const std::vector<uint8_t>& bytes, const Manifest& m) {
        generate::Image img;
        img.bytes = std::span<const uint8_t>(bytes.data(), bytes.size());
        img.code = m.code;
        img.rodata = m.rodata;
        img.funcs = m.funcs;
        return img;
    }

    void usage() {
        fprintf(stderr,
            "usage: mamlpipe <image> --ranges <manifest> \"<pipeline>\" [--trace]\n"
            "       mamlpipe --batch <jobfile> --image <image> --ranges <manifest>\n"
            "\n"
            "stages: str(\"text\") | bytes(\"pattern\") | find(\"pattern\")\n"
            "        | before(\"pattern\", within=N) | after(\"pattern\", within=N)\n"
            "        | capture(\"name\") | xrefs | callers | func | func:strict | func:loose\n"
            "        | unique | nth(N) | limit(N) | read(N),  composed with ->\n"
            "manifest lines: size N | code A B | rodata A B | func A B | instruction A B\n");
    }

} // namespace

int main(int argc, char** argv) {
    std::string image, ranges, jobfile, source;
    bool batch = false, trace = false;
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--dialect") {
            if (i + 1 == argc || std::string(argv[++i]) != "maml-v1") {
                fprintf(stderr, "Unknown dialect; MAML is v1 only\n");
                return 2;
            }
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

    auto execute = [&](const std::string& text, const std::string& name) {
        try {
            const auto result = v1::Pipeline(text).run(v1::Image{ bytes }, img.code, img.rodata, img.funcs, m.instructions);
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
