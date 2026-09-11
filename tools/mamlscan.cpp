// mamlscan -- scan an image with a maml pattern and report hits as RVAs.
//
// This is the validator behind every pattern this repo ships: a pattern is
// only believed once it produces exactly one hit in BOTH builds of a version,
// resolving to the intended target in each. Written against the real engine
// so the semantics are the engine's, not a reimplementation of them.
//
// Usage:  mamlscan <image> <pattern> [--limit N] [--expect RVA] [--save-index K]
//         mamlscan --batch <jobfile>
//
// Batch job file: one job per line, TAB separated
//     name <TAB> image <TAB> expect-rva-hex <TAB> save-index <TAB> pattern
// Output per job, TAB separated
//     name <TAB> OK|MISS|MULTI|NONE|ERR <TAB> hits <TAB> rva[,rva...] <TAB> detail
#include "maml/mamlscan.hpp"
#include "maml/v1.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace maml;

// Anonymous namespace rather than file-scope `static`: same internal
// linkage, but it also covers the types declared here, and it is the form
// clang-tidy's misc-use-anonymous-namespace asks for.
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

struct Scan {
    std::string status;
    std::vector<uint64_t> rvas;
    std::string detail;
};

// save_index 0 is the match offset; 1+ indexes named captures in schema order.
Scan scan(const std::vector<uint8_t>& img, const std::string& pattern,
    size_t save_index, size_t limit) {
    Scan out;
    try {
        const v1::Pattern pat(pattern);
        for (const auto& hit : pat.find_all(v1::Image{ img }, limit + 1)) {
            uint64_t rva = hit.offset;
            if (save_index != 0) {
                if (save_index > hit.captures.size()) {
                    out.status = "ERR";
                    out.detail = "save index " + std::to_string(save_index) +
                                 " but only " + std::to_string(hit.captures.size()) + " saved";
                    return out;
                }
                rva = hit.captures[save_index - 1].data.value;
            }
            out.rvas.push_back(rva);
            if (out.rvas.size() > limit)
                break;
        }
    } catch (const std::exception& e) {
        out.status = "ERR";
        out.detail = e.what();
        return out;
    }
    return out;
}

void classify(Scan& s, bool have_expect, uint64_t expect) {
    if (s.status == "ERR")
        return;
    if (s.rvas.empty())
        s.status = "NONE";
    else if (s.rvas.size() > 1)
        s.status = "MULTI";
    else if (!have_expect)
        s.status = "OK";
    else
        s.status = (s.rvas[0] == expect) ? "OK" : "MISS";
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

int run_batch(const char* jobfile) {
    std::ifstream jf(jobfile);
    if (!jf) {
        fprintf(stderr, "cannot open %s\n", jobfile);
        return 2;
    }
    // One image is ~130 MB; cache so a batch of 90 patterns loads it once.
    std::string cached_path;
    std::vector<uint8_t> cached;
    std::string line;
    while (std::getline(jf, line)) {
        if (line.empty())
            continue;
        std::vector<std::string> f;
        size_t start = 0;
        for (size_t i = 0; i <= line.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                f.push_back(line.substr(start, i - start));
                start = i + 1;
            }
        }
        if (f.size() < 5) {
            printf("%s\tERR\t0\t\tmalformed job\n", f.empty() ? "?" : f[0].c_str());
            continue;
        }
        const std::string& name = f[0];
        if (f[1] != cached_path) {
            cached = load(f[1]);
            cached_path = f[1];
            if (cached.empty()) {
                printf("%s\tERR\t0\t\tcannot read %s\n", name.c_str(), f[1].c_str());
                cached_path.clear();
                continue;
            }
        }
        const bool have_expect = !f[2].empty();
        const uint64_t expect = have_expect ? strtoull(f[2].c_str(), nullptr, 16) : 0;
        const size_t save_index = f[3].empty() ? 0 : strtoul(f[3].c_str(), nullptr, 10);
        std::string pattern = f[4];
        for (size_t i = 5; i < f.size(); ++i)
            pattern += "\t" + f[i];

        Scan s = scan(cached, pattern, save_index, 8);
        classify(s, have_expect, expect);
        printf("%s\t%s\t%zu\t%s\t%s\n", name.c_str(), s.status.c_str(),
            s.rvas.size(), join(s.rvas, 8).c_str(), s.detail.c_str());
        fflush(stdout);
    }
    return 0;
}

int run_scan(const char* image, const char* jobfile) {
    std::vector<uint8_t> img = load(image);
    if (img.empty()) {
        fprintf(stderr, "cannot read %s\n", image);
        return 2;
    }
    std::ifstream f(jobfile);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty())
            continue;
        const size_t a = line.find('\t');
        const size_t b = line.find('\t', a + 1);
        const std::string name = line.substr(0, a);
        const size_t save = strtoul(line.substr(a + 1, b - a - 1).c_str(), nullptr, 10);
        const std::string rest = line.substr(b + 1);
        std::string pat = rest;
        const size_t c = rest.find('\t');
        if (c != std::string::npos)
            pat = rest.substr(0, c);
        try {
            const v1::Pattern pattern(pat);
            auto hits = pattern.find_all(v1::Image{ img }, 2);
            if (hits.empty()) {
                printf("%s\tNONE\t0\t0\t0\n", name.c_str());
            } else {
                uint64_t rva = hits[0].offset;
                if (save != 0) {
                    if (save > hits[0].captures.size()) {
                        printf("%s\tERR\t0\t0\t0\n", name.c_str());
                        fflush(stdout);
                        continue;
                    }
                    rva = hits[0].captures[save - 1].data.value;
                }
                printf("%s\tOK\t%llx\t%zu\t%zu\n", name.c_str(),
                    (unsigned long long)rva, hits.size(), hits.size());
            }
        } catch (const std::exception&) {
            printf("%s\tERR\t0\t0\t0\n", name.c_str());
        }
        fflush(stdout);
    }
    return 0;
}

// Explicit dialect selection keeps identical byte spellings unambiguous.
int run_v1(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        fprintf(stderr, "usage: mamlscan <image> <pattern> [--capture NAME] [--limit N] [--expect HEX]\n");
        return 2;
    }
    try {
        std::string capture;
        uint64_t limit = 32, expected = 0;
        bool have_expect = false;
        for (size_t i = 2; i < args.size(); i += 2) {
            if (i + 1 == args.size())
                throw std::runtime_error("Option requires an argument");
            if (args[i] == "--capture") {
                capture = args[i + 1];
                continue;
            }
            if (args[i] != "--limit" && args[i] != "--expect")
                throw std::runtime_error("Unknown v1 option: " + args[i]);
            const auto& text = args[i + 1];
            uint64_t number = 0;
            auto r = std::from_chars(text.data(), text.data() + text.size(), number, args[i] == "--expect" ? 16 : 10);
            if (r.ec != std::errc{} || r.ptr != text.data() + text.size())
                throw std::runtime_error("Invalid numeric argument");
            if (args[i] == "--limit")
                limit = number;
            else {
                expected = number;
                have_expect = true;
            }
        }
        if (!limit || limit >= SIZE_MAX)
            throw std::runtime_error("limit must be positive and below SIZE_MAX");
        const v1::Pattern pattern(args[1]);
        if (!capture.empty())
            (void)v1::Match{ 0, pattern.schema(), {} }.capture(capture);
        auto data = load(args[0]);
        if (data.empty())
            throw std::runtime_error("Cannot read nonempty image: " + args[0]);
        Scan result;
        for (const auto& hit : pattern.find_all(v1::Image{ data }, capture.empty() ? size_t(limit) + 1 : 0)) {
            if (capture.empty())
                result.rvas.push_back(hit.offset);
            else if (auto v = hit.capture(capture))
                result.rvas.push_back(v->value);
            if (result.rvas.size() > limit)
                break;
        }
        classify(result, have_expect, expected);
        printf("%s hits=%zu %s\n", result.status.c_str(), result.rvas.size(), join(result.rvas, size_t(limit)).c_str());
        return result.status == "OK" ? 0 : 1;
    } catch (const std::exception& e) {
        fprintf(stderr, "ERR %s\n", e.what());
        return 1;
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--dialect") == 0) {
            if (i + 1 == argc || strcmp(argv[++i], "maml-v1") != 0) {
                fprintf(stderr, "Unknown dialect; MAML is v1 only\n");
                return 2;
            }
            continue;
        }
        args.emplace_back(argv[i]);
    }
    if (args.size() >= 2 && args[0] == "--batch")
        return run_batch(args[1].c_str());
    if (args.size() >= 3 && args[0] == "--scan")
        return run_scan(args[1].c_str(), args[2].c_str());
    return run_v1(args);
}
