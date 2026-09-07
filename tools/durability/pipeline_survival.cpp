// Do locator pipelines survive a build step better than byte patterns?
//
// Measure pipeline durability against byte patterns using shared targets.
//
// The comparison is deliberately apples-to-apples: both shapes are measured
// on THE SAME targets, with the same BinDiff ground truth, resolved in the
// same third build. A pipeline rate quoted against a different target set
// would be meaningless -- the sets differ enormously in difficulty.
#include "maml/generate.hpp"
#include "maml/pipeline.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace maml;

static std::string datadir() {
    const char* d = getenv("MAML_DURABILITY_DIR");
    return d ? std::string(d) : std::string("/tmp/eido");
}

struct Build {
    std::vector<uint8_t> bytes;
    std::vector<generate::Range> code, rodata, funcs;
    generate::Image view() const { return { bytes, code, rodata, funcs }; }
};

static Build load(const std::string& tag) {
    Build b;
    std::ifstream f(datadir() + "/" + tag + ".img", std::ios::binary | std::ios::ate);
    const std::streamsize n = f.tellg();
    f.seekg(0);
    b.bytes.resize((size_t)n);
    f.read((char*)b.bytes.data(), n);
    std::ifstream m(datadir() + "/" + tag + ".txt");
    std::string k;
    uint64_t x = 0, y = 0;
    while (m >> k) {
        if (k == "size") { m >> x; continue; }
        m >> x >> y;
        if (k == "code") b.code.push_back({ x, y });
        else if (k == "rodata") b.rodata.push_back({ x, y });
        else if (k == "func") b.funcs.push_back({ x, y });
    }
    return b;
}

// A string is usable in a pipeline only if it round-trips through the quoting.
// Skipping the rest is honest: they are a property of the syntax, not of
// durability, and silently mangling them would corrupt the measurement.
static bool quotable(const std::string& s) {
    if (s.size() < 8 || s.size() > 60)
        return false;
    for (unsigned char c : s)
        if (c == '"' || c == '\\' || c < 0x20 || c > 0x7e)
            return false;
    return true;
}

int main(int argc, char** argv) {
    const size_t cap = argc > 1 ? (size_t)atoi(argv[1]) : 400;
    const double min_conf = argc > 2 ? atof(argv[2]) : 0.95;

    Build A = load("69404"), B = load("69382"), E = load("69497deob");

    std::unordered_map<uint64_t, uint64_t> gt;
    {
        std::ifstream f(datadir() + "/map.txt");
        uint64_t a = 0, e = 0;
        double conf = 0;
        while (f >> a >> e >> conf)
            if (conf >= min_conf)
                gt[a] = e;
    }
    printf("pipelines built on 69404-devirt, replayed in 69497-deob\n");
    printf("ground truth: BinDiff confidence >= %.2f, %zu mapped functions\n\n",
           min_conf, gt.size());

    // Build one pipeline per target: the first string whose xref chain lands
    // on a function we have ground truth for.
    const auto strs = generate::strings(A.view());
    std::unordered_map<uint64_t, std::string> pipe_for;
    for (const generate::Str& s : strs) {
        if (pipe_for.size() >= cap)
            break;
        if (s.rva + s.len > A.bytes.size())
            continue;
        const std::string text((const char*)A.bytes.data() + s.rva, s.len);
        if (!quotable(text))
            continue;
        const std::string src = "str \"" + text + "\" -> xref -> func -> unique";
        const auto r = pipeline::run(A.view(), src);
        if (!r.ok || r.addresses.size() != 1)
            continue;
        const uint64_t t = r.addresses[0];
        if (!gt.count(t) || pipe_for.count(t))
            continue;
        pipe_for[t] = src;
    }
    printf("targets with a working pipeline and ground truth: %zu\n\n", pipe_for.size());

    size_t p_ok = 0, p_wrong = 0, p_none = 0;
    size_t b_tried = 0, b_ok = 0, b_wrong = 0, b_none = 0;
    generate::Options o;
    o.want = 16;

    for (const auto& kv : pipe_for) {
        const uint64_t t = kv.first, t_e = gt.at(t);

        // 1. the pipeline, replayed verbatim in the third build
        const auto r = pipeline::run(E.view(), kv.second);
        // A stage failing for want of SUBSTRATE is a configuration error, not
        // a durability result. It read as "0 of 40 survived" once, because the
        // third build's manifest carried no funcs and this loop lumped the
        // executor's explicit error in with a genuine non-resolution. The
        // executor said so plainly -- "func: image has no funcs ranges" -- and
        // nothing was reading it.
        if (!r.error.empty() && r.error.find("image has no") != std::string::npos) {
            fprintf(stderr, "::error:: %s -- fix the manifest, this is not a result\n",
                    r.error.c_str());
            return 2;
        }
        if (!r.ok || r.addresses.size() != 1)
            ++p_none;
        else if (r.addresses[0] == t_e)
            ++p_ok;
        else
            ++p_wrong;

        // 2. byte patterns for the SAME target, dual-build verified, then
        //    resolved in the same third build by consensus.
        std::vector<generate::Candidate> ok;
        for (const auto& c : generate::candidates(A.view(), t, o)) {
            auto comp = locate::compile(c.pattern);
            locate::prime(comp, A.bytes);
            auto h = locate::find_all(A.bytes, comp, c.save_index, 2);
            if (h.size() != 1)
                continue;
            const uint64_t r0 = c.save_index != 0
                ? h[0].value : (uint64_t)((int64_t)h[0].offset - c.anchor_delta);
            if (r0 != t)
                continue;
            locate::prime(comp, B.bytes);
            if (locate::find_all(B.bytes, comp, c.save_index, 2).size() != 1)
                continue;
            ok.push_back(c);
        }
        if (ok.empty())
            continue;
        ++b_tried;
        const auto groups = generate::resolve_consensus(E.bytes, ok);
        if (groups.empty())
            ++b_none;
        else if (groups[0].address == t_e)
            ++b_ok;
        else
            ++b_wrong;
    }

    auto pct = [](size_t a, size_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; };
    const size_t n = pipe_for.size();
    printf("PIPELINE  str \"...\" -> xref -> func -> unique, replayed\n");
    printf("  resolved RIGHT   %5zu  (%.1f%%)\n", p_ok, pct(p_ok, n));
    printf("  resolved WRONG   %5zu  (%.1f%%)\n", p_wrong, pct(p_wrong, n));
    printf("  did not resolve  %5zu  (%.1f%%)\n\n", p_none, pct(p_none, n));
    printf("BYTE PATTERNS on the SAME targets (%zu of them afforded any)\n", b_tried);
    printf("  consensus RIGHT  %5zu  (%.1f%% of %zu)\n", b_ok, pct(b_ok, b_tried), b_tried);
    printf("  consensus WRONG  %5zu  (%.1f%%)\n", b_wrong, pct(b_wrong, b_tried));
    printf("  no anchor held   %5zu  (%.1f%%)\n", b_none, pct(b_none, b_tried));
    return 0;
}
