// Durability of generated patterns across four real builds of the same DLL.
//
// Under test: METHOD.md's 72% at one version step, and its stronger note that
// "every hit was unique at every distance -- zero ambiguous matches", i.e. a
// surviving pattern finds the right thing and a non-surviving one finds
// nothing. That asymmetry is what lets uniqueness stand in for resolution
// where there are no symbols (these DLLs export exactly one name). It is also
// falsifiable, so ambiguity is COUNTED rather than assumed away.
//
// Targets come from .pdata, the x64 exception directory: a complete function
// list needing no symbols.
#include "maml/generate.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

using namespace maml;

// Where flatten.py wrote its images and manifests. An env var rather than a
// baked path: the inputs are large binaries that live outside this repo.
static std::string datadir() {
    const char* d = getenv("MAML_DURABILITY_DIR");
    return d ? std::string(d) : std::string("/tmp/eido");
}

struct Build {
    std::string tag;
    std::vector<uint8_t> bytes;
    std::vector<generate::Range> code, rodata, funcs;
    generate::Image view() const { return { bytes, code, rodata, funcs }; }
};

static Build load(const std::string& tag) {
    Build b;
    b.tag = tag;
    {
        std::ifstream f(datadir() + "/" + tag + ".img", std::ios::binary | std::ios::ate);
        const std::streamsize n = f.tellg();
        f.seekg(0);
        b.bytes.resize((size_t)n);
        f.read((char*)b.bytes.data(), n);
    }
    std::ifstream m(datadir() + "/" + tag + ".txt");
    std::string kind;
    uint64_t x = 0, y = 0;
    while (m >> kind) {
        if (kind == "size") { m >> x; continue; }
        m >> x >> y;
        if (kind == "code") b.code.push_back({ x, y });
        else if (kind == "rodata") b.rodata.push_back({ x, y });
        else if (kind == "func") b.funcs.push_back({ x, y });
    }
    return b;
}

static size_t hits(const Build& b, const generate::Candidate& c) {
    try {
        return v1::Pattern(c.pattern).find_all(v1::Image{ b.bytes }, 2).size();
    } catch (...) {
        return 0;
    }
}

int main(int argc, char** argv) {
    const size_t sample = argc > 1 ? (size_t)atoi(argv[1]) : 150;
    const int want = argc > 2 ? atoi(argv[2]) : 4;

    // Build assignment matters more than it looks. 69273 and 69497 are 86.6%
    // byte-identical while every other pair is ~15%, so using those two as A
    // and B makes "dual-build verified" mean nothing -- it is the same-image
    // case verified() explicitly refuses, and the giveaway was 100% of
    // A-unique patterns also unique in B.
    const char* ta = argc > 3 ? argv[3] : "69382";
    const char* tb = argc > 4 ? argv[4] : "69404";
    const char* tc = argc > 5 ? argv[5] : "69273";
    const char* td = argc > 6 ? argv[6] : "69497";
    Build A = load(ta), B = load(tb), C = load(tc), D = load(td);
    printf("generate+verify on %s + %s ; survival on %s and %s\n",
           A.tag.c_str(), B.tag.c_str(), C.tag.c_str(), D.tag.c_str());
    printf("A: %.1fMB code=%zu rodata=%zu funcs=%zu\n\n",
           A.bytes.size() / 1e6, A.code.size(), A.rodata.size(), A.funcs.size());

    generate::Options o;
    o.want = want;

    size_t targets = 0, with_any = 0, pat_a = 0, pat_ab = 0;
    size_t surv_c = 0, surv_d = 0, amb_c = 0, amb_d = 0;
    size_t tgt_c = 0, tgt_d = 0, single_c = 0, single_d = 0;
    size_t tgt_dual = 0, tgt_multi = 0, tgt_multi_surv = 0;
    size_t by_strategy[4] = { 0, 0, 0, 0 }, surv_strategy[4] = { 0, 0, 0, 0 };

    const size_t step = std::max<size_t>(1, A.funcs.size() / sample);
    for (size_t i = 0; i < A.funcs.size(); i += step) {
        const uint64_t t = A.funcs[i].begin;
        ++targets;
        const auto cands = generate::candidates(A.view(), t, o);
        if (cands.empty())
            continue;

        std::vector<generate::Candidate> uniq_a;
        for (const auto& c : cands)
            if (hits(A, c) == 1)
                uniq_a.push_back(c);
        pat_a += uniq_a.size();
        if (!uniq_a.empty())
            ++with_any;

        std::vector<generate::Candidate> uniq_ab;
        for (const auto& c : uniq_a)
            if (hits(B, c) == 1)
                uniq_ab.push_back(c);
        pat_ab += uniq_ab.size();
        if (uniq_ab.empty())
            continue;

        bool any_c = false, any_d = false;
        for (const auto& c : uniq_ab) {
            const int s = (int)c.strategy;
            ++by_strategy[s];
            const size_t hc = hits(C, c), hd = hits(D, c);
            if (hc == 1) { ++surv_c; ++surv_strategy[s]; any_c = true; }
            else if (hc > 1) ++amb_c;
            if (hd == 1) { ++surv_d; any_d = true; }
            else if (hd > 1) ++amb_d;
        }
        ++tgt_dual;
        if (uniq_ab.size() >= 2) ++tgt_multi;
        if (uniq_ab.size() >= 2 && any_c) ++tgt_multi_surv;
        if (any_c) ++tgt_c;
        if (any_d) ++tgt_d;
        if (hits(C, uniq_ab[0]) == 1) ++single_c;
        if (hits(D, uniq_ab[0]) == 1) ++single_d;
    }

    auto pct = [](size_t a, size_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; };
    printf("targets sampled                 %6zu\n", targets);
    printf("  with >=1 pattern unique in A  %6zu  (%.1f%%)\n", with_any, pct(with_any, targets));
    printf("patterns unique in A            %6zu\n", pat_a);
    printf("  also unique in B              %6zu  (%.1f%%)\n", pat_ab, pct(pat_ab, pat_a));
    printf("\nPER-PATTERN survival of the dual-build set (%zu patterns)\n", pat_ab);
    printf("  still unique in C             %6zu  (%.1f%%)   ambiguous %zu\n", surv_c, pct(surv_c, pat_ab), amb_c);
    printf("  still unique in D             %6zu  (%.1f%%)   ambiguous %zu\n", surv_d, pct(surv_d, pat_ab), amb_d);
    printf("\ntargets with >=1 dual-build anchor  %6zu  (%.1f%% of sampled)\n",
           tgt_dual, pct(tgt_dual, targets));
    printf("  of those, with >=2 anchors        %6zu  (%.1f%%)\n", tgt_multi, pct(tgt_multi, tgt_dual));
    printf("  and >=2 anchors AND survives      %6zu  (%.1f%% of multi-anchor)\n",
           tgt_multi_surv, pct(tgt_multi_surv, tgt_multi));
    printf("\nPER-TARGET: several anchors vs one (denominator = targets with a dual-build anchor)\n");
    printf("  C: >=1 of %d survives         %6zu  (%.1f%%)   first-anchor-only %zu (%.1f%%)\n",
           want, tgt_c, pct(tgt_c, tgt_dual), single_c, pct(single_c, tgt_dual));
    printf("  D: >=1 of %d survives         %6zu  (%.1f%%)   first-anchor-only %zu (%.1f%%)\n",
           want, tgt_d, pct(tgt_d, tgt_dual), single_d, pct(single_d, tgt_dual));
    static const char* nm[4] = { "Body", "Xref", "StringAnchor", "RipRef" };
    printf("\nBY STRATEGY (survival into C)\n");
    for (int s = 0; s < 4; ++s)
        if (by_strategy[s])
            printf("  %-14s %5zu dual-build  ->  %5zu survive (%.1f%%)\n",
                   nm[s], by_strategy[s], surv_strategy[s], pct(surv_strategy[s], by_strategy[s]));
    return 0;
}
