// Does a surviving pattern find the RIGHT function, or merely something?
//
// The uniqueness run reproduced METHOD.md's 72% and 90%, but it could not test
// the claim those rest on: "a pattern that survives finds the right thing, and
// one that does not survive finds nothing." Uniqueness cannot distinguish
// "found the target" from "found something else, exactly once".
//
// Ground truth is a BinDiff function mapping between the generating build
// (69404-devirt) and a third build (69497-deob), so a resolved address can be
// checked rather than assumed.
#include "maml/generate.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace maml;

// Where flatten.py wrote its images and manifests. An env var rather than a
// baked path: the inputs are large binaries that live outside this repo.
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

// The resolution rule resolves_uniquely uses: read the capture slot when the
// pattern captures, otherwise subtract the anchor delta from the match.
static bool resolve(const Build& b, const generate::Candidate& c,
                    uint64_t* out, size_t* nhits) {
    auto comp = locate::compile(c.pattern);
    locate::prime(comp, b.bytes);
    const auto h = locate::find_all(b.bytes, comp, c.save_index, 2);
    *nhits = h.size();
    if (h.size() != 1)
        return false;
    *out = c.save_index != 0 ? h[0].value
                             : (uint64_t)((int64_t)h[0].offset - c.anchor_delta);
    return true;
}

int main(int argc, char** argv) {
    const size_t sample = argc > 1 ? (size_t)atoi(argv[1]) : 300;
    const int want = argc > 2 ? atoi(argv[2]) : 16;
    const double min_conf = argc > 3 ? atof(argv[3]) : 0.5;

    Build A = load("69404"), B = load("69382"), E = load("69497deob");

    std::unordered_map<uint64_t, uint64_t> gt;   // 69404 rva -> 69497deob rva
    {
        std::ifstream f(datadir() + "/map.txt");
        uint64_t a = 0, e = 0;
        double conf = 0;
        while (f >> a >> e >> conf)
            if (conf >= min_conf)
                gt[a] = e;
    }
    printf("generate 69404-devirt, dual-build vs 69382-devirt, resolve in 69497-deob\n");
    printf("ground truth: BinDiff, confidence >= %.2f, %zu mapped functions\n\n", min_conf, gt.size());

    generate::Options o;
    o.want = want;

    size_t targets = 0, pat_ab = 0;
    size_t hit1 = 0, correct = 0, wrong = 0, absent = 0, ambiguous = 0;
    size_t tgt_any_correct = 0, tgt_any_wrong = 0;
    size_t multi = 0, multi_correct = 0, single = 0, single_correct = 0;
    size_t consensus = 0, consensus_right = 0;

    const size_t step = std::max<size_t>(1, A.funcs.size() / sample);
    for (size_t i = 0; i < A.funcs.size(); i += step) {
        const uint64_t t = A.funcs[i].begin;
        auto g = gt.find(t);
        if (g == gt.end())
            continue;                      // no ground truth for this target
        const uint64_t t_e = g->second;
        ++targets;

        std::vector<generate::Candidate> ok;
        for (const auto& c : generate::candidates(A.view(), t, o)) {
            size_t nh = 0;
            uint64_t r = 0;
            if (!resolve(A, c, &r, &nh) || r != t)
                continue;                  // must be unique AND correct at home
            if (!resolve(B, c, &r, &nh))
                continue;                  // dual-build: unique in the second
            ok.push_back(c);
        }
        pat_ab += ok.size();
        if (ok.empty())
            continue;

        bool any_ok = false, any_bad = false;
        std::vector<uint64_t> resolved;
        for (const auto& c : ok) {
            size_t nh = 0;
            uint64_t r = 0;
            const bool uniq = resolve(E, c, &r, &nh);
            if (!uniq) { if (nh > 1) ++ambiguous; else ++absent; continue; }
            ++hit1;
            resolved.push_back(r);
            if (r == t_e) { ++correct; any_ok = true; }
            else { ++wrong; any_bad = true; }
        }
        // Consensus: do two or more anchors independently resolve to the SAME
        // address? If agreement implies correctness, it is a check a consumer
        // can apply with no ground truth at all -- which is the only kind of
        // check that helps in the field.
        if (resolved.size() >= 2) {
            std::sort(resolved.begin(), resolved.end());
            size_t best = 1, run = 1;
            uint64_t bestval = resolved[0];
            for (size_t z = 1; z < resolved.size(); ++z) {
                if (resolved[z] == resolved[z-1]) { ++run; if (run > best) { best = run; bestval = resolved[z]; } }
                else run = 1;
            }
            if (best >= 2) {
                ++consensus;
                if (bestval == t_e) ++consensus_right;
            }
        }
        if (any_ok) ++tgt_any_correct;
        if (any_bad) ++tgt_any_wrong;
        if (ok.size() >= 2) { ++multi; if (any_ok) ++multi_correct; }
        else { ++single; if (any_ok) ++single_correct; }
    }

    auto pct = [](size_t a, size_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; };
    printf("targets with ground truth + >=1 dual-build pattern : %zu\n", targets);
    printf("dual-build patterns                                : %zu\n\n", pat_ab);
    printf("IN THE THIRD BUILD, per pattern\n");
    printf("  matched exactly once      %5zu  (%.1f%%)\n", hit1, pct(hit1, pat_ab));
    printf("    ...and resolved RIGHT   %5zu  (%.1f%% of all, %.1f%% of unique hits)\n",
           correct, pct(correct, pat_ab), pct(correct, hit1));
    printf("    ...but resolved WRONG   %5zu  (%.1f%% of unique hits)\n", wrong, pct(wrong, hit1));
    printf("  matched more than once    %5zu  (%.1f%%)\n", ambiguous, pct(ambiguous, pat_ab));
    printf("  no match                  %5zu  (%.1f%%)\n\n", absent, pct(absent, pat_ab));
    printf("PER TARGET\n");
    printf("  >=1 anchor resolves right %5zu  (%.1f%%)\n", tgt_any_correct, pct(tgt_any_correct, targets));
    printf("  >=1 anchor resolves WRONG %5zu  (%.1f%%)\n", tgt_any_wrong, pct(tgt_any_wrong, targets));
    printf("  one anchor  : %4zu targets, %4zu right (%.1f%%)\n", single, single_correct, pct(single_correct, single));
    printf("  >=2 anchors : %4zu targets, %4zu right (%.1f%%)\n", multi, multi_correct, pct(multi_correct, multi));
    printf("\nCONSENSUS (>=2 anchors resolving to the SAME address, no ground truth needed)\n");
    printf("  targets with consensus    %5zu\n", consensus);
    printf("  consensus was CORRECT     %5zu  (%.1f%%)\n", consensus_right, pct(consensus_right, consensus));
    return 0;
}
