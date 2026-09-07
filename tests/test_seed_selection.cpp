// select_seed's two measured defects: it skipped one-byte runs, and it
// truncated counts at 4096 and then fell back to longest-wins.
#include "catch.hpp"
#include "maml.hpp"
#include <algorithm>
#include <vector>
using namespace maml;

// Filler is 0x90 so no byte under test appears by accident. Stride 16 keeps
// every placed sequence disjoint, and all placements stay under 0x80000.
//
// `plant_match` writes one real occurrence of `41 42 ? 43 44 45` at 1'000'000,
// well clear of the strided runs. Without it the image holds plenty of each
// RUN but no MATCH of the whole pattern, and every find()-based assertion
// below fails on has_value() for the wrong reason.
static std::vector<uint8_t> make_seed_image(size_t n_4142, size_t n_434445, size_t n_d0,
                                            bool plant_match = false) {
    std::vector<uint8_t> img(2u * 1024 * 1024, 0x90);
    size_t p = 0;
    for (size_t i = 0; i < n_4142; ++i)   { img[p] = 0x41; img[p+1] = 0x42; p += 16; }
    for (size_t i = 0; i < n_434445; ++i) { img[p] = 0x43; img[p+1] = 0x44; img[p+2] = 0x45; p += 16; }
    for (size_t i = 0; i < n_d0; ++i)     { img[p] = 0xD0; p += 16; }
    if (plant_match) {
        const size_t at = 1000000;
        img[at] = 0x41; img[at+1] = 0x42;          // img[at+2] stays 0x90, the `?`
        img[at+3] = 0x43; img[at+4] = 0x44; img[at+5] = 0x45;
    }
    return img;
}

static constexpr size_t kPlantedMatch = 1000000;

TEST_CASE("select_seed ranks one-byte runs", "[seed]") {
    // 41 42 occurs 5000 times; D0 occurs 3 times. The rare single byte wins.
    auto img = make_seed_image(5000, 0, 3);
    auto fx  = locate::fixed_bytes("41 42 ? D0");
    auto s   = locate::select_seed(img, fx);
    REQUIRE(s.bytes == std::vector<uint8_t>{ 0xD0 });
    REQUIRE(s.offset == 3);
}

TEST_CASE("select_seed counts exactly by default", "[seed]") {
    // Both runs exceed the load-time cap, and the LONGER one is commoner.
    auto img = make_seed_image(8000, 20000, 0);
    auto fx  = locate::fixed_bytes("41 42 ? 43 44 45");

    SECTION("capped: counts truncate, so longest wins the tiebreak") {
        auto s = locate::select_seed(img, fx, locate::kSeedCapLoadTime);
        REQUIRE(s.bytes == std::vector<uint8_t>{ 0x43, 0x44, 0x45 });
    }
    SECTION("exact: the rarer run wins") {
        auto s = locate::select_seed(img, fx, locate::kSeedCapExact);
        REQUIRE(s.bytes == std::vector<uint8_t>{ 0x41, 0x42 });
    }
    SECTION("exact is the default") {
        REQUIRE(locate::select_seed(img, fx).bytes == std::vector<uint8_t>{ 0x41, 0x42 });
    }
}

TEST_CASE("seed choice changes cost, never the answer", "[seed]") {
    // The safety property behind every change in this plan: find() verifies each
    // surviving candidate against the full atom matcher and returns the first
    // match in increasing offset order, so a worse seed costs candidates, not
    // correctness.
    auto img = make_seed_image(8000, 20000, 0, /*plant_match=*/true);
    const char* pat = "41 42 ? 43 44 45";

    locate::Seed common;                       // the run the capped path would pick
    common.offset = 3;
    common.bytes  = { 0x43, 0x44, 0x45 };
    locate::Seed rare;                         // the run the exact path picks
    rare.offset = 0;
    rare.bytes  = { 0x41, 0x42 };

    auto a = locate::find(img, pat, 0, &common);
    auto b = locate::find(img, pat, 0, &rare);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(a->offset == b->offset);
    REQUIRE(a->offset == kPlantedMatch);
    REQUIRE(a->value  == b->value);
}

TEST_CASE("the string overload of find seeds with kSeedCapLoadTime", "[compiled]") {
    // The load-bearing line is `mamlscan.hpp`'s `find(image, pattern, ...)`
    // calling `prime(c, image, kSeedCapLoadTime)` when no offline Seed is
    // supplied. Deleting that third argument (defaulting back to
    // kSeedCapExact) compiles and leaves the rest of the suite green, at the
    // cost of ~0.25s per pattern at DLL load time -- so it needs its own
    // pin. Same fixture and pattern as "select_seed counts exactly by
    // default": the longer run 43 44 45 is commoner (20000) than 41 42
    // (8000), so a cap-truncated count picks the wrong one and drags in
    // 2.5x more candidates.
    auto img = make_seed_image(8000, 20000, 0, /*plant_match=*/true);
    const char* pat = "41 42 ? 43 44 45";

    // Capped (the string overload, no seed supplied): picks "43 44 45" and
    // therefore scans through every one of the 20000 planted decoys before
    // the real match at kPlantedMatch.
    auto capped = locate::find(img, pat, 0, nullptr);
    REQUIRE(capped.has_value());
    REQUIRE(capped->offset == kPlantedMatch);
    REQUIRE(capped->candidates == 20001);

    // Exact (Compiled overload, primed with kSeedCapExact): picks "41 42"
    // and scans through the 8000 decoys instead.
    auto c = locate::compile(pat);
    locate::prime(c, img, locate::kSeedCapExact);
    REQUIRE(c.seed.bytes == std::vector<uint8_t>{ 0x41, 0x42 });
    auto exact = locate::find(img, c, 0);
    REQUIRE(exact.has_value());
    REQUIRE(exact->offset == kPlantedMatch);
    REQUIRE(exact->candidates == 8001);
}

TEST_CASE("compile/prime/find match the string form exactly", "[compiled]") {
    auto img = make_seed_image(8000, 20000, 0, /*plant_match=*/true);
    const char* pat = "41 42 ? 43 44 45";

    auto c = locate::compile(pat);
    locate::prime(c, img);
    auto viaCompiled = locate::find(img, c, 0);
    auto viaString   = locate::find(img, pat, 0);

    REQUIRE(viaCompiled.has_value());
    REQUIRE(viaString.has_value());
    REQUIRE(viaCompiled->offset == viaString->offset);
    REQUIRE(viaCompiled->offset == kPlantedMatch);
    REQUIRE(viaCompiled->value  == viaString->value);
}

TEST_CASE("compile throws where the string form returns nullopt", "[compiled]") {
    auto img = make_seed_image(10, 0, 0);
    // The string overload's contract is nullopt, not an exception. Consumers
    // depend on that; only the new entry point throws.
    REQUIRE(!locate::find(img, "48 8B [5-").has_value());
    REQUIRE_THROWS_AS(locate::compile("48 8B [5-"), ParseException);
}

TEST_CASE("an empty Seed falls through to selection", "[compiled]") {
    // FindPatternBMAny in the consumer passes &S unconditionally, where S is
    // default-constructed when no offline seed was supplied. That must still
    // select rather than scan for an empty needle.
    auto img = make_seed_image(8000, 20000, 0, /*plant_match=*/true);
    locate::Seed empty;
    REQUIRE(!empty.ok());
    auto a = locate::find(img, "41 42 ? 43 44 45", 0, &empty);
    auto b = locate::find(img, "41 42 ? 43 44 45", 0, nullptr);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(a->offset == b->offset);
    // Load-bearing: weakening the guard to just `seed` (dropping `->ok()`)
    // installs the empty Seed as-is instead of falling through to
    // select_seed. `find`'s own `!c.seed.ok()` check then routes to the
    // UNSEEDED branch, which finds the same first offset by scanning with the
    // matcher directly -- so `offset` still matches by accident -- but that
    // branch never touches candidates/verified, so candidates stays 0. Only
    // this assertion catches it; the offset comparison above does not.
    REQUIRE(a->candidates > 0);
}

TEST_CASE("a primed Compiled is reusable across images", "[compiled]") {
    // Seed choice is a property of the (pattern, image) PAIR, so these two images
    // are built so the same pattern selects a different run in each: in `small`
    // 43 44 45 occurs 5 times against 41 42's 30, and in `large` that reverses.
    // If re-priming did nothing, the second assertion would still see 43 44 45.
    auto small = make_seed_image(30, 5, 0);
    auto large = make_seed_image(8000, 20000, 0);
    auto c = locate::compile("41 42 ? 43 44 45");

    locate::prime(c, small);
    REQUIRE(c.seed.bytes == std::vector<uint8_t>{ 0x43, 0x44, 0x45 });

    locate::prime(c, large);
    REQUIRE(c.seed.bytes == std::vector<uint8_t>{ 0x41, 0x42 });
}

TEST_CASE("find_all returns every match in offset order", "[findall]") {
    // 41 42 placed at stride 16, so 5 matches at 0, 16, 32, 48, 64.
    auto img = make_seed_image(5, 0, 0);
    auto c = locate::compile("41 42");
    locate::prime(c, img);

    auto all = locate::find_all(img, c);
    REQUIRE(all.size() == 5);
    for (size_t i = 0; i < all.size(); ++i)
        REQUIRE(all[i].offset == i * 16);
}

TEST_CASE("find_all honours limit, and 0 means unbounded", "[findall]") {
    auto img = make_seed_image(5, 0, 0);
    auto c = locate::compile("41 42");
    locate::prime(c, img);

    REQUIRE(locate::find_all(img, c, 0, 2).size() == 2);
    REQUIRE(locate::find_all(img, c, 0, 0).size() == 5);
    REQUIRE(locate::find_all(img, c, 0, 99).size() == 5);
}

TEST_CASE("find_all agrees with find on the first match", "[findall]") {
    auto img = make_seed_image(5, 0, 0);
    auto c = locate::compile("41 42");
    locate::prime(c, img);

    auto one = locate::find(img, c, 0);
    auto all = locate::find_all(img, c);
    REQUIRE(one.has_value());
    REQUIRE(!all.empty());
    REQUIRE(one->offset == all.front().offset);
    REQUIRE(one->value  == all.front().value);
}

TEST_CASE("find_all counters are cumulative, and the last carries the totals", "[findall]") {
    // "41 42" alone can't distinguish candidates from verified: every seed
    // hit in that fixture also passes the fixed-byte re-check, so the two
    // counters move in lockstep and a bug that swapped which field gets
    // which value would go undetected. This fixture forces them apart.
    //
    // 2 bogus, standalone "41 42" sit BEFORE 5 real "41 42 ? 43 44 45"
    // matches, so the seed ("41 42": rarer than "43 44 45", which also gets
    // 10 bogus standalone occurrences elsewhere to keep it that way) hits
    // those 2 bogus positions first. They fail the fixed-byte re-check (no
    // "43 44 45" follows), so `candidates` counts them but `verified`
    // doesn't -- every real match from here on carries that gap.
    std::vector<uint8_t> img(2u * 1024 * 1024, 0x90);
    for (int i = 0; i < 2; ++i) {
        size_t at = (size_t)i * 32;
        img[at] = 0x41; img[at + 1] = 0x42;
    }
    for (int i = 0; i < 5; ++i) {
        size_t at = 200 + (size_t)i * 32;
        img[at] = 0x41; img[at + 1] = 0x42;
        img[at + 3] = 0x43; img[at + 4] = 0x44; img[at + 5] = 0x45;
    }
    for (int i = 0; i < 10; ++i) {
        size_t at = 10000 + (size_t)i * 32;
        img[at] = 0x43; img[at + 1] = 0x44; img[at + 2] = 0x45;
    }

    auto c = locate::compile("41 42 ? 43 44 45");
    locate::prime(c, img);
    REQUIRE(c.seed.bytes == std::vector<uint8_t>{ 0x41, 0x42 }); // the seed with bogus hits

    auto all = locate::find_all(img, c);
    REQUIRE(all.size() == 5);
    for (size_t i = 1; i < all.size(); ++i) {
        REQUIRE(all[i].candidates >= all[i - 1].candidates);
        REQUIRE(all[i].verified   >= all[i - 1].verified);
    }
    // Measured (not guessed): the 2 rejected bogus candidates precede every
    // real match in scan order, so `candidates` runs ahead of `verified` by
    // exactly that gap at every step, including the last.
    REQUIRE(all.back().candidates == 7);
    REQUIRE(all.back().verified   == 5);
    REQUIRE(all.back().candidates > all.back().verified);
}

TEST_CASE("find_all covers the unseeded branch when the fixed region is empty", "[findall]") {
    // "[1-2] 41 42" opens with a range skip, so fixed_bytes() stops before
    // consuming anything and priming selects no seed -- the branch every
    // other find_all test above skips, since "41 42" alone always seeds.
    auto img = make_seed_image(5, 0, 0);
    auto c = locate::compile("[1-2] 41 42");
    locate::prime(c, img);
    REQUIRE(c.fx.offsets.empty());
    REQUIRE(!c.seed.ok()); // provably exercising the `!c.seed.ok()` branch

    // Measured, not guessed: each planted "41 42" past the first (at 16, 32,
    // 48, 64) is reachable by a skip of both 1 and 2 bytes, giving 2 hits
    // each; the one at offset 0 has no valid preceding start. 4 * 2 == 8.
    auto all = locate::find_all(img, c);
    REQUIRE(all.size() == 8);

    // limit is honoured in the unseeded loop too.
    REQUIRE(locate::find_all(img, c, 0, 3).size() == 3);
}

TEST_CASE("version macros exist and match the CMake project version", "[version]") {
    // A consumer vendoring the headers has no other way to assert what it got;
    // PROVENANCE.md is prose and cannot fail a build.
    static_assert(MAML_VERSION_MAJOR == 0, "major");
    static_assert(MAML_VERSION_MINOR >= 1, "minor: Compiled/find_all landed in 1.1");
    REQUIRE(MAML_VERSION_MAJOR == 0);
    REQUIRE(MAML_VERSION_MINOR == 1);
    REQUIRE(MAML_VERSION_PATCH == 0);
}

TEST_CASE("on a tie the longer run wins", "[seed][ordering]") {
    // Two runs, identical occurrence counts, different lengths. Under offset
    // order the 2-byte run was visited first and kept the tie; ordering
    // longest-first hands ties to the longer run instead. Counts are 7, above
    // the `bestCount <= 4` early break, so the whole loop runs.
    std::vector<uint8_t> img(2u * 1024 * 1024, 0x90);
    size_t p = 0;
    for (int i = 0; i < 7; ++i) { img[p] = 0x41; img[p+1] = 0x42; p += 32; }
    for (int i = 0; i < 7; ++i) { img[p] = 0x51; img[p+1] = 0x52; img[p+2] = 0x53; img[p+3] = 0x54; p += 32; }

    auto fx = locate::fixed_bytes("41 42 ? 51 52 53 54");
    auto s  = locate::select_seed(img, fx);
    REQUIRE(s.bytes == std::vector<uint8_t>{ 0x51, 0x52, 0x53, 0x54 });
    REQUIRE(s.offset == 3);
}

TEST_CASE("ordering does not change the choice when the minimum is unique", "[seed][ordering]") {
    // The rare single byte still wins over the common pair, and the rarer pair
    // still wins over the commoner longer run -- both minima are unique, so
    // visit order cannot matter.
    auto a = make_seed_image(5000, 0, 3);
    REQUIRE(locate::select_seed(a, locate::fixed_bytes("41 42 ? D0")).bytes
            == std::vector<uint8_t>{ 0xD0 });

    auto b = make_seed_image(8000, 20000, 0);
    REQUIRE(locate::select_seed(b, locate::fixed_bytes("41 42 ? 43 44 45")).bytes
            == std::vector<uint8_t>{ 0x41, 0x42 });
}

TEST_CASE("the longest-run fallback is unaffected by ordering", "[seed][ordering]") {
    // Every run exceeds the load-time cap, so counts are indistinguishable and
    // the fallback picks the longest. Sorting must not change which one.
    auto img = make_seed_image(8000, 20000, 0);
    auto s = locate::select_seed(img, locate::fixed_bytes("41 42 ? 43 44 45"),
                                 locate::kSeedCapLoadTime);
    REQUIRE(s.bytes == std::vector<uint8_t>{ 0x43, 0x44, 0x45 });
}

TEST_CASE("count_up_to edge semantics survive the memchr rewrite", "[count]") {
    std::vector<uint8_t> img(64, 0x90);
    img[10] = 0xAA; img[11] = 0xAA; img[12] = 0xAA;   // three bytes, two overlapping pairs

    SECTION("overlapping occurrences are counted") {
        REQUIRE(locate::count_up_to(img, { 0xAA, 0xAA }, SIZE_MAX) == 2);
    }
    SECTION("cap returns as soon as it is reached") {
        REQUIRE(locate::count_up_to(img, { 0xAA, 0xAA }, 1) == 1);
    }
    SECTION("empty needle is SIZE_MAX") {
        REQUIRE(locate::count_up_to(img, {}, SIZE_MAX) == SIZE_MAX);
    }
    SECTION("needle longer than the haystack is SIZE_MAX") {
        std::vector<uint8_t> big(img.size() + 1, 0x00);
        REQUIRE(locate::count_up_to(img, big, SIZE_MAX) == SIZE_MAX);
    }
    SECTION("a needle exactly the haystack's length still matches") {
        std::vector<uint8_t> whole(img.begin(), img.end());
        REQUIRE(locate::count_up_to(img, whole, SIZE_MAX) == 1);
    }
    SECTION("absent needle counts zero") {
        REQUIRE(locate::count_up_to(img, { 0xDE, 0xAD }, SIZE_MAX) == 0);
    }
    SECTION("single-byte needle") {
        REQUIRE(locate::count_up_to(img, { 0xAA }, SIZE_MAX) == 3);
    }
}

TEST_CASE("a match at the very end of the image is still found", "[count][findall]") {
    // The memchr length argument is (last - it) - k + 1. An off-by-one there
    // silently drops the final possible start offset, which no other test covers.
    std::vector<uint8_t> img(256, 0x90);
    img[254] = 0x41; img[255] = 0x42;
    REQUIRE(locate::count_up_to(img, { 0x41, 0x42 }, SIZE_MAX) == 1);

    auto c = locate::compile("41 42");
    locate::prime(c, img);
    auto all = locate::find_all(img, c);
    REQUIRE(all.size() == 1);
    REQUIRE(all[0].offset == 254);
}

TEST_CASE("scan_literal finds the same matches as a scalar scan", "[simd]") {
    // Adversarial by construction: matches at offset 0, straddling every 16-byte
    // vector boundary, overlapping each other, and ending exactly at the last
    // legal start offset. A vector loop that mishandles its tail or its stride
    // drops one of these and nothing else in the suite would notice.
    std::vector<uint8_t> img(1024, 0x90);
    const std::vector<uint8_t> n{ 0x41, 0x42 };
    for (size_t at : { size_t(0), size_t(15), size_t(16), size_t(31), size_t(100),
                       size_t(101), size_t(1022) })
        { img[at] = 0x41; img[at + 1] = 0x42; }
    // 100 and 101 overlap: 41 42 42 is not two matches, so drop 101 unless the
    // byte at 102 was also set. Recompute ground truth by brute force instead of
    // trusting the plant list.
    std::vector<size_t> expect;
    for (size_t i = 0; i + n.size() <= img.size(); ++i)
        if (std::equal(n.begin(), n.end(), img.begin() + i))
            expect.push_back(i);

    std::vector<size_t> got;
    locate::detail::scan_literal(img.data(), img.data() + img.size(),
                                 n.data(), n.size(),
                                 [&](const uint8_t* q) {
                                     got.push_back((size_t)(q - img.data()));
                                     return false;
                                 });
    REQUIRE(got == expect);
    REQUIRE(!expect.empty());
    REQUIRE(expect.back() == 1022);            // the last legal start offset
}

TEST_CASE("scan_literal handles a needle spanning multiple 16-byte blocks", "[simd]") {
    // All three existing [simd] cases use 1-2 byte needles, and the one case
    // with a 64-byte needle sizes the image to match it exactly, so the
    // vector loop's stride never runs. That leaves the second anchor load at
    // `p + k - 1` untested for the case that matters: k >= 16, so `p` and
    // `p + k - 1` fall in DIFFERENT 16-byte blocks. A needle of 20 bytes in a
    // 1024-byte image forces exactly that, with matches planted straddling a
    // 16-byte boundary and at the very last legal start offset.
    std::vector<uint8_t> img(1024, 0x90);
    std::vector<uint8_t> n;
    for (uint8_t b = 0x01; b <= 0x14; ++b)
        n.push_back(b); // 20 distinct bytes, none equal to the 0x90 filler
    REQUIRE(n.size() == 20);

    const size_t last = img.size() - n.size(); // 1004: the last legal start offset
    for (size_t at : { size_t(0), size_t(10), size_t(16), size_t(200),
                       size_t(550), last }) {
        REQUIRE(at + n.size() <= img.size());
        std::copy(n.begin(), n.end(), img.begin() + (ptrdiff_t)at);
    }
    // 10 (10..29) and 550 (550..569) each straddle a 16-byte vector boundary
    // (16 and 560 respectively) rather than starting on one.

    std::vector<size_t> expect;
    for (size_t i = 0; i + n.size() <= img.size(); ++i)
        if (std::equal(n.begin(), n.end(), img.begin() + (ptrdiff_t)i))
            expect.push_back(i);

    std::vector<size_t> got;
    locate::detail::scan_literal(img.data(), img.data() + img.size(),
                                 n.data(), n.size(),
                                 [&](const uint8_t* q) {
                                     got.push_back((size_t)(q - img.data()));
                                     return false;
                                 });
    REQUIRE(got == expect);
    REQUIRE(!expect.empty());
    REQUIRE(std::find(expect.begin(), expect.end(), last) != expect.end());
}

TEST_CASE("scan_literal stops when the callback says stop", "[simd]") {
    std::vector<uint8_t> img(1024, 0x90);
    for (size_t at : { size_t(10), size_t(20), size_t(30) }) { img[at] = 0x41; img[at+1] = 0x42; }
    size_t seen = 0;
    locate::detail::scan_literal(img.data(), img.data() + img.size(),
                                 (const uint8_t*)"\x41\x42", 2,
                                 [&](const uint8_t*) { ++seen; return seen == 2; });
    REQUIRE(seen == 2);
}

TEST_CASE("scan_literal handles degenerate needles", "[simd]") {
    std::vector<uint8_t> img(64, 0x90);
    img[5] = 0x41;
    size_t n = 0;
    auto count = [&](const uint8_t*) { ++n; return false; };

    SECTION("single byte") {
        locate::detail::scan_literal(img.data(), img.data() + img.size(),
                                     (const uint8_t*)"\x41", 1, count);
        REQUIRE(n == 1);
    }
    SECTION("zero-length needle does nothing") {
        locate::detail::scan_literal(img.data(), img.data() + img.size(),
                                     (const uint8_t*)"", 0, count);
        REQUIRE(n == 0);
    }
    SECTION("needle longer than the haystack does nothing") {
        std::vector<uint8_t> big(img.size() + 1, 0x90);
        locate::detail::scan_literal(img.data(), img.data() + img.size(),
                                     big.data(), big.size(), count);
        REQUIRE(n == 0);
    }
}

// A masked byte is fixed-WIDTH but not fixed-VALUE. fixed_bytes() is a
// whitespace-split pre-scan that is independent of the real lexer, and it
// did not know `&` at all: for `83 38 & 38` it kept the `38` as an exact
// seed byte and the seeded scan then rejected every real match whose masked
// bits differed -- silently, since `find` re-verifies only the fixed bytes it
// was told about. The unseeded BinaryMatcher was right the whole time, so
// the bug lived exactly and only in the path the DLL and the bindings use.
//
// The image: `83 3D` at 0 is a genuine reg=7 ModRM (cmp [rip+disp], imm8),
// `83 38` at 9 is the literal. Both must be found by every spelling.
static std::vector<uint8_t> mask_image() {
    return { 0x83, 0x3D, 0x11, 0x22, 0x33, 0x44, 0x00, 0x90, 0x90, 0x83, 0x38, 0x00 };
}

TEST_CASE("fixed_bytes retracts a byte the lexer will mask", "[seed][mask]") {
    // The lexer binds `&` to the immediately preceding hex run, whether or
    // not whitespace separates them; all four spellings mean the same thing.
    for (const char* p : { "83 38 & 38", "83 38&38", "83 38 &38", "83 38& 38" }) {
        INFO(p);
        auto fx = locate::fixed_bytes(p);
        REQUIRE(fx.offsets == std::vector<int>{ 0 });
        REQUIRE(fx.bytes == std::vector<uint8_t>{ 0x83 });
        REQUIRE(fx.span == 2); // the masked byte still occupies its slot
    }
}

TEST_CASE("fixed bytes after a mask are still at known offsets", "[seed][mask]") {
    auto fx = locate::fixed_bytes("83 38 & 38 11 22 33 44");
    REQUIRE(fx.offsets == std::vector<int>{ 0, 2, 3, 4, 5 });
    REQUIRE(fx.bytes == std::vector<uint8_t>{ 0x83, 0x11, 0x22, 0x33, 0x44 });
    REQUIRE(fx.span == 6);
    // and the seed can key on the run PAST the mask, which is the rarer one
    auto img = mask_image();
    auto s = locate::select_seed(img, fx);
    REQUIRE(s.offset == 2);
    REQUIRE(s.bytes == std::vector<uint8_t>{ 0x11, 0x22, 0x33, 0x44 });
}

TEST_CASE("a masked byte does not lose matches on the seeded path", "[seed][mask][findall]") {
    auto img = mask_image();
    std::span<const uint8_t> sp(img.data(), img.size());
    for (const char* p : { "83 38 & 38", "83 38&38", "83 38 &38", "83 38& 38" }) {
        INFO(p);
        auto c = locate::compile(p);
        locate::prime(c, sp);
        auto hits = locate::find_all(sp, c, 0, 0);
        std::vector<size_t> offs;
        for (const auto& h : hits)
            offs.push_back(h.offset);
        REQUIRE(offs == std::vector<size_t>{ 0, 9 });
        // and the one-shot string form, which the DLL calls
        auto first = locate::find(sp, p, 0, nullptr);
        REQUIRE(first.has_value());
        REQUIRE(first->offset == 0);
    }
}

TEST_CASE("the seeded and unseeded paths agree on a masked pattern", "[seed][mask]") {
    // The unseeded matcher is the oracle: sweep every ModRM byte and demand
    // the seeded find() says yes exactly where the matcher does.
    for (const char* p : { "83 38 & 38", "83 38&38" }) {
        auto pat = compiler::optimize_pattern(compiler::parse_pattern(p));
        for (int m = 0; m < 256; ++m) {
            const uint8_t img[2] = { 0x83, (uint8_t)m };
            SpanMatchTarget tg(img);
            BinaryMatcher<> mt(pat, tg);
            const bool oracle = mt.next_match().has_value();
            const bool seeded = locate::find(std::span<const uint8_t>(img, 2), p, 0, nullptr).has_value();
            INFO(p << " modrm=" << m);
            REQUIRE(seeded == oracle);
        }
    }
}
