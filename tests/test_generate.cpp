// The generator: given a target in two builds, emit patterns unique in both.
#include "catch.hpp"
#include "maml.hpp"
#include "maml/generate.hpp"
#include <algorithm>
#include <set>
#include <cstdio>
#include <chrono>
#include <vector>
using namespace maml;

TEST_CASE("the generate surface is callable, and Body emits from any address", "[generate]") {
    std::vector<uint8_t> bytes(0x100, 0xCC);
    std::vector<generate::Range> code{ { 0, 0x100 } };
    generate::Image img{ bytes, code, {}, {} };

    // This fixture has no E8 anywhere, so Xref finds nothing -- but Body
    // needs no caller, only a target, so it emits here even though the
    // "body" is undifferentiated 0xCC filler. That candidate is real output,
    // not a defect: dual-build verification is what is supposed to strip a
    // candidate this undistinctive, not candidates() itself.
    auto cs = generate::candidates(img, 0x10);
    REQUIRE(cs.size() == 1);
    REQUIRE(cs[0].strategy == generate::Strategy::Body);
    REQUIRE(cs[0].save_index == 0);
    REQUIRE(cs[0].anchor_delta == 0);

    // verified() still rejects it: a 64-byte run of 0xCC is not unique across
    // a 256-byte image that is nothing but 0xCC, so nothing survives.
    //
    // A SECOND BUFFER, not the same one twice. verified() refuses a call
    // whose two images are the same object, so passing `img` twice would make
    // this pass for the wrong reason -- empty because the call was refused,
    // not because the candidate is undistinctive.
    std::vector<uint8_t> second(0x100, 0xCC);
    generate::Image img_b{ second, code, {}, {} };
    REQUIRE(generate::verified(img, 0x10, img_b, 0x10).empty());
}

TEST_CASE("Options carry the design's defaults", "[generate]") {
    generate::Options o;
    REQUIRE(o.max_len == 64);
    REQUIRE(o.want == 4);
    REQUIRE(o.prefer_short == true);
    REQUIRE(o.deep_anchor == true);
}

TEST_CASE("a Candidate carries a seed and a signed anchor delta", "[generate]") {
    // anchor_delta is SIGNED and the convention is SUBTRACT FROM THE MATCH TO
    // GET THE TARGET. DESIGN_generate.md records that a batch with this sign
    // backwards called three correct patterns MISS.
    generate::Candidate c;
    c.anchor_delta = -8;
    REQUIRE(c.anchor_delta < 0);
    REQUIRE(c.seed.bytes.empty());          // locate::Seed, default-constructed
    REQUIRE(c.save_index == 0);
}

// Build an image with `n` calls to `callee` at the given sites.
static std::vector<uint8_t> make_call_image(size_t callee,
                                            const std::vector<size_t>& sites,
                                            size_t size = 0x1000) {
    std::vector<uint8_t> img(size, 0xCC);
    img[callee] = 0x48; img[callee + 1] = 0x89;       // callee prologue, arbitrary
    for (size_t s : sites) {
        img[s] = 0xE8;
        int32_t rel = (int32_t)(callee - (s + 5));
        for (int k = 0; k < 4; ++k)
            img[s + 1 + k] = (uint8_t)((uint32_t)rel >> (8 * k));
    }
    return img;
}

TEST_CASE("callers_of finds every E8 whose rel32 lands on the target", "[generate][callgraph]") {
    // The callee (0x100) precedes every call site, so rel32 is negative for
    // all three: -261, -517, -773 (0xfffffefb, 0xfffffdfb, 0xfffffcfb -- high
    // bit set). This test's coverage of the sign path is deliberate, not
    // incidental: a widening bug that skips the `(int32_t)` narrowing step
    // fails to find any of the three calls here.
    auto bytes = make_call_image(0x100, { 0x200, 0x300, 0x400 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto c = generate::callers_of(img, 0x100);
    REQUIRE(c == std::vector<uint64_t>{ 0x200, 0x300, 0x400 });   // increasing order
}

TEST_CASE("callers_of ignores calls to other targets", "[generate][callgraph]") {
    auto bytes = make_call_image(0x100, { 0x200 });
    // a second call, to a different callee
    size_t s = 0x300, other = 0x180;
    bytes[s] = 0xE8;
    int32_t rel = (int32_t)(other - (s + 5));
    for (int k = 0; k < 4; ++k) bytes[s + 1 + k] = (uint8_t)((uint32_t)rel >> (8 * k));

    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };
    REQUIRE(generate::callers_of(img, 0x100) == std::vector<uint64_t>{ 0x200 });
    REQUIRE(generate::callers_of(img, other) == std::vector<uint64_t>{ 0x300 });
}

TEST_CASE("callers_of handles backward calls", "[generate][callgraph]") {
    // The callee (0x100) is BEFORE the call site (0x800), so rel32 =
    // callee - (site + 5) = 0x100 - 0x805 = -1797 (0xfffff8fb as a raw
    // rel32 -- high bit set). Without the intermediate `(int32_t)` cast,
    // widening the unsigned rel32 straight to int64_t turns this negative
    // offset into a huge positive one, and the caller is never found.
    auto bytes = make_call_image(0x100, { 0x800 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };
    REQUIRE(generate::callers_of(img, 0x100) == std::vector<uint64_t>{ 0x800 });
}

TEST_CASE("callers_of handles forward calls", "[generate][callgraph]") {
    // The callee (0x800) is AFTER the call site (0x100), so rel32 =
    // callee - (site + 5) = 0x800 - 0x105 = +1787 (0x000006fb -- high bit
    // clear). Paired with the backward-call test above so both directions
    // are named for what they actually exercise, instead of one direction
    // being covered only by accident of another test's fixture.
    auto bytes = make_call_image(0x800, { 0x100 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };
    REQUIRE(generate::callers_of(img, 0x800) == std::vector<uint64_t>{ 0x100 });
}

TEST_CASE("callers_of only scans executable ranges", "[generate][callgraph]") {
    // The same bytes appearing in .rdata are not call sites. Section bounds are
    // exactly what the caller supplies that the bytes cannot say.
    auto bytes = make_call_image(0x100, { 0x200, 0x900 });
    std::vector<generate::Range> code{ { 0, 0x500 } };          // 0x900 is outside
    generate::Image img{ bytes, code, {}, {} };
    REQUIRE(generate::callers_of(img, 0x100) == std::vector<uint64_t>{ 0x200 });
}

TEST_CASE("callers_of finds nothing for an uncalled target", "[generate][callgraph]") {
    auto bytes = make_call_image(0x100, { 0x200 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };
    REQUIRE(generate::callers_of(img, 0x700).empty());
}

TEST_CASE("callers_of does not read past the end of a range", "[generate][callgraph]") {
    // An E8 in the last four bytes has no complete rel32. Reading it would be
    // an over-read; the correct behaviour is to ignore it.
    std::vector<uint8_t> bytes(0x100, 0xCC);
    bytes[0xFC] = 0xE8;                                   // only 3 bytes follow
    std::vector<generate::Range> code{ { 0, 0x100 } };
    generate::Image img{ bytes, code, {}, {} };
    REQUIRE(generate::callers_of(img, 0x00).empty());     // must not crash
}

// A call site followed by `tail`, so a generated xref pattern has literals to
// key on beyond the call itself.
static std::vector<uint8_t> make_xref_image(size_t callee,
                                            const std::vector<size_t>& sites,
                                            const std::vector<uint8_t>& tail,
                                            size_t size = 0x1000) {
    auto img = make_call_image(callee, sites, size);
    for (size_t s : sites)
        for (size_t k = 0; k < tail.size(); ++k)
            img[s + 5 + k] = tail[k];
    return img;
}

// The same, but each call site gets its OWN tail, so the sites yield DISTINCT
// patterns. Task 10's dedup keys on the resolving triple, and two sites with a
// common tail produce one triple -- which is correct, and useless for any test
// whose subject is how many anchors a set holds.
static std::vector<uint8_t> make_xref_image_varied(
    size_t callee,
    const std::vector<std::pair<size_t, std::vector<uint8_t>>>& sites,
    size_t size = 0x1000) {
    std::vector<size_t> just_sites;
    for (const auto& s : sites)
        just_sites.push_back(s.first);
    auto img = make_call_image(callee, just_sites, size);
    for (const auto& s : sites)
        for (size_t k = 0; k < s.second.size(); ++k)
            img[s.first + 5 + k] = s.second[k];
    return img;
}

TEST_CASE("Xref emits one candidate per call site", "[generate][xref]") {
    // Distinct tails, so the two sites are two anchors rather than one
    // deduplicated triple -- what this test's name claims is one candidate
    // per SITE, and dedup does not disturb that when the sites differ.
    auto bytes = make_xref_image_varied(0x100,
        { { 0x200, { 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 } },
          { 0x300, { 0x4D, 0x8B, 0xD0, 0x48, 0x85, 0xC0 } } });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    // Body can ALSO appear for this target now (DESIGN_generate.md: all four
    // strategies can appear for one target) -- so count Xref candidates
    // specifically rather than asserting the total.
    auto cs = generate::candidates(img, 0x100);
    size_t xref_count = 0;
    for (const auto& c : cs) {
        if (c.strategy != generate::Strategy::Xref)
            continue;
        ++xref_count;
        REQUIRE(c.save_index == 1);          // the `'` capture holds the callee
        REQUIRE(c.anchor_delta == 0);        // target comes from the slot, not the match
        REQUIRE(c.pattern.rfind("E8 $ { ' }", 0) == 0);
    }
    REQUIRE(xref_count == 2);
}

TEST_CASE("an Xref candidate actually resolves to its target", "[generate][xref]") {
    // The whole point: what comes out must go back in. Compile the emitted
    // pattern, prime it, and confirm the saved value IS the target.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
    auto bytes = make_xref_image(0x100, { 0x200 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    // Body can also appear for this target now, so pick out the Xref one
    // specifically rather than assuming it is the only (or first) candidate.
    auto cs = generate::candidates(img, 0x100);
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Xref;
    });
    REQUIRE(it != cs.end());

    auto comp = locate::compile(it->pattern);
    locate::prime(comp, bytes);
    auto hits = locate::find_all(bytes, comp, it->save_index, 2);
    REQUIRE(hits.size() == 1);               // unique in this image
    REQUIRE(hits[0].value == 0x100);         // and it is the target
}

TEST_CASE("Options::want bounds how many anchors are emitted", "[generate][xref]") {
    // Five sites with five DIFFERENT tails, so five distinct triples are
    // available and `want` is the only thing that can be doing the bounding.
    auto bytes = make_xref_image_varied(0x100,
        { { 0x200, { 0x11, 0x8B, 0xD0 } },
          { 0x300, { 0x22, 0x8B, 0xD0 } },
          { 0x400, { 0x33, 0x8B, 0xD0 } },
          { 0x500, { 0x44, 0x8B, 0xD0 } },
          { 0x600, { 0x55, 0x8B, 0xD0 } } });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o;
    o.want = 2;
    REQUIRE(generate::candidates(img, 0x100, o).size() == 2);
    o.want = 4;
    REQUIRE(generate::candidates(img, 0x100, o).size() == 4);
    // And it bounds the TOTAL across strategies, not each strategy's own
    // count: Body has something to say about this target too, so a
    // per-strategy cap would let the set grow past `want`.
    o.want = 6;
    auto six = generate::candidates(img, 0x100, o);
    REQUIRE(six.size() == 6);
    REQUIRE(std::any_of(six.begin(), six.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Body;
    }));
}

TEST_CASE("the seed is filled in, and it is the rarest run", "[generate][xref]") {
    // DESIGN_generate.md: Candidate::seed is filled in, not left to the caller
    // -- the generator has already counted every run, so choosing the rarest is
    // free here and expensive anywhere else.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
    auto bytes = make_xref_image(0x100, { 0x200 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, 0x100);
    REQUIRE(!cs[0].seed.bytes.empty());
    REQUIRE(cs[0].seed.ok());

    // and it agrees with what select_seed would choose for that pattern
    auto fx = locate::fixed_bytes(cs[0].pattern);
    auto want = locate::select_seed(bytes, fx);
    REQUIRE(cs[0].seed.bytes == want.bytes);
    REQUIRE(cs[0].seed.offset == want.offset);
}

TEST_CASE("an uncalled target yields no Xref candidates", "[generate][xref]") {
    // Body now covers this target instead of Xref -- it needs no caller, so
    // the overall candidates() result is no longer empty. What this test's
    // name actually claims -- no XREF candidate for an uncalled target --
    // still holds, so that is what it checks now.
    auto bytes = make_call_image(0x100, { 0x200 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, 0x700);
    REQUIRE(!cs.empty());              // Body still emits something -- not vacuous
    size_t xref_count = 0;
    for (const auto& c : cs) {
        if (c.strategy == generate::Strategy::Xref)
            ++xref_count;
        else
            REQUIRE(c.strategy == generate::Strategy::Body);
    }
    REQUIRE(xref_count == 0);
}

TEST_CASE("two call sites with identical tails collapse to one candidate", "[generate][xref][dedup]") {
    // Nothing in candidates() reads the call SITE into the pattern -- only the
    // callee (captured via `'`) and the tail bytes after the call. Two sites
    // with the same tail therefore produce byte-identical patterns, with the
    // same save_index and the same anchor_delta: one resolving triple, and so
    // one candidate.
    //
    // Emitting both was legitimate output before Task 10 and is not now.
    // DESIGN_generate.md defines `want` as "independent anchors per target",
    // and cross-build verification depends on anchors
    // failing INDEPENDENTLY -- identical patterns fail together, so a second
    // copy is not a second anchor. It is worse than useless: it spends budget
    // that a genuinely different anchor could have had.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0, 0x74, 0xC8 };
    auto bytes = make_xref_image(0x100, { 0x200, 0x300 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    // Body can also appear for this target now, so isolate the Xref set
    // rather than assuming candidates() returns only it.
    std::vector<generate::Candidate> xrefs;
    for (auto& c : generate::candidates(img, 0x100))
        if (c.strategy == generate::Strategy::Xref)
            xrefs.push_back(std::move(c));
    REQUIRE(xrefs.size() == 1);

    // The fixture is only meaningful if the two sites really are both there
    // and really do produce the same bytes -- otherwise this would pass with
    // dedup removed entirely.
    REQUIRE(generate::callers_of(img, 0x100) == std::vector<uint64_t>{ 0x200, 0x300 });

    // And the survivor is the FIRST emitted, which is what makes the output
    // reproducible rather than merely deduplicated.
    auto comp = locate::compile(xrefs[0].pattern);
    locate::prime(comp, bytes);
    auto hits = locate::find_all(bytes, comp, xrefs[0].save_index, 4);
    REQUIRE(hits.size() == 2);           // the pattern genuinely matches both sites
    REQUIRE(hits[0].offset == 0x200);
}

TEST_CASE("max_len truncates the tail when the image has more bytes than the option allows", "[generate][xref]") {
    // opt.max_len is the binding constraint here: the image has plenty of
    // bytes after the call, but the option caps how many are captured.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0,
                                      0x74, 0xC8, 0x90, 0x90, 0x90, 0x90 };
    auto bytes = make_xref_image(0x100, { 0x200 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    // Body can also appear for this target now, so pick out the Xref one.
    // prefer_short is off: it would shorten the tail further, on its own
    // (uniqueness) grounds, and hide the ceiling this test is about.
    generate::Options o;
    o.max_len = 5;
    o.prefer_short = false;
    auto cs = generate::candidates(img, 0x100, o);
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Xref;
    });
    REQUIRE(it != cs.end());
    REQUIRE(it->literals == 6);   // the E8 plus 5 tail bytes, not 12
    REQUIRE(it->pattern == "E8 $ { ' } 4C 8B D0 48 85");
}

TEST_CASE("max_len truncates to what remains in the image when the call site is near the end", "[generate][xref]") {
    // Here the option would allow the default 64 bytes, but the image itself
    // runs out first -- n - after is the binding constraint, not opt.max_len.
    const size_t size = 0x100;
    const size_t callee = 0x10;            // well inside the image, unlike the site
    const size_t site = 0xF0;              // after = 0xF5, only 11 bytes remain
    const std::vector<uint8_t> tail{ 0x11, 0x22, 0x33, 0x44, 0x55,
                                      0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };
    REQUIRE(site + 5 + tail.size() == size);   // tail exactly fills the image
    auto bytes = make_xref_image(callee, { site }, tail, size);
    std::vector<generate::Range> code{ { 0, size } };
    generate::Image img{ bytes, code, {}, {} };

    // Body can also appear for this target now, so pick out the Xref one.
    // prefer_short off, for the same reason as the test above: the binding
    // constraint being pinned is the image's end, not uniqueness.
    generate::Options o;
    o.prefer_short = false;
    auto cs = generate::candidates(img, callee, o);   // default max_len == 64
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Xref;
    });
    REQUIRE(it != cs.end());
    REQUIRE(it->literals == 12);   // E8 plus all 11 remaining bytes, capped by image size
    REQUIRE(it->pattern == "E8 $ { ' } 11 22 33 44 55 66 77 88 99 AA BB");
}

TEST_CASE("verified keeps a candidate unique and correct in both builds", "[generate][verified]") {
    // Two independent compilations: same logical code, different addresses,
    // identical tail.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
    auto ba = make_xref_image(0x100, { 0x200 }, tail);
    auto bb = make_xref_image(0x180, { 0x300 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    auto v = generate::verified(a, 0x100, b, 0x180);
    REQUIRE(!v.empty());
    for (const auto& c : v) {
        for (auto [img, want] : { std::pair{ &ba, (uint64_t)0x100 },
                                  std::pair{ &bb, (uint64_t)0x180 } }) {
            auto comp = locate::compile(c.pattern);
            locate::prime(comp, *img);
            auto hits = locate::find_all(*img, comp, c.save_index, 2);
            REQUIRE(hits.size() == 1);
            REQUIRE(hits[0].value == want);
        }
    }
}

TEST_CASE("verified drops a candidate whose tail differs in the second build",
          "[generate][verified]") {
    // This is the documented limitation made visible: the XREF candidate is
    // emitted from A and DISCARDED, not repaired into a range-tolerant form.
    //
    // Body can independently survive here: the callee's own bytes ("48 89"
    // plus filler) are identical in both builds -- only the CALL SITE's tail
    // differs -- so a real, distinct Body candidate legitimately verifies.
    // That is not a bug; DESIGN_generate.md's "all four strategies can
    // appear for one target" is exactly this. So this test checks the XREF
    // candidate specifically, which is what its name actually claims.
    //
    // The tails differ in their FIRST byte, not their third. With
    // prefer_short on (the default) the emitted tail is only as long as
    // uniqueness in A requires, so a difference further in would simply be
    // shortened out of the pattern and the candidate would survive -- a real
    // consequence of shortening against one image, and not the thing this
    // test is about.
    auto ba = make_xref_image(0x100, { 0x200 }, { 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 });
    auto bb = make_xref_image(0x180, { 0x300 }, { 0x4D, 0x8B, 0xD0, 0x48, 0x85, 0xC0 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    auto cs = generate::candidates(a, 0x100);
    REQUIRE(std::any_of(cs.begin(), cs.end(),
        [](const generate::Candidate& c) { return c.strategy == generate::Strategy::Xref; }));
    auto v = generate::verified(a, 0x100, b, 0x180);
    REQUIRE(!v.empty());   // Body survives here -- not vacuous if verified() were ever empty
    for (const auto& c : v)
        REQUIRE(c.strategy != generate::Strategy::Xref);  // Xref's tail mismatch still rejects it
}

TEST_CASE("verified drops a candidate that is not unique", "[generate][verified]") {
    // Two call sites with identical surroundings: each pattern matches both, so
    // neither is unique and neither survives.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0 };
    auto ba = make_xref_image(0x100, { 0x200, 0x400 }, tail);
    auto bb = make_xref_image(0x180, { 0x300, 0x500 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    for (const auto& c : generate::verified(a, 0x100, b, 0x180)) {
        auto comp = locate::compile(c.pattern);
        locate::prime(comp, ba);
        REQUIRE(locate::find_all(ba, comp, c.save_index, 2).size() == 1);
    }
}

TEST_CASE("verified drops a candidate resolving to the WRONG target", "[generate][verified]") {
    // Unique in both is not enough -- it must resolve to ITS OWN target in each.
    // Here B's pattern is unique but points at a different function.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
    auto ba = make_xref_image(0x100, { 0x200 }, tail);
    auto bb = make_xref_image(0x180, { 0x300 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    // claim the target in B is somewhere it is not
    REQUIRE(generate::verified(a, 0x100, b, 0x999).empty());
}

TEST_CASE("verified returns a SET, because durability is a property of the set",
          "[generate][verified]") {
    // Four anchors on four call sites fail independently; that is the whole of
    // the 72% -> 90% difference. So verified() returns candidates, not one answer.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
    auto ba = make_xref_image(0x100, { 0x200, 0x300, 0x400 }, tail);
    auto bb = make_xref_image(0x180, { 0x500, 0x600, 0x700 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    // Each site's tail is identical, so no single pattern is unique; the point
    // of this case is that the RETURN TYPE is a set and the API does not
    // collapse to one answer.
    auto v = generate::verified(a, 0x100, b, 0x180);
    REQUIRE(v.size() <= 3);
}

// --- Body: the baseline strategy -------------------------------------------

TEST_CASE("Body anchors at the entry with a zero delta", "[generate][body]") {
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    const std::vector<uint8_t> body{ 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20 };
    for (size_t k = 0; k < body.size(); ++k) bytes[0x400 + k] = body[k];
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o; o.want = 8;
    bool saw_body = false;
    for (const auto& c : generate::candidates(img, 0x400, o))
        if (c.strategy == generate::Strategy::Body) {
            saw_body = true;
            REQUIRE(c.save_index == 0);
            REQUIRE(c.anchor_delta == 0);        // anchored AT the entry
            auto comp = locate::compile(c.pattern);
            locate::prime(comp, bytes);
            auto hits = locate::find_all(bytes, comp, 0, 2);
            REQUIRE(hits.size() == 1);
            // Explicitly signed: hits[0].offset is size_t, anchor_delta is
            // int64_t -- mixing them lets the unsigned operand silently win
            // the usual arithmetic conversions, which is harmless at delta 0
            // but a sign trap the moment Critical 1's fix makes deltas move.
            REQUIRE((int64_t)hits[0].offset - c.anchor_delta == 0x400);
        }
    REQUIRE(saw_body);
}

TEST_CASE("a Body candidate anchored past the entry carries a nonzero delta",
          "[generate][body]") {
    // The trap CLAUDE.md records twice. If the entry bytes are not distinctive
    // but bytes further in are, the anchor moves and the delta must move with it.
    std::vector<uint8_t> bytes(0x1000, 0x90);            // filler is a real opcode
    const std::vector<uint8_t> distinctive{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    for (size_t k = 0; k < distinctive.size(); ++k) bytes[0x408 + k] = distinctive[k];
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o; o.want = 8;
    for (const auto& c : generate::candidates(img, 0x400, o)) {
        if (c.strategy != generate::Strategy::Body) continue;
        auto comp = locate::compile(c.pattern);
        locate::prime(comp, bytes);
        auto hits = locate::find_all(bytes, comp, 0, 2);
        if (hits.size() != 1) continue;
        // Whatever delta the generator chose, this identity must hold.
        REQUIRE((int64_t)hits[0].offset - c.anchor_delta == 0x400);
    }
}

TEST_CASE("Body moves deeper when the entry itself is not distinctive", "[generate][body]") {
    // Critical 1's fix: the delta walk's trigger is DISTINCTIVENESS -- unique
    // within this image at save_index 0 -- not room. take = min(max_len, n -
    // anchor) is >= 1 for any in-bounds anchor, so a room-only rule can never
    // produce a nonzero delta; this fixture is built so the delta-0 window
    // has plenty of room but is still nothing but repeated filler.
    std::vector<uint8_t> bytes(0x1000, 0x90);           // filler is a real opcode
    const std::vector<uint8_t> distinctive{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    // Placed at +16 so an 8-byte window (below) cannot reach it before delta
    // 16 -- deltas 0, 4 and 8 all land short of it.
    for (size_t k = 0; k < distinctive.size(); ++k) bytes[0x410 + k] = distinctive[k];
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o;
    o.max_len = 8;    // small enough that delta 0's window cannot reach the run at +16
    auto cs = generate::candidates(img, 0x400, o);
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Body;
    });
    REQUIRE(it != cs.end());
    REQUIRE(it->anchor_delta != 0);    // moved past the undistinctive entry
    REQUIRE(it->anchor_delta == 16);   // observed by running this fixture, not assumed

    auto comp = locate::compile(it->pattern);
    locate::prime(comp, bytes);
    auto hits = locate::find_all(bytes, comp, 0, 2);
    REQUIRE(hits.size() == 1);
    REQUIRE((int64_t)hits[0].offset - it->anchor_delta == 0x400);  // match - delta == target
}

TEST_CASE("Body's deeper offsets are checked against img.code, not just the target",
          "[generate][body]") {
    // Regression for the Minor (i) fix: target + delta must be checked
    // against img.code (and clamped via clamp_to_func) using the ANCHOR,
    // not the original target. Without that, a deeper delta can walk
    // straight out of the target's function -- or out of code entirely --
    // once the walk can ever advance past delta 0.
    //
    // Same base fixture as the delta-16 test above (filler 0x90, a
    // distinctive run at target+16, max_len=8 so deltas 0/4/8 cannot reach
    // it), but img.code is narrowed to end AT 0x410 -- comfortably covering
    // the target (0x400) while excluding the anchor the walk would
    // otherwise pick at delta 16 (0x410). If the check used `target`
    // (always in-code here) instead of the per-anchor value, it would
    // wrongly reach and pick delta 16's distinctive run; the correct anchor
    // is delta 0, the only in-code offset, even though it is not
    // distinctive.
    std::vector<uint8_t> bytes(0x1000, 0x90);
    const std::vector<uint8_t> distinctive{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    for (size_t k = 0; k < distinctive.size(); ++k) bytes[0x410 + k] = distinctive[k];
    std::vector<generate::Range> code{ { 0x300, 0x410 } };   // 0x400 is in; 0x410 is not
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o;
    o.max_len = 8;
    auto cs = generate::candidates(img, 0x400, o);
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Body;
    });
    REQUIRE(it != cs.end());
    REQUIRE(it->anchor_delta == 0);    // delta 16 is out of code and must be rejected
}

TEST_CASE("verified compares match minus delta, not the raw match", "[generate][body]") {
    // A Body candidate with a nonzero delta must survive verification. If
    // verified() compared the raw match to the target it would reject it --
    // exactly the failure CLAUDE.md says has happened twice.
    //
    // max_len is kept small (8) and the distinctive run placed at +16 in
    // BOTH images, mirroring the delta-16 fixture above. With the default
    // max_len=64 this test previously used, delta 0's window already
    // swallowed the run, so the ONLY candidate verified() could return here
    // carried anchor_delta == 0 -- the branch this test exists to pin was
    // never actually exercised through verified(). This fixture forces the
    // surviving candidate to carry a nonzero delta instead.
    std::vector<uint8_t> ba(0x1000, 0x90), bb(0x1000, 0x90);
    const std::vector<uint8_t> d{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    for (size_t k = 0; k < d.size(); ++k) { ba[0x410 + k] = d[k]; bb[0x610 + k] = d[k]; }
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    generate::Options o; o.want = 8; o.max_len = 8;
    auto v = generate::verified(a, 0x400, b, 0x600, o);
    auto it = std::find_if(v.begin(), v.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Body;
    });
    REQUIRE(it != v.end());
    REQUIRE(it->anchor_delta != 0);   // the trap: this must not be 0 or the branch goes untested
}

// --- funcs: clamp the tail so it does not run into the next function -------

TEST_CASE("Xref clamps the tail to the function containing the call site when funcs is supplied",
          "[generate][xref][funcs]") {
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0,
                                      0x74, 0xC8, 0x90, 0x90, 0x90, 0x90 };
    auto bytes = make_xref_image(0x100, { 0x200 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    // The call site (0x200) lands at 0x205 after the E8+rel32; the function
    // containing it ends at 0x209 -- four bytes of real tail, not all twelve.
    std::vector<generate::Range> funcs{ { 0x1F0, 0x209 } };
    generate::Image img{ bytes, code, {}, funcs };

    // Body can also appear for this target now (its window, at 0x100, sits
    // outside `funcs` entirely so it is unaffected), so pick out the Xref one.
    // prefer_short off: the clamp is the constraint under test, and
    // uniqueness-driven shortening would sit in front of it.
    generate::Options o;
    o.max_len = 12;   // would capture the whole tail if nothing clamped it
    o.prefer_short = false;
    auto cs = generate::candidates(img, 0x100, o);
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Xref;
    });
    REQUIRE(it != cs.end());
    REQUIRE(it->literals == 5);   // E8 plus 4 tail bytes -- clamped to the function's end
    REQUIRE(it->pattern == "E8 $ { ' } 4C 8B D0 48");
}

TEST_CASE("Xref's tail is unchanged from current behaviour when funcs is empty",
          "[generate][xref][funcs]") {
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0,
                                      0x74, 0xC8, 0x90, 0x90, 0x90, 0x90 };
    auto bytes = make_xref_image(0x100, { 0x200 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };   // no funcs supplied

    // Body can also appear for this target now, so pick out the Xref one.
    // prefer_short off: what is unchanged from Tasks 1-4 is the UNCLAMPED
    // tail, which is a statement about funcs, not about uniqueness.
    generate::Options o;
    o.max_len = 12;
    o.prefer_short = false;
    auto cs = generate::candidates(img, 0x100, o);
    auto it = std::find_if(cs.begin(), cs.end(), [](const generate::Candidate& c) {
        return c.strategy == generate::Strategy::Xref;
    });
    REQUIRE(it != cs.end());
    REQUIRE(it->literals == 13);  // E8 plus the full 12-byte tail, exactly as Tasks 1-4
    REQUIRE(it->pattern == "E8 $ { ' } 4C 8B D0 48 85 C0 74 C8 90 90 90 90");
}

TEST_CASE("Body clamps its window to the function containing the anchor when funcs is supplied",
          "[generate][body][funcs]") {
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    const std::vector<uint8_t> body{ 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57 };
    for (size_t k = 0; k < body.size(); ++k) bytes[0x400 + k] = body[k];
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    // The function containing the target ends 4 bytes into the body.
    std::vector<generate::Range> funcs{ { 0x400, 0x404 } };
    generate::Image img{ bytes, code, {}, funcs };

    generate::Options o;
    o.max_len = 6;   // would capture the whole `body` array if nothing clamped it
    o.prefer_short = false;   // the clamp is the subject, not uniqueness
    auto cs = generate::candidates(img, 0x400, o);
    REQUIRE(cs.size() == 1);
    REQUIRE(cs[0].strategy == generate::Strategy::Body);
    REQUIRE(cs[0].literals == 4);   // clamped to the function's end, not all 6
    REQUIRE(cs[0].pattern == "48 89 5C 24");
}

TEST_CASE("Body's window is unchanged from current behaviour when funcs is empty",
          "[generate][body][funcs]") {
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    const std::vector<uint8_t> body{ 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57 };
    for (size_t k = 0; k < body.size(); ++k) bytes[0x400 + k] = body[k];
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };   // no funcs supplied

    generate::Options o;
    o.max_len = 6;
    o.prefer_short = false;   // the unclamped window is the subject
    auto cs = generate::candidates(img, 0x400, o);
    REQUIRE(cs.size() == 1);
    REQUIRE(cs[0].strategy == generate::Strategy::Body);
    REQUIRE(cs[0].literals == 6);
    REQUIRE(cs[0].pattern == "48 89 5C 24 08 57");
}

// strings(): the table StringAnchor (Task 8) will anchor on.

TEST_CASE("strings finds a run of exactly 6 printable bytes plus a trailing NUL",
          "[generate][strings]") {
    std::vector<uint8_t> bytes(0x20, 0x00);
    const std::vector<uint8_t> run{ 'A', 'B', 'C', 'D', 'E', 'F' };  // 6 printable bytes
    for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
    bytes[4 + run.size()] = 0x00;   // the terminating NUL, already there via fill
    std::vector<generate::Range> rodata{ { 0, bytes.size() } };
    generate::Image img{ bytes, {}, rodata, {} };

    auto ss = generate::strings(img);
    REQUIRE(ss.size() == 1);
    REQUIRE(ss[0].rva == 4);
    REQUIRE(ss[0].len == 6);
}

TEST_CASE("strings does not find a run of only 5 printable bytes", "[generate][strings]") {
    std::vector<uint8_t> bytes(0x20, 0x00);
    const std::vector<uint8_t> run{ 'A', 'B', 'C', 'D', 'E' };  // 5 printable bytes
    for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
    std::vector<generate::Range> rodata{ { 0, bytes.size() } };
    generate::Image img{ bytes, {}, rodata, {} };

    REQUIRE(generate::strings(img).empty());
}

TEST_CASE("strings does not find a printable run with no trailing NUL", "[generate][strings]") {
    std::vector<uint8_t> bytes(0x20, 0x20);  // fill with a printable byte (space), not NUL
    const std::vector<uint8_t> run{ 'A', 'B', 'C', 'D', 'E', 'F', 'G' };  // 7 printable bytes
    for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
    bytes[4 + run.size()] = 0x01;   // non-printable, non-NUL terminator -- not a string end
    std::vector<generate::Range> rodata{ { 0, bytes.size() } };
    generate::Image img{ bytes, {}, rodata, {} };

    REQUIRE(generate::strings(img).empty());
}

TEST_CASE("strings ignores runs in code and only looks at rodata", "[generate][strings]") {
    std::vector<uint8_t> bytes(0x20, 0x00);
    const std::vector<uint8_t> run{ 'A', 'B', 'C', 'D', 'E', 'F' };
    for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
    std::vector<generate::Range> code{ { 0, bytes.size() } };  // covers the run
    generate::Image img{ bytes, code, {}, {} };                // rodata is empty

    REQUIRE(generate::strings(img).empty());
}

TEST_CASE("strings does not read past a range's end to find the terminating NUL",
          "[generate][strings]") {
    // The printable run continues right up to (and past) the range boundary,
    // and a NUL sits exactly one byte past `r.end`. If the scan ever read
    // that byte the run would wrongly count as terminated; since it must not
    // be read, this run is dropped instead.
    std::vector<uint8_t> bytes(0x20, 0x41);  // 'A' everywhere
    const uint64_t range_end = 10;
    bytes[range_end] = 0x00;                 // the NUL, one byte past r.end
    std::vector<generate::Range> rodata{ { 4, range_end } };
    generate::Image img{ bytes, {}, rodata, {} };

    REQUIRE(generate::strings(img).empty());
}

TEST_CASE("strings never reads at or beyond bytes.size() either", "[generate][strings]") {
    // Same shape as the range-end case, but the range's own `end` overruns
    // the image entirely. ASan/UBSan builds would catch an out-of-bounds
    // read here; a plain assertion on the result is the portable half of
    // that guarantee.
    std::vector<uint8_t> bytes(10, 0x41);    // 'A' * 10, no NUL anywhere
    std::vector<generate::Range> rodata{ { 0, 1000 } };  // far past bytes.size()
    generate::Image img{ bytes, {}, rodata, {} };

    REQUIRE(generate::strings(img).empty());
}

TEST_CASE("strings emits one entry per maximal run, not one per suffix",
          "[generate][strings]") {
    std::vector<uint8_t> bytes(0x20, 0x00);
    const std::string run = "HELLO_WORLD";   // 11 printable bytes, underscore included
    for (size_t k = 0; k < run.size(); ++k) bytes[2 + k] = (uint8_t)run[k];
    std::vector<generate::Range> rodata{ { 0, bytes.size() } };
    generate::Image img{ bytes, {}, rodata, {} };

    auto ss = generate::strings(img);
    REQUIRE(ss.size() == 1);        // not eleven overlapping suffix entries
    REQUIRE(ss[0].rva == 2);
    REQUIRE(ss[0].len == 11);
}

TEST_CASE("strings returns RVAs sorted ascending, regardless of range order",
          "[generate][strings]") {
    std::vector<uint8_t> bytes(0x100, 0x00);
    const std::vector<uint8_t> a{ 'A', 'A', 'A', 'A', 'A', 'A' };  // rva 0x80
    const std::vector<uint8_t> b{ 'B', 'B', 'B', 'B', 'B', 'B' };  // rva 0x10
    const std::vector<uint8_t> c{ 'C', 'C', 'C', 'C', 'C', 'C' };  // rva 0x40
    for (size_t k = 0; k < a.size(); ++k) bytes[0x80 + k] = a[k];
    for (size_t k = 0; k < b.size(); ++k) bytes[0x10 + k] = b[k];
    for (size_t k = 0; k < c.size(); ++k) bytes[0x40 + k] = c[k];
    // Ranges supplied out of order on purpose -- the guarantee is on the
    // output, not on the caller having sorted its input.
    std::vector<generate::Range> rodata{ { 0x60, 0x90 }, { 0, 0x30 }, { 0x30, 0x60 } };
    generate::Image img{ bytes, {}, rodata, {} };

    auto ss = generate::strings(img);
    REQUIRE(ss.size() == 3);
    REQUIRE(ss[0].rva == 0x10);
    REQUIRE(ss[1].rva == 0x40);
    REQUIRE(ss[2].rva == 0x80);
    REQUIRE(std::is_sorted(ss.begin(), ss.end(),
        [](const generate::Str& x, const generate::Str& y) { return x.rva < y.rva; }));
}

TEST_CASE("strings does not duplicate an entry whose rva is covered by overlapping rodata ranges",
          "[generate][strings]") {
    std::vector<uint8_t> bytes(0x20, 0x00);
    const std::vector<uint8_t> run{ 'A', 'B', 'C', 'D', 'E', 'F' };
    for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
    // Two overlapping ranges, both covering the same run.
    std::vector<generate::Range> rodata{ { 0, 0x10 }, { 2, 0x18 } };
    generate::Image img{ bytes, {}, rodata, {} };

    auto ss = generate::strings(img);
    REQUIRE(ss.size() == 1);
    REQUIRE(ss[0].rva == 4);
    REQUIRE(ss[0].len == 6);
}

TEST_CASE("strings treats printable as the closed range 0x20..0x7E inclusive",
          "[generate][strings]") {
    // 0x20 (space) is ACCEPTED: a run containing a space stays ONE string,
    // not split at the space. Splitting is the actual failure mode -- real
    // rodata strings are full of spaces, so an off-by-one here would
    // quietly shrink the whole candidate pool, not just miss an edge case.
    {
        std::vector<uint8_t> bytes(0x20, 0x00);
        const std::vector<uint8_t> run{ 'A', 'B', ' ', 'C', 'D', 'E', 'F' };  // 7 bytes, space included
        for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
        std::vector<generate::Range> rodata{ { 0, bytes.size() } };
        generate::Image img{ bytes, {}, rodata, {} };

        auto ss = generate::strings(img);
        REQUIRE(ss.size() == 1);   // not split into "AB" and "CDEF"
        REQUIRE(ss[0].rva == 4);
        REQUIRE(ss[0].len == 7);
    }

    // 0x7E ('~') is ACCEPTED, as the run's own last byte.
    {
        std::vector<uint8_t> bytes(0x20, 0x00);
        const std::vector<uint8_t> run{ 'A', 'B', 'C', 'D', 'E', '~' };  // 6 bytes, ends at 0x7E
        for (size_t k = 0; k < run.size(); ++k) bytes[4 + k] = run[k];
        std::vector<generate::Range> rodata{ { 0, bytes.size() } };
        generate::Image img{ bytes, {}, rodata, {} };

        auto ss = generate::strings(img);
        REQUIRE(ss.size() == 1);
        REQUIRE(ss[0].rva == 4);
        REQUIRE(ss[0].len == 6);
    }

    // 0x1F is REJECTED: it terminates a run rather than extending it, so two
    // 6-byte printable chunks either side of it do not merge into one.
    {
        std::vector<uint8_t> bytes(0x20, 0x00);
        const std::vector<uint8_t> first{ 'A', 'B', 'C', 'D', 'E', 'F' };   // rva 2..7
        const std::vector<uint8_t> second{ 'G', 'H', 'I', 'J', 'K', 'L' };  // rva 9..14
        for (size_t k = 0; k < first.size(); ++k) bytes[2 + k] = first[k];
        bytes[8] = 0x1F;   // non-printable, non-NUL -- breaks the run, not extends it
        for (size_t k = 0; k < second.size(); ++k) bytes[9 + k] = second[k];
        std::vector<generate::Range> rodata{ { 0, bytes.size() } };
        generate::Image img{ bytes, {}, rodata, {} };

        auto ss = generate::strings(img);
        // The first chunk is dropped -- terminated by 0x1F, not a NUL.
        // Only the second chunk, terminated by the array's NUL fill, survives.
        REQUIRE(ss.size() == 1);
        REQUIRE(ss[0].rva == 9);
        REQUIRE(ss[0].len == 6);
    }

    // 0x7F (DEL) is likewise REJECTED, same shape as the 0x1F case above.
    {
        std::vector<uint8_t> bytes(0x20, 0x00);
        const std::vector<uint8_t> first{ 'A', 'B', 'C', 'D', 'E', 'F' };
        const std::vector<uint8_t> second{ 'G', 'H', 'I', 'J', 'K', 'L' };
        for (size_t k = 0; k < first.size(); ++k) bytes[2 + k] = first[k];
        bytes[8] = 0x7F;
        for (size_t k = 0; k < second.size(); ++k) bytes[9 + k] = second[k];
        std::vector<generate::Range> rodata{ { 0, bytes.size() } };
        generate::Image img{ bytes, {}, rodata, {} };

        auto ss = generate::strings(img);
        REQUIRE(ss.size() == 1);
        REQUIRE(ss[0].rva == 9);
        REQUIRE(ss[0].len == 6);
    }
}

// Build an image with a RIP-relative `lea` (48 8D <modrm> <disp32>) at
// `site`. `modrm` defaults to 0x0D -- mod=00, reg=001, rm=101 -- which is
// the exact byte the brief's Step 1 names.
static std::vector<uint8_t> make_lea_image(uint64_t site, int32_t disp,
                                           uint8_t modrm = 0x0D,
                                           size_t size = 0x1000) {
    std::vector<uint8_t> img(size, 0xCC);
    img[site] = 0x48;
    img[site + 1] = 0x8D;
    img[site + 2] = modrm;
    for (int k = 0; k < 4; ++k)
        img[site + 3 + k] = (uint8_t)((uint32_t)disp >> (8 * k));
    return img;
}

TEST_CASE("rip_refs_to resolves a hand-built 48 8D 0D <disp32> to its target",
          "[generate][ripref]") {
    // site = 0x200, target = 0x500: disp32 = target - (site + 7) = 761 =
    // 0x000002F9, little-endian bytes F9 02 00 00.
    const uint64_t site = 0x200;
    auto bytes = make_lea_image(site, 761);
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x500) == std::vector<uint64_t>{ site });
}

TEST_CASE("rip_refs_to resolves a backward reference (negative disp32), target computed by hand",
          "[generate][ripref]") {
    // site = 0x800. By hand: disp32 = target - (site + 7). Choosing raw bytes
    // F9 F8 FF FF little-endian gives disp32 = 0xFFFFF8F9 as int32 = -1799.
    // target = site + 7 + disp32 = 0x807 + (-1799) = 2055 - 1799 = 256 = 0x100,
    // computed here directly rather than by calling rip_refs_to and reading
    // back whatever it produces.
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    const uint64_t site = 0x800;
    bytes[site] = 0x48;
    bytes[site + 1] = 0x8D;
    bytes[site + 2] = 0x0D;    // mod=00, reg=001, rm=101
    bytes[site + 3] = 0xF9;
    bytes[site + 4] = 0xF8;
    bytes[site + 5] = 0xFF;
    bytes[site + 6] = 0xFF;
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x100) == std::vector<uint64_t>{ site });
}

TEST_CASE("rip_refs_to leaves modrm's reg field unconstrained", "[generate][ripref]") {
    // Two sites with different `reg` bits (000 and 111) in an otherwise
    // identical mod=00/rm=101 modrm byte. Both must be found: reg is the
    // destination register, not part of the addressing-mode gate.
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    auto site1 = make_lea_image(0x200, 249, 0x05, 0x1000);   // reg=000, target 0x300
    auto site2 = make_lea_image(0x400, 249, 0x3D, 0x1000);   // reg=111, target 0x500
    // Merge both instructions into one image.
    for (size_t i = 0x200; i < 0x207; ++i) bytes[i] = site1[i];
    for (size_t i = 0x400; i < 0x407; ++i) bytes[i] = site2[i];
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x300) == std::vector<uint64_t>{ 0x200 });
    REQUIRE(generate::rip_refs_to(img, 0x500) == std::vector<uint64_t>{ 0x400 });
}

TEST_CASE("rip_refs_to ignores a modrm whose mod is not 00", "[generate][ripref]") {
    // modrm = 0x45: mod=01, reg=000, rm=101 -- same rm as the RIP-relative
    // form, but mod=01 means disp8 base+displacement addressing, not RIP-
    // relative. If the gate only checked rm, this would wrongly match.
    const uint64_t site = 0x200;
    auto bytes = make_lea_image(site, 89, 0x45);   // would-be target 0x260 if accepted
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x260).empty());
}

TEST_CASE("rip_refs_to ignores a modrm whose rm is not 101", "[generate][ripref]") {
    // modrm = 0x04: mod=00, reg=000, rm=100 -- mod=00 matches, but rm=100
    // means a SIB byte follows, not a disp32. If the gate only checked mod,
    // this would wrongly match.
    const uint64_t site = 0x200;
    auto bytes = make_lea_image(site, 89, 0x04);   // would-be target 0x260 if accepted
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x260).empty());
}

TEST_CASE("rip_refs_to does not read past the end of a range", "[generate][ripref]") {
    // Only 6 bytes follow `site` inside the range -- one byte short of the 7
    // the instruction needs. The image itself keeps going past the range,
    // and the byte exactly at `r.end` (the disp32's would-be top byte) is
    // deliberately set so that, IF an over-length read used it, the result
    // would resolve to a specific, checkable target (0x999). That makes this
    // decisive rather than relying on undefined behaviour happening to
    // produce something that doesn't match: a buggy bound (e.g. `i + 6 <=
    // hi`) is caught by finding 0x999, not by a crash.
    const uint64_t site = 0x10;
    const uint64_t range_end = site + 6;      // 6 bytes follow: site..site+5
    std::vector<uint8_t> bytes(0x100, 0xCC);
    bytes[site] = 0x48;
    bytes[site + 1] = 0x8D;
    bytes[site + 2] = 0x0D;                   // a valid gate, if only the disp32 fit
    // disp32 = 0x00000982 little-endian; if all 4 bytes (including the one
    // at range_end, past the range) were read, target = site + 7 + 0x982
    // = 0x999. That last byte sits one past the range on purpose.
    bytes[site + 3] = 0x82;
    bytes[site + 4] = 0x09;
    bytes[site + 5] = 0x00;
    bytes[range_end] = 0x00;                  // one byte past r.end -- must not be read
    std::vector<generate::Range> code{ { 0, range_end } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x999).empty());
}

TEST_CASE("rip_refs_to ignores references outside code ranges", "[generate][ripref]") {
    const uint64_t site = 0x200;
    auto bytes = make_lea_image(site, 761);    // target 0x500, same as the basic case
    std::vector<generate::Range> code{ { 0, 0x100 } };   // does not cover 0x200
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x500).empty());
}

TEST_CASE("rip_refs_to matches every REX.W lea, not just the 0x48 encoding",
          "[generate][ripref]") {
    // This test used to assert the OPPOSITE, pinning a deliberate decision to
    // match `48 8D` alone. That decision was wrong, and its stated cost -- "a
    // coverage limit, not a correctness bug" -- was the wrong half to be
    // confident about.
    //
    // REX is 0100WRXB, so a lea whose DESTINATION is r8-r15 sets REX.R and
    // encodes as `4C 8D`. On a retail binary that is 29.1% of all
    // rip-relative LEAs, 112,180 of 385,184, and 30.5% of those targeting
    // .rdata. r8 and r9 are the third and fourth integer arguments in the
    // Win64 ABI, so `lea r8, [rip+string]` is one of the commonest ways a
    // string reaches a call -- exactly the StringAnchor substrate.
    //
    // And the correctness half: a MISSING reference manufactures FALSE
    // UNIQUENESS. `rip_refs_to(...).size() == 1` cannot distinguish "one
    // reference exists" from "one was indexed and the rest were skipped".
    //
    // REX.X and REX.B are meaningless for a RIP-relative operand, so the whole
    // 0x48-0x4F range is the same instruction and the check is a mask.
    const uint64_t site = 0x200;
    for (uint8_t rex : { 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F }) {
        auto bytes = make_lea_image(site, 761);
        bytes[site] = rex;
        std::vector<generate::Range> code{ { 0, bytes.size() } };
        generate::Image img{ bytes, code, {}, {} };
        INFO("REX prefix 0x" << std::hex << (int)rex);
        REQUIRE(generate::rip_refs_to(img, 0x500) == std::vector<uint64_t>{ site });
    }

    // Not a blanket "any first byte": 0x40 is REX with W clear, which is not
    // a 64-bit lea, and 0x8D alone is the 32-bit form. Both must still miss,
    // or the mask has simply stopped filtering.
    for (uint8_t rex : { 0x40, 0x44, 0x47, 0x50, 0x8D }) {
        auto bytes = make_lea_image(site, 761);
        bytes[site] = rex;
        std::vector<generate::Range> code{ { 0, bytes.size() } };
        generate::Image img{ bytes, code, {}, {} };
        INFO("prefix 0x" << std::hex << (int)rex << " must NOT match");
        REQUIRE(generate::rip_refs_to(img, 0x500).empty());
    }
}

TEST_CASE("rip_refs_to's target is site + 7 + disp32, not site + 6 or site + 8",
          "[generate][ripref]") {
    // disp32 is fixed at 0x10. The correct target is site + 7 + 0x10; the
    // targets a +6 or +8 convention would produce instead are one less and
    // one more, respectively, and must resolve to nothing.
    const uint64_t site = 0x200;
    auto bytes = make_lea_image(site, 0x10);
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    const uint64_t correct = site + 7 + 0x10;   // 0x217
    REQUIRE(generate::rip_refs_to(img, correct) == std::vector<uint64_t>{ site });
    REQUIRE(generate::rip_refs_to(img, correct - 1).empty());   // the +6 result
    REQUIRE(generate::rip_refs_to(img, correct + 1).empty());   // the +8 result
}

TEST_CASE("rip_refs_to returns sites in ascending order and does not duplicate a site covered by overlapping code ranges",
          "[generate][ripref]") {
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    auto lea1 = make_lea_image(0x200, 1785);   // target 0x900
    auto lea2 = make_lea_image(0x400, 1273);   // target 0x900
    for (size_t i = 0x200; i < 0x207; ++i) bytes[i] = lea1[i];
    for (size_t i = 0x400; i < 0x407; ++i) bytes[i] = lea2[i];
    // Two overlapping ranges, both covering the site at 0x200.
    std::vector<generate::Range> code{ { 0, 0x300 }, { 0x100, 0x500 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x900) == std::vector<uint64_t>{ 0x200, 0x400 });
}

TEST_CASE("rip_refs_to sorts sites ascending even when code ranges push them out of order",
          "[generate][ripref]") {
    // Ranges are supplied in DESCENDING address order, and each contains one
    // matching lea, so the natural push order during the scan is [0x400,
    // 0x200] -- the OPPOSITE of ascending. If the implementation relied on
    // erase(unique(...)) alone (no sort), this would come back unsorted;
    // only an actual sort produces the documented ascending guarantee.
    // Mirrors the out-of-order-ranges shape strings() is tested with
    // ({0x60,0x90},{0,0x30},{0x30,0x60}).
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    auto lea_hi = make_lea_image(0x400, 1273);   // target 0x900
    auto lea_lo = make_lea_image(0x200, 1785);   // target 0x900
    for (size_t i = 0x400; i < 0x407; ++i) bytes[i] = lea_hi[i];
    for (size_t i = 0x200; i < 0x207; ++i) bytes[i] = lea_lo[i];
    std::vector<generate::Range> code{ { 0x400, 0x500 }, { 0x200, 0x300 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x900) == std::vector<uint64_t>{ 0x200, 0x400 });
}

TEST_CASE("rip_refs_to rejects a well-formed 48 89 05 <disp32> (mov, not lea) whose disp32 resolves to the target",
          "[generate][ripref]") {
    // 48 89 05 <disp32> is `mov [rip+disp], rax` -- REX.W, opcode 0x89, the
    // same mod=00/rm=101 modrm a RIP-relative lea would use, and a disp32
    // engineered to resolve to the exact target being queried. The ONLY
    // thing that can reject this is checking the second opcode byte (0x8D);
    // a mutant that drops that check and looks only at the 0x48 prefix
    // reports this mov as a lea, which on a real image means every
    // `48 ?? <mod=00,rm=101>` form -- not just lea -- gets misreported.
    const uint64_t site = 0x200;
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    bytes[site] = 0x48;
    bytes[site + 1] = 0x89;    // MOV, not 0x8D (LEA)
    bytes[site + 2] = 0x05;    // mod=00, reg=000, rm=101
    // disp32 = 0x570 little-endian, chosen so site + 7 + disp32 == 0x777.
    bytes[site + 3] = 0x70;
    bytes[site + 4] = 0x05;
    bytes[site + 5] = 0x00;
    bytes[site + 6] = 0x00;
    std::vector<generate::Range> code{ { 0, bytes.size() } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_refs_to(img, 0x777).empty());
}

// --- StringAnchor (Task 8) --------------------------------------------------
//
// One fixture vocabulary for the whole strategy. 0xCC filler is deliberate on
// three counts: it is not printable, so it invents no strings; it is neither
// 0x48 nor 0x8D, so it invents no leas; and it is not 0xE8, so it invents no
// call sites. Code lives below 0x1000, rodata from 0x1000 up.
static constexpr size_t kSaSize = 0x2000;
static constexpr uint64_t kSaRodataBegin = 0x1000;
static constexpr uint64_t kSaRodataEnd = 0x1400;

static void put_str(std::vector<uint8_t>& b, uint64_t rva, const std::string& s) {
    for (size_t i = 0; i < s.size(); ++i)
        b[rva + i] = (uint8_t)s[i];
    b[rva + s.size()] = 0x00;                 // strings() requires the NUL
}

static void put_lea(std::vector<uint8_t>& b, uint64_t site, uint64_t strva,
                    uint8_t modrm = 0x0D) {
    b[site] = 0x48;
    b[site + 1] = 0x8D;
    b[site + 2] = modrm;
    // RIP-relative is measured from the END of the 7-byte instruction.
    const int32_t disp = (int32_t)((int64_t)strva - (int64_t)(site + 7));
    for (int k = 0; k < 4; ++k)
        b[site + 3 + k] = (uint8_t)((uint32_t)disp >> (8 * k));
}

static void put_call(std::vector<uint8_t>& b, uint64_t site, uint64_t callee) {
    b[site] = 0xE8;
    const int32_t rel = (int32_t)((int64_t)callee - (int64_t)(site + 5));
    for (int k = 0; k < 4; ++k)
        b[site + 1 + k] = (uint8_t)((uint32_t)rel >> (8 * k));
}

static void put_bytes(std::vector<uint8_t>& b, uint64_t at,
                      const std::vector<uint8_t>& v) {
    for (size_t i = 0; i < v.size(); ++i)
        b[at + i] = v[i];
}

static void clear_bytes(std::vector<uint8_t>& b, uint64_t at, size_t n) {
    for (size_t i = 0; i < n; ++i)
        b[at + i] = 0xCC;
}

static size_t count_sa(const std::vector<generate::Candidate>& cs) {
    size_t k = 0;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::StringAnchor)
            ++k;
    return k;
}

// Callers must pass a NAMED vector: the returned pointer is into `cs`, so
// first_sa(candidates(...)) dangles the instant the statement ends. Three of
// these tests were written that way and passed for the wrong reason.
static const generate::Candidate* first_sa(const std::vector<generate::Candidate>& cs) {
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::StringAnchor)
            return &c;
    return nullptr;
}

// The depth-0 shape used by several tests below and by the two-build test:
// target function [0x100, 0x180), a lea at 0x120 loading `strva`, a
// distinctive tail right behind it. `strva` is a parameter precisely so a
// second build can put the same string somewhere else.
static std::vector<uint8_t> make_depth0_image(uint64_t strva) {
    std::vector<uint8_t> b(kSaSize, 0xCC);
    put_str(b, strva, "STRING_ANCHOR_TEXT");
    put_lea(b, 0x120, strva);
    put_bytes(b, 0x127, { 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0, 0x74, 0x11 });
    return b;
}

TEST_CASE("StringAnchor anchors on the lea when the load site is in the target's own function",
          "[generate][stringanchor]") {
    auto bytes = make_depth0_image(kSaRodataBegin);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 } };
    generate::Image img{ bytes, code, rodata, funcs };

    // prefer_short off: what this pins is the SHAPE of a depth-0 anchor --
    // wildcarded displacement, whole-pattern max_len budget -- and
    // uniqueness-driven shortening of the tail is a separate property with
    // its own tests below.
    generate::Options o;
    o.prefer_short = false;
    auto cs = generate::candidates(img, 0x100, o);
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->save_index == 0);                       // no capture: the match itself
    REQUIRE(c->anchor_delta == 0x20);                  // 0x120 - 0x100
    // The four displacement bytes are wildcards, one `?` per byte.
    REQUIRE(c->pattern.rfind("48 8D 0D ? ? ? ? 4C 8B D0 48 85 C0 74 11", 0) == 0);

    // max_len budgets the WHOLE pattern, so the tail gets 64 - 7 bytes, and
    // `literals` counts concrete bytes only -- the four `?` are not literals.
    REQUIRE(c->literals == 3 + (64 - 7));

    // What comes out must go back in, minus the delta.
    auto comp = locate::compile(c->pattern);
    locate::prime(comp, bytes);
    auto hits = locate::find_all(bytes, comp, c->save_index, 2);
    REQUIRE(hits.size() == 1);
    REQUIRE((uint64_t)((int64_t)hits[0].offset - c->anchor_delta) == 0x100);
}

TEST_CASE("StringAnchor keeps the lea's modrm literal while wildcarding its displacement",
          "[generate][stringanchor]") {
    // modrm's reg field names the destination register and is part of the
    // instruction; only the displacement moves between builds. A pattern that
    // wildcarded the modrm too would match every RIP-relative lea in the image.
    std::vector<uint8_t> bytes(kSaSize, 0xCC);
    put_str(bytes, kSaRodataBegin, "STRING_ANCHOR_TEXT");
    put_lea(bytes, 0x120, kSaRodataBegin, 0x15);       // mod=00, reg=010, rm=101
    put_bytes(bytes, 0x127, { 0x4C, 0x8B, 0xD0 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 } };
    generate::Image img{ bytes, code, rodata, funcs };

    generate::Options o;
    o.prefer_short = false;   // keep the whole tail, so the modrm is not the only literal left
    auto cs = generate::candidates(img, 0x100, o);
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->pattern.rfind("48 8D 15 ? ? ? ? 4C 8B D0", 0) == 0);
}

TEST_CASE("a StringAnchor pattern survives the string moving between builds",
          "[generate][stringanchor][verified]") {
    // THE test for the wildcarded displacement, and the reason the strategy is
    // worth having. Two builds identical except for where the linker put the
    // string: the lea's disp32 differs, everything else is byte-for-byte the
    // same. A pattern with the displacement rendered as literals is unique in
    // build A and absent from build B, so verified() returns nothing -- which
    // a single-image test would never notice.
    auto a = make_depth0_image(0x1000);
    auto b = make_depth0_image(0x1100);

    // The fixture is only meaningful if the displacement really does differ.
    bool disp_differs = false;
    for (int k = 3; k < 7; ++k)
        if (a[0x120 + k] != b[0x120 + k])
            disp_differs = true;
    REQUIRE(disp_differs);

    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 } };
    generate::Image ia{ a, code, rodata, funcs };
    generate::Image ib{ b, code, rodata, funcs };

    auto v = generate::verified(ia, 0x100, ib, 0x100);
    REQUIRE(count_sa(v) == 1);
    REQUIRE(first_sa(v)->anchor_delta == 0x20);
}

TEST_CASE("a string whose bytes occur twice in rodata anchors nothing",
          "[generate][stringanchor]") {
    // strings() dedupes by RVA, not by content, so the same text in two rodata
    // slots is two entries. Anchoring on either is anchoring on whichever slot
    // the next build's linker kept -- so BOTH are disqualified.
    auto build = [](const std::string& second) {
        std::vector<uint8_t> b(kSaSize, 0xCC);
        put_str(b, 0x1000, "DUPLICATED_TEXT");
        put_str(b, 0x1100, second);
        put_lea(b, 0x120, 0x1000);
        put_bytes(b, 0x127, { 0x4C, 0x8B, 0xD0 });
        return b;
    };
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 } };

    auto dup = build("DUPLICATED_TEXT");
    generate::Image idup{ dup, code, rodata, funcs };
    REQUIRE(count_sa(generate::candidates(idup, 0x100)) == 0);

    // Positive control on the identical fixture: change only the second copy's
    // text and the very same lea now anchors a candidate. Without this the
    // assertion above would also pass if StringAnchor were broken outright.
    auto uniq = build("SOMETHING_ELSE_ENTIRELY");
    generate::Image iuniq{ uniq, code, rodata, funcs };
    REQUIRE(count_sa(generate::candidates(iuniq, 0x100)) == 1);
}

TEST_CASE("a string loaded from two sites anchors nothing", "[generate][stringanchor]") {
    // A string two functions load does not name a function: the pattern built
    // from either lea is one of two equally good matches, and which one a later
    // build keeps is not something the generator can know.
    std::vector<uint8_t> bytes(kSaSize, 0xCC);
    put_str(bytes, 0x1000, "STRING_ANCHOR_TEXT");
    put_lea(bytes, 0x120, 0x1000);                     // inside the target
    put_bytes(bytes, 0x127, { 0x4C, 0x8B, 0xD0 });
    put_lea(bytes, 0x200, 0x1000);                     // and a second loader
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 }, { 0x200, 0x280 } };
    generate::Image img{ bytes, code, rodata, funcs };
    REQUIRE(generate::rip_refs_to(img, 0x1000).size() == 2);   // the fixture is what it claims
    REQUIRE(count_sa(generate::candidates(img, 0x100)) == 0);

    // Positive control: erase the second loader, keep everything else, and the
    // first lea anchors a candidate again.
    clear_bytes(bytes, 0x200, 7);
    generate::Image one{ bytes, code, rodata, funcs };
    REQUIRE(generate::rip_refs_to(one, 0x1000).size() == 1);
    REQUIRE(count_sa(generate::candidates(one, 0x100)) == 1);
}

// A caller of `target` at 0x200 that loads a string at 0x210 and calls at
// `call_site`, with three distinctive bytes filling the gap between them.
static std::vector<uint8_t> make_depth1_image(uint64_t call_site, uint64_t target = 0x100) {
    std::vector<uint8_t> b(kSaSize, 0xCC);
    put_str(b, kSaRodataBegin, "STRING_ANCHOR_TEXT");
    put_lea(b, 0x210, kSaRodataBegin);
    put_bytes(b, 0x217, { 0x4C, 0x8B, 0xD0 });
    put_call(b, call_site, target);
    return b;
}

TEST_CASE("StringAnchor spans lea to call when the load site is in a direct caller",
          "[generate][stringanchor]") {
    auto bytes = make_depth1_image(0x21A);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x200, 0x280 } };
    generate::Image img{ bytes, code, rodata, funcs };

    auto cs = generate::candidates(img, 0x100);
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->save_index == 1);       // the `'` capture holds the callee
    REQUIRE(c->anchor_delta == 0);     // target comes from the slot, not the match
    REQUIRE(c->pattern == "48 8D 0D ? ? ? ? 4C 8B D0 E8 $ { ' }");
    REQUIRE(c->literals == 3 + 3 + 1); // lea opcode, gap, and the E8

    // The capture really does name the target.
    auto comp = locate::compile(c->pattern);
    locate::prime(comp, bytes);
    auto hits = locate::find_all(bytes, comp, c->save_index, 2);
    REQUIRE(hits.size() == 1);
    REQUIRE(hits[0].value == 0x100);

    // And verified() agrees -- it must read a capturing candidate's target
    // out of the save slot, not out of the match offset.
    //
    // TWO BUILDS, because verified() takes two. This used to pass `img`
    // twice, which verified() now refuses outright: a candidate checked
    // against its own image proves only that it was generated from that
    // image. Build B moves the target to 0x140 and leaves the caller where it
    // is; the pattern wildcards the string's displacement and captures the
    // callee out of the `E8`, so it names 0x140 there without being reissued.
    auto bytes_b = make_depth1_image(0x21A, 0x140);
    std::vector<generate::Range> funcs_b{ { 0x140, 0x180 }, { 0x200, 0x280 } };
    generate::Image img_b{ bytes_b, code, rodata, funcs_b };
    REQUIRE(count_sa(generate::verified(img, 0x100, img_b, 0x140)) == 1);
}

TEST_CASE("StringAnchor does not chase a grandcaller's string", "[generate][stringanchor]") {
    // G loads the string and calls F; F calls the target. `E8 $ { ' }` resolves
    // exactly ONE call edge, so a pattern anchored in G would capture F, not
    // the target. The bound is structural, not a budget.
    std::vector<uint8_t> bytes(kSaSize, 0xCC);
    put_str(bytes, kSaRodataBegin, "STRING_ANCHOR_TEXT");
    put_lea(bytes, 0x310, kSaRodataBegin);             // in G
    put_bytes(bytes, 0x317, { 0x4C, 0x8B, 0xD0 });
    put_call(bytes, 0x31A, 0x200);                     // G -> F
    put_call(bytes, 0x210, 0x100);                     // F -> target
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x200, 0x240 }, { 0x300, 0x380 } };
    generate::Image img{ bytes, code, rodata, funcs };
    REQUIRE(generate::callers_of(img, 0x200) == std::vector<uint64_t>{ 0x31A });   // G really calls F
    REQUIRE(generate::callers_of(img, 0x100) == std::vector<uint64_t>{ 0x210 });   // F really calls the target
    REQUIRE(count_sa(generate::candidates(img, 0x100)) == 0);

    // Positive control: point G's call straight at the target and the same lea
    // anchors a depth-1 candidate.
    put_call(bytes, 0x31A, 0x100);
    generate::Image direct{ bytes, code, rodata, funcs };
    auto cs = generate::candidates(direct, 0x100);
    REQUIRE(count_sa(cs) == 1);
    REQUIRE(first_sa(cs)->save_index == 1);
}

TEST_CASE("StringAnchor's call must lie in the same function as the lea",
          "[generate][stringanchor]") {
    // The call to the target is close enough to the lea to fit the budget, but
    // it belongs to the NEXT function -- so the lea's own function does not
    // call the target and there is nothing to anchor. Only the funcs bound can
    // reject this; a budget-only check accepts it and emits a pattern spanning
    // two functions.
    std::vector<uint8_t> bytes(kSaSize, 0xCC);
    put_str(bytes, kSaRodataBegin, "STRING_ANCHOR_TEXT");
    put_lea(bytes, 0x310, kSaRodataBegin);
    put_call(bytes, 0x330, 0x100);                     // 0x330 + 5 > 0x328
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x300, 0x328 }, { 0x328, 0x380 } };
    generate::Image img{ bytes, code, rodata, funcs };
    REQUIRE(count_sa(generate::candidates(img, 0x100)) == 0);

    // Positive control: widen the lea's function to cover the call and the same
    // bytes now anchor. The span is well inside the default 64-byte budget
    // either way, so the budget is not what changed.
    std::vector<generate::Range> wide{ { 0x100, 0x140 }, { 0x300, 0x380 } };
    generate::Image inside{ bytes, code, rodata, wide };
    REQUIRE(count_sa(generate::candidates(inside, 0x100)) == 1);
}

TEST_CASE("with funcs empty StringAnchor emits only the depth-1 form",
          "[generate][stringanchor]") {
    // Without funcs there is no way to say which function holds the lea, so
    // depth 0 -- which is defined entirely by that containment -- cannot be
    // established and is not guessed at.
    auto bytes = make_depth1_image(0x21A);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    generate::Image img{ bytes, code, rodata, {} };

    auto cs = generate::candidates(img, 0x100);
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->save_index == 1);
    REQUIRE(c->anchor_delta == 0);
    REQUIRE(c->pattern == "48 8D 0D ? ? ? ? 4C 8B D0 E8 $ { ' }");
}

TEST_CASE("with funcs empty a lea with no call to the target after it anchors nothing",
          "[generate][stringanchor]") {
    // The same bytes as the depth-0 fixture, minus any funcs. The lea sits
    // where the target's own function would be, but nothing says so, and
    // emitting a depth-0 candidate on that assumption would produce an
    // anchor_delta computed from a guess.
    auto bytes = make_depth0_image(kSaRodataBegin);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    generate::Image img{ bytes, code, rodata, {} };
    REQUIRE(count_sa(generate::candidates(img, 0x100)) == 0);
}

TEST_CASE("StringAnchor emits nothing rather than a pattern too short to reach the call",
          "[generate][stringanchor]") {
    // lea at 0x210, call at 0x290: the span from the lea through the end of the
    // call is 0x85 bytes, past the 64-byte default. A truncated pattern would
    // stop short of the E8, so the `'` slot would never be filled and the
    // candidate could not resolve to anything at all.
    auto bytes = make_depth1_image(0x290);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x200, 0x300 } };
    generate::Image img{ bytes, code, rodata, funcs };
    REQUIRE(count_sa(generate::candidates(img, 0x100)) == 0);

    // Raise the budget past the span and the same bytes anchor.
    generate::Options o;
    o.max_len = 200;
    auto cs = generate::candidates(img, 0x100, o);
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->literals == 3 + (0x290 - 0x217) + 1);
    REQUIRE(c->pattern.rfind("48 8D 0D ? ? ? ? 4C 8B D0 CC", 0) == 0);
    REQUIRE(c->pattern.size() > 10);
    REQUIRE(c->pattern.rfind("E8 $ { ' }") == c->pattern.size() - 10);  // and it reaches the call
}

TEST_CASE("StringAnchor runs after Body and inside the same anchor budget",
          "[generate][stringanchor]") {
    // Ordering and dedup are Task 10's business; what this pins is that
    // StringAnchor is a third block in the same `want` budget rather than a
    // replacement for either of the two before it.
    auto bytes = make_depth1_image(0x21A);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x200, 0x280 } };
    generate::Image img{ bytes, code, rodata, funcs };

    auto cs = generate::candidates(img, 0x100);
    std::vector<generate::Strategy> got;
    for (const auto& c : cs)
        got.push_back(c.strategy);
    REQUIRE(got == std::vector<generate::Strategy>{ generate::Strategy::Xref,
                                                    generate::Strategy::Body,
                                                    generate::Strategy::StringAnchor });

    // A budget Xref and Body already fill leaves no room for StringAnchor.
    generate::Options o;
    o.want = 2;
    REQUIRE(count_sa(generate::candidates(img, 0x100, o)) == 0);
}

TEST_CASE("a StringAnchor candidate carries the seed select_seed would choose",
          "[generate][stringanchor]") {
    auto bytes = make_depth0_image(kSaRodataBegin);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 } };
    generate::Image img{ bytes, code, rodata, funcs };

    auto cs = generate::candidates(img, 0x100);
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(!c->seed.bytes.empty());
    REQUIRE(c->seed.ok());
    auto want = locate::select_seed(bytes, locate::fixed_bytes(c->pattern));
    REQUIRE(c->seed.bytes == want.bytes);
    REQUIRE(c->seed.offset == want.offset);
}

TEST_CASE("StringAnchor anchors nothing when the image has no rodata to draw on",
          "[generate][stringanchor]") {
    // The lea and the call are both there; only the string table is missing.
    // The other strategies are unaffected, which is the point -- selection
    // filters choose a string to anchor on, they never suppress anything else.
    auto bytes = make_depth1_image(0x21A);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x200, 0x280 } };
    generate::Image img{ bytes, code, {}, funcs };
    auto cs = generate::candidates(img, 0x100);
    REQUIRE(count_sa(cs) == 0);
    REQUIRE(cs.size() == 2);                           // Xref and Body still emit
}

// ---------------------------------------------------------------------------
// Strategy::RipRef. Same fixture discipline as StringAnchor: 0xCC filler
// invents no strings, no leas and no call sites, code lives below 0x1000 and
// the globals these instructions reference sit above it, outside any code
// range -- which is the situation the strategy exists for. A global has no
// call site for Xref and no entry bytes for Body.
static constexpr size_t kRrSize = 0x2000;
static constexpr uint64_t kRrGlobal = 0x1200;

// One RIP-relative instruction: opcode bytes, modrm, disp32, then whatever
// immediate the form carries. The displacement is measured from the END of the
// instruction, THE IMMEDIATE INCLUDED -- writing this helper the other way
// would build a fixture that agrees with the bug instead of catching it.
static void put_rip_insn(std::vector<uint8_t>& b, uint64_t site,
                         const std::vector<uint8_t>& opcode, uint8_t modrm,
                         uint64_t global, const std::vector<uint8_t>& imm) {
    uint64_t p = site;
    for (uint8_t o : opcode)
        b[p++] = o;
    b[p++] = modrm;
    const uint64_t end = site + opcode.size() + 1 + 4 + imm.size();
    const int32_t disp = (int32_t)((int64_t)global - (int64_t)end);
    for (int k = 0; k < 4; ++k)
        b[p++] = (uint8_t)((uint32_t)disp >> (8 * k));
    for (uint8_t v : imm)
        b[p++] = v;
}

static size_t count_rr(const std::vector<generate::Candidate>& cs) {
    size_t k = 0;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::RipRef)
            ++k;
    return k;
}

// As with first_sa: the caller must pass a NAMED vector, or the pointer
// dangles the instant the full expression ends.
static const generate::Candidate* first_rr(const std::vector<generate::Candidate>& cs) {
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::RipRef)
            return &c;
    return nullptr;
}

// What a pattern's save slot actually holds in this image, or nothing when it
// does not match exactly once. Every trap assertion below goes through this:
// the claim being pinned is about the ADDRESS CAPTURED, not about the text.
static std::optional<uint64_t> captured(const std::vector<uint8_t>& img,
                                        const std::string& pattern,
                                        size_t save_index = 1) {
    auto comp = locate::compile(pattern);
    locate::prime(comp, img);
    auto hits = locate::find_all(img, comp, save_index, 2);
    if (hits.size() != 1)
        return std::nullopt;
    return hits[0].value;
}

TEST_CASE("RipRef anchors on a mov whose disp32 names the global", "[generate][ripref]") {
    // The form with no trailing immediate: the disp32 IS the last field, so a
    // bare `$` is already correct and no corrective skip appears.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x0D, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    REQUIRE(cs.size() == 1);                     // no caller, no body, no string
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    // Three opcode bytes, the capturing block, and a LITERAL TAIL. The tail
    // is what makes this a pattern rather than an instruction selector: see
    // the ambiguity test below, where the tail-free form has seven hits.
    // Here the filler is 0xCC, so the tail is four bytes of it -- the floor
    // (detail::kMinLiteralRun), since one byte of context is already unique
    // on a fixture this bare.
    REQUIRE(c->pattern == "48 8B 0D $ { ' } CC CC CC CC");
    REQUIRE(c->save_index == 1);                 // captures, so nonzero -- the invariant
    REQUIRE(c->anchor_delta == 0);               // target comes from the slot
    REQUIRE(c->literals == 3 + 4);               // 48 8B 0D, plus the tail
    REQUIRE(c->seed.ok());

    REQUIRE(captured(bytes, c->pattern) == kRrGlobal);
}

TEST_CASE("RipRef anchors on a lea, which NAMES a global rather than reading it",
          "[generate][ripref]") {
    // The other kRipForms rows all dereference the global -- mov from it, mov
    // to it, imul with it, cmp against it. `lea` takes its ADDRESS, and that
    // is how a global is most often referenced at all: the address is then
    // passed, stored, or indexed rather than loaded on the spot.
    //
    // Omitting the row was not a partial gap. A global whose only references
    // are leas got NO candidate from any strategy: Xref needs a call site a
    // datum never has, Body needs the target inside a code range, and
    // StringAnchor needs it to be a string. Measured on a real client, nine
    // of twelve globals reported unanchorable produced nothing at all; with
    // this row, two-build verified() went 2/9 -> 5/9.
    //
    // 4C rather than 48 as the REX byte on purpose: REX.R selects r8-r15 as
    // the destination, and the mask that admits it (0xF8) is the same one a
    // previous defect got wrong by testing == 0x48. A lea row added without
    // that mask would silently miss every lea into a high register.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x4C, 0x8D }, 0x35, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    REQUIRE(count_rr(cs) == 1);
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    // disp32 is the last field, so a bare `$` is correct: no corrective skip.
    REQUIRE(c->pattern == "4C 8D 35 $ { ' } CC CC CC CC");
    REQUIRE(c->save_index == 1);
    REQUIRE(c->anchor_delta == 0);
    REQUIRE(captured(bytes, c->pattern) == kRrGlobal);
}

TEST_CASE("RipRef corrects for a trailing imm32, and the uncorrected form is four bytes low",
          "[generate][ripref]") {
    // BOTH HALVES, exactly as tests/test_patterns.cpp pins them for the
    // matcher. A test that only checks the corrected pattern cannot tell the
    // two apart: the uncorrected one still matches and still reports one hit.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x69 }, 0x15, kRrGlobal, { 0x98, 0x00, 0x00, 0x00 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    // The tail starts just past the disp32, where `}` leaves the cursor --
    // so the trailing imm32 (0x98) lands in it as literal context. That is
    // the immediate working FOR the pattern: "the site that multiplies this
    // global by 0x98" is far more distinctive than "a site that reads it".
    REQUIRE(c->pattern == "48 69 15 $ { [4] ' } 98 00 00 00");
    REQUIRE(c->save_index == 1);
    REQUIRE(c->anchor_delta == 0);
    REQUIRE(c->literals == 3 + 4);

    // The emitted pattern resolves to the SAME global the mov form does.
    // The `[4]` skip walks the CAPTURE's cursor; the tail behind `}` is the
    // outer cursor's business, and the two do not interfere.
    REQUIRE(captured(bytes, c->pattern) == kRrGlobal);

    // And the pattern that would come out with the skip dropped resolves four
    // bytes below it -- plausible, unique, and wrong.
    REQUIRE(captured(bytes, "48 69 15 $ { ' }") == kRrGlobal - 4);
}

TEST_CASE("RipRef corrects for a trailing imm8, and the uncorrected form is one byte low",
          "[generate][ripref]") {
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x83 }, 0x3D, kRrGlobal, { 0x07 });   // cmp dword [rip+d], 7
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->pattern == "83 3D $ { [1] ' } 07 CC CC CC");
    REQUIRE(c->literals == 2 + 4);               // 83 and the modrm, plus the tail

    REQUIRE(captured(bytes, c->pattern) == kRrGlobal);
    REQUIRE(captured(bytes, "83 3D $ { ' }") == kRrGlobal - 1);
}

TEST_CASE("RipRef corrects for the imm32 store form too", "[generate][ripref]") {
    // `48 C7 /0 id` writes an immediate to the global. A bare `$` can never
    // capture a global that is only ever written this way, which is half the
    // reason README.md lists the form.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0xC7 }, 0x05, kRrGlobal, { 0x01, 0x00, 0x00, 0x00 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    // The stored constant is the first thing in the tail, which is exactly
    // the context this form wants: `mov qword [rip+X], 1` is one particular
    // initialisation, not "some write to the global".
    REQUIRE(c->pattern == "48 C7 05 $ { [4] ' } 01 00 00 00");
    REQUIRE(captured(bytes, c->pattern) == kRrGlobal);
    REQUIRE(captured(bytes, "48 C7 05 $ { ' }") == kRrGlobal - 4);
}

TEST_CASE("RipRef's target arithmetic uses the FULL instruction length, immediate included",
          "[generate][ripref]") {
    // Reading the target as disp32-offset + 4 instead of the whole length is
    // the same off-by-the-immediate error as dropping the skip, moved into the
    // scan: every immediate-bearing site would then answer to the address one
    // immediate below the real global, and to nothing at the global itself.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x69 }, 0x15, kRrGlobal, { 0x98, 0x00, 0x00, 0x00 });
    put_rip_insn(bytes, 0x140, { 0x83 }, 0x3D, kRrGlobal, { 0x07 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto refs = generate::rip_operand_refs_to(img, kRrGlobal);
    REQUIRE(refs.size() == 2);
    REQUIRE(refs[0].site == 0x120);
    REQUIRE(refs[1].site == 0x140);              // ascending
    REQUIRE(refs[0].form->imm_width == 4);
    REQUIRE(refs[1].form->imm_width == 1);

    // Neither site references the short address, and asking for it finds none.
    REQUIRE(generate::rip_operand_refs_to(img, kRrGlobal - 4).empty());
    REQUIRE(generate::rip_operand_refs_to(img, kRrGlobal - 1).empty());
}

TEST_CASE("an encoding outside the table anchors nothing rather than being guessed at",
          "[generate][ripref]") {
    // `C7 05 <disp32> <imm32>` -- the 32-bit-operand store, no REX prefix, ten
    // bytes long. It is a real RIP-relative reference to the global and it is
    // NOT in the table, so nothing is emitted for it. The alternative -- assume
    // the disp32 is last -- would emit `C7 05 $ { ' }`, which matches, reports
    // one hit, and captures an address four bytes below the global with nothing
    // downstream able to notice.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0xC7 }, 0x05, kRrGlobal, { 0x01, 0x00, 0x00, 0x00 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_operand_refs_to(img, kRrGlobal).empty());
    REQUIRE(count_rr(generate::candidates(img, kRrGlobal)) == 0);

    // Nor does the site turn up under the address the guessed reading would
    // have computed. Checking only the global would let a fallback through:
    // one that reads this ten-byte instruction as six answers to global - 4,
    // and says nothing at the global at all.
    REQUIRE(generate::rip_operand_refs_to(img, kRrGlobal - 4).empty());

    // The fixture is only meaningful if the site really does reference the
    // global, and if the guessed reading really would be wrong.
    REQUIRE(captured(bytes, "C7 05 $ { [4] ' }") == kRrGlobal);
    REQUIRE(captured(bytes, "C7 05 $ { ' }") == kRrGlobal - 4);
}

TEST_CASE("RipRef leaves modrm's reg field free where it names a register",
          "[generate][ripref]") {
    // `48 8B /r`: reg is the destination, so every value of it is the same
    // instruction and the modrm byte stays literal in the pattern -- the same
    // rule rip_refs_to applies to lea.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x05, kRrGlobal, {});   // rax
    put_rip_insn(bytes, 0x140, { 0x48, 0x8B }, 0x3D, kRrGlobal, {});   // rdi
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    REQUIRE(count_rr(cs) == 2);
    REQUIRE(cs[0].pattern == "48 8B 05 $ { ' } CC CC CC CC");
    REQUIRE(cs[1].pattern == "48 8B 3D $ { ' } CC CC CC CC");
}

TEST_CASE("RipRef holds modrm's reg field where the opcode's own /digit lives there",
          "[generate][ripref]") {
    // `83 /7` is cmp. `83 /0` is add: a different instruction that the cmp row
    // does not describe, so it is skipped like any other unlisted form rather
    // than matched by a row that names cmp.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x83 }, 0x05, kRrGlobal, { 0x07 });   // 83 /0, add
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_operand_refs_to(img, kRrGlobal).empty());
    REQUIRE(count_rr(generate::candidates(img, kRrGlobal)) == 0);
}

TEST_CASE("RipRef ignores a modrm that is not RIP-relative", "[generate][ripref]") {
    // mod=01 (disp8) and rm=100 (SIB) are ordinary memory operands, not
    // RIP-relative ones: `(modrm & 0xC7) == 0x05` is the whole gate.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x4D, kRrGlobal, {});   // mod=01
    put_rip_insn(bytes, 0x140, { 0x48, 0x8B }, 0x0C, kRrGlobal, {});   // rm=100
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(generate::rip_operand_refs_to(img, kRrGlobal).empty());
}

TEST_CASE("RipRef scans code ranges only, at every byte offset", "[generate][ripref]") {
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x121, { 0x48, 0x8B }, 0x0D, kRrGlobal, {});   // odd, unaligned
    put_rip_insn(bytes, 0x800, { 0x48, 0x8B }, 0x0D, kRrGlobal, {});   // outside `code`
    std::vector<generate::Range> code{ { 0x100, 0x200 } };
    generate::Image img{ bytes, code, {}, {} };

    auto refs = generate::rip_operand_refs_to(img, kRrGlobal);
    REQUIRE(refs.size() == 1);
    REQUIRE(refs[0].site == 0x121);
}

TEST_CASE("RipRef needs the whole instruction in bounds, not just the displacement",
          "[generate][ripref]") {
    // The imul form is eleven bytes. A range ending after its disp32 but
    // before its imm32 does not contain it, and reading the immediate's bytes
    // would be reading past the range -- the same rule callers_of and
    // rip_refs_to already apply to their own fixed lengths.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x69 }, 0x15, kRrGlobal, { 0x98, 0x00, 0x00, 0x00 });

    std::vector<generate::Range> tight{ { 0x100, 0x127 } };            // 7 of 11 bytes
    generate::Image cut{ bytes, tight, {}, {} };
    REQUIRE(generate::rip_operand_refs_to(cut, kRrGlobal).empty());

    std::vector<generate::Range> whole{ { 0x100, 0x12B } };            // all 11
    generate::Image full{ bytes, whole, {}, {} };
    REQUIRE(generate::rip_operand_refs_to(full, kRrGlobal).size() == 1);

    // bytes.size() clamps the same way a range end does.
    std::vector<uint8_t> shortimg(bytes.begin(), bytes.begin() + 0x127);
    generate::Image clipped{ shortimg, whole, {}, {} };
    REQUIRE(generate::rip_operand_refs_to(clipped, kRrGlobal).empty());
}

TEST_CASE("RipRef reads the four forms a consumer had to hand-write",
          "[generate][ripref]") {
    // These four rows were added because a downstream project verified
    // hand-built patterns for globals `candidates()` returned nothing for.
    // The forms differ in length (6, 7 and 8 bytes) and in where modrm sits,
    // which is the part a single masked row cannot express.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x0F, 0x11 }, 0x05, kRrGlobal, {});        // movups store
    put_rip_insn(bytes, 0x140, { 0x8B }, 0x05, kRrGlobal, {});              // mov r32, no REX
    put_rip_insn(bytes, 0x160, { 0x0F, 0xB6 }, 0x05, kRrGlobal, {});        // movzx r32
    put_rip_insn(bytes, 0x180, { 0x44, 0x0F, 0xB6 }, 0x05, kRrGlobal, {});  // REX.R movzx
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto refs = generate::rip_operand_refs_to(img, kRrGlobal);
    REQUIRE(refs.size() == 4);
    REQUIRE(refs[0].site == 0x120);
    REQUIRE(refs[0].form->total_len == 7);
    REQUIRE(refs[1].site == 0x140);
    REQUIRE(refs[1].form->total_len == 6);
    REQUIRE(refs[2].site == 0x160);
    REQUIRE(refs[2].form->total_len == 7);
    REQUIRE(refs[3].site == 0x180);
    REQUIRE(refs[3].form->total_len == 8);

    // And each becomes a candidate that resolves to the global -- the length
    // is what the `$` arithmetic trusts, so a row with the wrong total_len
    // would still match here and capture the wrong address.
    auto cs = generate::candidates(img, kRrGlobal, { .want = 8 });
    REQUIRE(count_rr(cs) == 4);
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::RipRef)
            REQUIRE(captured(bytes, c.pattern) == kRrGlobal);
}

TEST_CASE("a shorter form does not report a second site inside a longer one",
          "[generate][ripref]") {
    // `8B 05 <disp>` is the byte tail of `48 8B 05 <disp>`, and `0F B6 05
    // <disp>` the tail of `44 0F B6 05 <disp>`. Both shorter readings start
    // one byte in and END at the same address, so their target arithmetic
    // agrees and nothing downstream can reject them.
    //
    // They are the same instruction counted twice. Two anchors one byte apart
    // are not two anchors -- they die together in the next build -- so the
    // set has to hold one per instruction end.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x05, kRrGlobal, {});
    put_rip_insn(bytes, 0x140, { 0x44, 0x0F, 0xB6 }, 0x05, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto refs = generate::rip_operand_refs_to(img, kRrGlobal);
    REQUIRE(refs.size() == 2);
    REQUIRE(refs[0].site == 0x120);
    REQUIRE(refs[0].form->total_len == 7);   // the REX reading, not `8B` at 0x121
    REQUIRE(refs[1].site == 0x140);
    REQUIRE(refs[1].form->total_len == 8);   // not `0F B6` at 0x141
    REQUIRE(count_rr(generate::candidates(img, kRrGlobal, { .want = 8 })) == 2);
}

TEST_CASE("the end-dedup keeps one site per instruction, not one per opcode row",
          "[generate][ripref]") {
    // The case the rejected alternative got wrong. Guarding on "is the
    // preceding byte 0x40-0x4F" drops a genuine non-REX site whenever the
    // byte before it happens to be a displacement or immediate in that range
    // -- here a plain 0x48 that is data, not a prefix.
    //
    // Keying on the instruction END drops nothing: both readings of these
    // bytes -- `48 8B 05 <disp>` from 0x11F and `8B 05 <disp>` from 0x120 --
    // finish at 0x126 and name the same global, so exactly one anchor is
    // emitted and it resolves correctly either way. One end, one anchor.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x8B }, 0x05, kRrGlobal, {});
    bytes[0x11F] = 0x48;                     // data, but a legal REX reading
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto refs = generate::rip_operand_refs_to(img, kRrGlobal);
    REQUIRE(refs.size() == 1);
    REQUIRE(refs[0].site + refs[0].form->total_len == 0x126);

    auto cs = generate::candidates(img, kRrGlobal, { .want = 8 });
    REQUIRE(count_rr(cs) == 1);
    const generate::Candidate* rr = first_rr(cs);
    REQUIRE(rr != nullptr);
    REQUIRE(captured(bytes, rr->pattern) == kRrGlobal);
}

TEST_CASE("a bare 8B site with no REX reading of its own is still found",
          "[generate][ripref]") {
    // The row exists for globals loaded 32 bits at a time, which is the form
    // one consumer's CURRENT_TIMESTAMP is read through. 0xCC before it means
    // there is no longer reading to prefer, so the site stands on its own.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x8B }, 0x05, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto refs = generate::rip_operand_refs_to(img, kRrGlobal);
    REQUIRE(refs.size() == 1);
    REQUIRE(refs[0].site == 0x120);
    REQUIRE(refs[0].form->total_len == 6);
}

TEST_CASE("a RipRef candidate survives the global moving between builds",
          "[generate][ripref][verified]") {
    // The two-build test, on the immediate-bearing form because that is where
    // the trap lives. Both builds are byte-identical except for where the
    // linker put the global, so the disp32 differs and the pattern does not.
    //
    // This is also what a dropped corrective skip costs: the capture would be
    // four bytes below each build's global, so resolves_uniquely rejects it in
    // both and verified() returns nothing.
    auto build = [](uint64_t global) {
        std::vector<uint8_t> b(kRrSize, 0xCC);
        put_rip_insn(b, 0x120, { 0x48, 0x69 }, 0x15, global, { 0x98, 0x00, 0x00, 0x00 });
        return b;
    };
    auto a = build(0x1200);
    auto b = build(0x1300);
    bool disp_differs = false;
    for (int k = 3; k < 7; ++k)
        if (a[0x120 + k] != b[0x120 + k])
            disp_differs = true;
    REQUIRE(disp_differs);

    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image ia{ a, code, {}, {} };
    generate::Image ib{ b, code, {}, {} };

    auto v = generate::verified(ia, 0x1200, ib, 0x1300);
    REQUIRE(count_rr(v) == 1);
    // The imm32 rides along in the tail and is identical in both builds --
    // only the disp32 moved, and the disp32 is the one field the pattern
    // does not spell out.
    REQUIRE(first_rr(v)->pattern == "48 69 15 $ { [4] ' } 98 00 00 00");
    REQUIRE(first_rr(v)->save_index == 1);

    // save_index 0 would send resolves_uniquely down the match-offset branch,
    // which answers 0x120 rather than the global: the candidate resolves to
    // its own anchor and nothing survives.
    generate::Candidate mis = *first_rr(v);
    mis.save_index = 0;
    REQUIRE_FALSE(generate::detail::resolves_uniquely(a, mis, 0x1200));
}

TEST_CASE("RipRef runs after StringAnchor and inside the same anchor budget",
          "[generate][ripref]") {
    // A target that is both called and RIP-referenced, so more than one
    // strategy has something to say about it. Ordering and dedup are Task 10's
    // business; what this pins is that RipRef is a fourth block in the same
    // `want` budget, not a replacement for anything before it.
    auto bytes = make_call_image(0x100, { 0x300 }, kRrSize);
    put_rip_insn(bytes, 0x400, { 0x48, 0x8B }, 0x0D, 0x100, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, 0x100);
    std::vector<generate::Strategy> got;
    for (const auto& c : cs)
        got.push_back(c.strategy);
    REQUIRE(got == std::vector<generate::Strategy>{ generate::Strategy::Xref,
                                                    generate::Strategy::Body,
                                                    generate::Strategy::RipRef });

    generate::Options o;
    o.want = 2;                                  // Xref and Body fill it
    REQUIRE(count_rr(generate::candidates(img, 0x100, o)) == 0);
}

TEST_CASE("a RipRef candidate carries the seed select_seed would choose", "[generate][ripref]") {
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x0D, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal);
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    auto want = locate::select_seed(bytes, locate::fixed_bytes(c->pattern));
    REQUIRE(c->seed.bytes == want.bytes);
    REQUIRE(c->seed.offset == want.offset);
    REQUIRE(c->seed.bytes.size() == 3);          // the fixed region ends at `$`
}

// ---------------------------------------------------------------------------
// Task 10: the seams. Dedup, ordering, the `want` bound, `prefer_short`, and
// the oversample verified() needs to return `want` anchors that WORK rather
// than `want` that were tried.

static const generate::Candidate* first_of(const std::vector<generate::Candidate>& cs,
                                           generate::Strategy s) {
    for (const auto& c : cs)
        if (c.strategy == s)
            return &c;
    return nullptr;
}

// How many times `pattern` matches in `img`. Capped well above 1 so a test can
// say "this is NOT unique, and here is how far from unique it is".
static size_t hit_count(const std::vector<uint8_t>& img, const std::string& pattern,
                        size_t save_index = 0) {
    auto comp = locate::compile(pattern);
    locate::prime(comp, img);
    return locate::find_all(img, comp, save_index, 8).size();
}

// A target every strategy has something to say about: it is CALLED (Xref), it
// is a function with its own body (Body), its function loads a string that is
// unique in rodata and loaded nowhere else (StringAnchor, depth 0), and a
// RIP-relative `mov` names it (RipRef). 0xCC filler, as everywhere else here,
// invents no strings, leas, calls or table forms.
//
// Every address is a parameter, defaulting to the original layout, so a
// SECOND BUILD of the same logical code can be laid out elsewhere. verified()
// takes two images and refuses to be handed one twice; a test that wants four
// verified anchors needs a real second compilation to check them against.
static std::vector<uint8_t> make_all_four_image(uint64_t target = 0x100,
                                                uint64_t strva = 0x1000,
                                                uint64_t caller = 0x210,
                                                uint64_t rip_site = 0x310) {
    std::vector<uint8_t> b(0x2000, 0xCC);
    put_str(b, strva, "ALL_FOUR_STRATEGIES");
    put_bytes(b, target, { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57 });      // the target's prologue
    put_lea(b, target + 0x10, strva);                                  // ... which loads the string
    put_bytes(b, target + 0x17, { 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 });
    put_call(b, caller, target);                                       // a caller, elsewhere
    put_rip_insn(b, rip_site, { 0x48, 0x8B }, 0x0D, target, {});       // and a rip-relative load
    return b;
}

static const std::vector<generate::Range> kAllFourCode{ { 0, 0x1000 } };
static const std::vector<generate::Range> kAllFourRodata{ { 0x1000, 0x1400 } };
static const std::vector<generate::Range> kAllFourFuncs{
    { 0x100, 0x180 }, { 0x200, 0x280 }, { 0x300, 0x380 }
};

// The same shape, relocated: target 0x400, its string at 0x1100, its caller at
// 0x510 and its rip-relative load at 0x610.
static const std::vector<generate::Range> kAllFourFuncsB{
    { 0x400, 0x480 }, { 0x500, 0x580 }, { 0x600, 0x680 }
};

TEST_CASE("every strategy reports the site it anchored on",
          "[generate][integration]") {
    // The field exists to answer "are these anchors independent?", so the
    // test that matters is that each strategy names its OWN anchor point --
    // not the target, and not zero. A field wired to a constant would pass a
    // name check and fail here.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x0D, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal, { .want = 8 });
    const generate::Candidate* rr = first_rr(cs);
    REQUIRE(rr != nullptr);
    REQUIRE(rr->anchor_site == 0x120);          // the instruction, not the global
    REQUIRE(rr->anchor_site != kRrGlobal);
}

TEST_CASE("two anchors on one instruction are visible as one site",
          "[generate][integration]") {
    // The consumer-facing point of anchor_site. Nothing here stops a caller
    // holding two candidates cut from a single reference site -- generate no
    // longer emits such a pair, but hand-written patterns do, and that is
    // exactly what was once mistaken for a two-witness consensus.
    //
    // With the site reported, "how many distinct anchors do I have" is a set
    // size rather than a count, and the two cases separate.
    std::vector<uint8_t> bytes(kRrSize, 0xCC);
    put_rip_insn(bytes, 0x120, { 0x48, 0x8B }, 0x0D, kRrGlobal, {});
    put_rip_insn(bytes, 0x200, { 0x48, 0x8D }, 0x0D, kRrGlobal, {});
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    auto cs = generate::candidates(img, kRrGlobal, { .want = 8 });
    std::set<uint64_t> sites;
    size_t rr = 0;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::RipRef) {
            ++rr;
            sites.insert(c.anchor_site);
        }
    REQUIRE(rr == 2);
    REQUIRE(sites.size() == 2);                  // two instructions, two anchors
    REQUIRE(sites.count(0x120) == 1);
    REQUIRE(sites.count(0x200) == 1);
}

TEST_CASE("all four strategies can appear for one target", "[generate][integration]") {
    // DESIGN_generate.md's claim, made checkable. Each block is an addition to
    // the same budget, not a fallback for the one before it -- a fallback
    // chain would emit Xref and stop.
    auto bytes = make_all_four_image();
    generate::Image img{ bytes, kAllFourCode, kAllFourRodata, kAllFourFuncs };

    generate::Options o;
    o.want = 4;
    auto cs = generate::candidates(img, 0x100, o);
    REQUIRE(cs.size() == 4);

    std::vector<generate::Strategy> got;
    for (const auto& c : cs)
        got.push_back(c.strategy);
    // Emitter order is part of the contract: dedup keeps the FIRST of a
    // colliding triple, so the order is what makes the output reproducible.
    REQUIRE(got == std::vector<generate::Strategy>{ generate::Strategy::Xref,
                                                    generate::Strategy::Body,
                                                    generate::Strategy::StringAnchor,
                                                    generate::Strategy::RipRef });

    // Every one of them resolves to the target -- via the save slot where it
    // captures, via match-minus-delta where it does not.
    for (const auto& c : cs)
        REQUIRE(generate::detail::resolves_uniquely(bytes, c, 0x100));
}

TEST_CASE("want bounds the total, not the per-strategy count", "[generate][integration]") {
    // Four strategies each have something to say about this target, so a cap
    // applied per strategy rather than to the set would let the total run past
    // `want` -- while still looking correct from any single strategy's tests.
    auto bytes = make_all_four_image();
    generate::Image img{ bytes, kAllFourCode, kAllFourRodata, kAllFourFuncs };

    generate::Options o;
    for (int want : { 1, 2, 3, 4 }) {
        o.want = want;
        auto cs = generate::candidates(img, 0x100, o);
        REQUIRE((int)cs.size() == want);
    }

    // And the budget is a ceiling, not a quota: asking for more than the image
    // affords yields what it affords.
    o.want = 8;
    REQUIRE(generate::candidates(img, 0x100, o).size() == 4);
}

TEST_CASE("max_len is respected across every strategy", "[generate][integration]") {
    // Each strategy budgets max_len the way its own comment says: Xref spends
    // it on the tail alone (the E8 is extra), Body on its window, and
    // StringAnchor and RipRef on the WHOLE pattern (the seven lea bytes, or
    // the three opcode bytes, come out of it first). Asserted at two
    // different budgets so it is the option being tracked, not the fixture.
    //
    // RipRef used to be the exception here -- max_len was documented as inert
    // for it, because it emitted no tail at all. It emits one now, so the
    // budget binds, and `literals == max_len` is the same whole-pattern rule
    // StringAnchor follows.
    auto bytes = make_all_four_image();
    generate::Image img{ bytes, kAllFourCode, kAllFourRodata, kAllFourFuncs };

    for (size_t max_len : { (size_t)12, (size_t)20 }) {
        generate::Options o;
        o.want = 4;
        o.max_len = max_len;
        o.prefer_short = false;   // max_len is the ceiling under test here
        auto cs = generate::candidates(img, 0x100, o);
        REQUIRE(cs.size() == 4);

        REQUIRE(first_of(cs, generate::Strategy::Xref)->literals == max_len + 1);
        REQUIRE(first_of(cs, generate::Strategy::Body)->literals == max_len);
        REQUIRE(first_of(cs, generate::Strategy::StringAnchor)->literals == 3 + (max_len - 7));
        REQUIRE(first_of(cs, generate::Strategy::RipRef)->literals == max_len);
    }
}

TEST_CASE("identical patterns from different call sites appear once",
          "[generate][integration][dedup]") {
    // Three sites, one tail. One resolving triple, so one candidate -- and the
    // budget it does not spend is left for a genuinely different anchor.
    const std::vector<uint8_t> tail{ 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
    auto bytes = make_xref_image(0x100, { 0x200, 0x300, 0x400 }, tail);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o;
    o.want = 4;
    o.prefer_short = false;
    auto cs = generate::candidates(img, 0x100, o);

    size_t xrefs = 0;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::Xref)
            ++xrefs;
    REQUIRE(xrefs == 1);
    REQUIRE(generate::callers_of(img, 0x100).size() == 3);   // all three sites are really there
}

TEST_CASE("dedup keys on the resolving triple, not on the pattern text alone",
          "[generate][integration][dedup]") {
    // Two leas in the target's own function, loading two different strings and
    // each followed by the SAME bytes. The two patterns are textually
    // identical; their anchor_deltas are not -- 0x10 and 0x40 -- so they
    // resolve to DIFFERENT addresses. Collapsing on the pattern string alone
    // throws one anchor away and keeps one whose delta may name the wrong
    // place. Only the whole triple is a safe key.
    //
    // prefer_short is off deliberately: shortening would drive the two tails
    // apart in the course of reaching uniqueness, and the case being pinned
    // here is precisely the one where the TEXT collides.
    std::vector<uint8_t> bytes(kSaSize, 0xCC);
    put_str(bytes, 0x1000, "FIRST_STRING_TEXT");
    put_str(bytes, 0x1100, "SECOND_STRING_TEXT");
    put_lea(bytes, 0x110, 0x1000);
    put_lea(bytes, 0x140, 0x1100);
    const std::vector<uint8_t> shared{ 0x4C, 0x8B, 0xD0, 0x48, 0x85 };
    put_bytes(bytes, 0x117, shared);
    put_bytes(bytes, 0x147, shared);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x180 } };
    generate::Image img{ bytes, code, rodata, funcs };

    generate::Options o;
    o.want = 8;
    o.max_len = 12;             // the seven lea bytes plus the five shared ones
    o.prefer_short = false;
    auto cs = generate::candidates(img, 0x100, o);

    std::vector<const generate::Candidate*> sa;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::StringAnchor)
            sa.push_back(&c);
    REQUIRE(sa.size() == 2);
    REQUIRE(sa[0]->pattern == sa[1]->pattern);      // identical text ...
    REQUIRE(sa[0]->save_index == sa[1]->save_index);
    REQUIRE(sa[0]->anchor_delta == 0x10);           // ... resolving to different places
    REQUIRE(sa[1]->anchor_delta == 0x40);
}

TEST_CASE("prefer_short emits the SHORTEST unique run, not the longest",
          "[generate][integration][prefer_short]") {
    // The distinctive run appears TWICE, differing only from its fifth byte
    // on, so uniqueness needs exactly five bytes: four is one short and
    // sixteen is fourteen too many. That pins the emitted length between both
    // failure modes -- "return the full window" and "return one byte".
    std::vector<uint8_t> bytes(0x1000, 0x90);
    put_bytes(bytes, 0x400, { 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44 });
    put_bytes(bytes, 0x800, { 0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0x66, 0x77, 0x88 });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    // The fixture's own claim, checked rather than assumed: four bytes match
    // twice, five match once. Monotone in the run's length, which is what
    // makes bisecting for the smallest valid at all.
    REQUIRE(hit_count(bytes, "DE AD BE EF") == 2);
    REQUIRE(hit_count(bytes, "DE AD BE EF 11") == 1);

    generate::Options o;
    o.max_len = 16;
    auto cs = generate::candidates(img, 0x400, o);
    const auto* body = first_of(cs, generate::Strategy::Body);
    REQUIRE(body != nullptr);
    REQUIRE(body->pattern == "DE AD BE EF 11");
    REQUIRE(body->literals == 5);
    REQUIRE(body->anchor_delta == 0);
    REQUIRE(generate::detail::resolves_uniquely(bytes, *body, 0x400));

    // The same fixture with the option off keeps the whole window -- so this
    // is prefer_short doing the shortening, not the window happening to be
    // five bytes long.
    o.prefer_short = false;
    const auto full = generate::candidates(img, 0x400, o);
    const auto* long_body = first_of(full, generate::Strategy::Body);
    REQUIRE(long_body != nullptr);
    REQUIRE(long_body->literals == 16);
    REQUIRE(long_body->pattern.rfind("DE AD BE EF 11 22 33 44", 0) == 0);
}

TEST_CASE("prefer_short shortens an Xref tail without disturbing the capture",
          "[generate][integration][prefer_short]") {
    // Two call sites whose tails share their first FIVE bytes, so five bytes
    // of tail are not enough to tell them apart and six are. The `'` capture
    // is in front of the tail and is untouched by any of this.
    //
    // The shared prefix is five bytes rather than one so that the answer is
    // set by uniqueness and not by detail::kMinLiteralRun: a run that becomes
    // unique at one or two bytes is emitted at the floor instead, which is a
    // real rule (see the floor test below) and would make this test about the
    // wrong thing.
    auto bytes = make_xref_image_varied(0x100,
        { { 0x200, { 0xAA, 0xBB, 0x11, 0x22, 0x33, 0x44 } },
          { 0x300, { 0xAA, 0xBB, 0x11, 0x22, 0x33, 0x55 } } });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(hit_count(bytes, "E8 $ { ' } AA BB 11 22 33", 1) == 2);
    REQUIRE(hit_count(bytes, "E8 $ { ' } AA BB 11 22 33 44", 1) == 1);

    auto cs = generate::candidates(img, 0x100);
    const auto* x = first_of(cs, generate::Strategy::Xref);
    REQUIRE(x != nullptr);
    REQUIRE(x->pattern == "E8 $ { ' } AA BB 11 22 33 44");
    REQUIRE(x->literals == 7);                 // the E8 plus six tail bytes
    REQUIRE(captured(bytes, x->pattern) == 0x100);
}

TEST_CASE("prefer_short never shortens a run a later atom depends on",
          "[generate][integration][prefer_short]") {
    // StringAnchor's depth-1 gap is NOT a trailing run: the `E8 $ { ' }`
    // behind it is what fills the save slot. Shortening it would be legal by
    // the uniqueness test alone -- the shorter head really is unique here --
    // and would produce a pattern that reaches no `E8` and captures nothing.
    auto bytes = make_depth1_image(0x21A);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> rodata{ { kSaRodataBegin, kSaRodataEnd } };
    std::vector<generate::Range> funcs{ { 0x100, 0x140 }, { 0x200, 0x280 } };
    generate::Image img{ bytes, code, rodata, funcs };

    auto cs = generate::candidates(img, 0x100);   // prefer_short on, by default
    const auto* c = first_sa(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->pattern == "48 8D 0D ? ? ? ? 4C 8B D0 E8 $ { ' }");
    REQUIRE(c->literals == 3 + 3 + 1);
    REQUIRE(captured(bytes, c->pattern) == 0x100);

    // The temptation, and what it costs. One byte of gap IS unique on its own
    // -- so a uniqueness-only rule would happily stop there ...
    REQUIRE(hit_count(bytes, "48 8D 0D ? ? ? ? 4C") == 1);
    // ... and the pattern that results reaches no call at all.
    REQUIRE(captured(bytes, "48 8D 0D ? ? ? ? 4C E8 $ { ' }") == std::nullopt);
}

TEST_CASE("verified oversamples so `want` counts anchors that work, not anchors tried",
          "[generate][integration][verified]") {
    // Four call sites in A, emitted in address order. Only the LAST one's tail
    // survives into B; the first three differ there and are rejected. Asking
    // candidates() for exactly `want` would therefore hand verified() nothing
    // but the first candidate -- one attempt, zero anchors -- and the caller
    // would be told this target has no durable pattern when it has one.
    auto ba = make_xref_image_varied(0x100,
        { { 0x200, { 0x11, 0x11, 0x11, 0x11 } },
          { 0x300, { 0x22, 0x22, 0x22, 0x22 } },
          { 0x400, { 0x33, 0x33, 0x33, 0x33 } },
          { 0x500, { 0x44, 0x44, 0x44, 0x44 } } });
    auto bb = make_xref_image_varied(0x180,
        { { 0x600, { 0x55, 0x55, 0x55, 0x55 } },
          { 0x700, { 0x66, 0x66, 0x66, 0x66 } },
          { 0x800, { 0x77, 0x77, 0x77, 0x77 } },
          { 0x900, { 0x44, 0x44, 0x44, 0x44 } } });
    // `code` starts at 0x200, so it covers every call site and NEITHER
    // target. That keeps Body out of this fixture entirely, which matters
    // now that the budget is spent round-robin: with Body emitting, the
    // oversampled set would be Xref, Body, Xref, Xref and the fourth call
    // site -- the only one that survives into B -- would fall outside it.
    // This test's subject is the oversample, so the fixture is narrowed to
    // one strategy rather than the assertion being loosened.
    std::vector<generate::Range> code{ { 0x200, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    generate::Options o;
    o.want = 1;
    o.prefer_short = false;   // the whole tail, so the differing bytes stay in

    // The fixture is only meaningful if the surviving candidate is NOT the
    // first one emitted: candidates() caps at `want`, so with no oversample
    // verified() would never see it.
    generate::Options probe = o;
    probe.want = 4;
    auto cs = generate::candidates(a, 0x100, probe);
    REQUIRE(cs.size() == 4);
    REQUIRE_FALSE(generate::detail::resolves_uniquely(bb, cs[0], 0x180));
    REQUIRE_FALSE(generate::detail::resolves_uniquely(bb, cs[1], 0x180));
    REQUIRE_FALSE(generate::detail::resolves_uniquely(bb, cs[2], 0x180));
    REQUIRE(generate::detail::resolves_uniquely(bb, cs[3], 0x180));

    auto v = generate::verified(a, 0x100, b, 0x180, o);
    REQUIRE(v.size() == 1);                       // `want`, not zero
    REQUIRE(v[0].strategy == generate::Strategy::Xref);
    REQUIRE(v[0].pattern == cs[3].pattern);       // and it is the fourth candidate
}

TEST_CASE("verified still returns at most `want`", "[generate][integration][verified]") {
    // The oversample is an input to the search, not to the answer: verified()
    // stops at `want` survivors however many candidates it had to try.
    //
    // TWO GENUINELY DIFFERENT BUILDS. This used to pass one image twice,
    // which made every single-image candidate pass and so tested the cap
    // against a set that had never been verified at all. Build B is the same
    // logical code at a different address, with its string in a different
    // rodata slot -- so the four anchors here really did survive two
    // compilations, which is the only thing that makes a count of them mean
    // anything.
    auto ba = make_all_four_image();
    auto bb = make_all_four_image(0x400, 0x1100, 0x510, 0x610);
    generate::Image a{ ba, kAllFourCode, kAllFourRodata, kAllFourFuncs };
    generate::Image b{ bb, kAllFourCode, kAllFourRodata, kAllFourFuncsB };

    // The fixture's own claim, checked: all four strategies survive here, so
    // the cap below is capping a set that is genuinely larger than `want`.
    generate::Options all;
    all.want = 8;
    REQUIRE(generate::verified(a, 0x100, b, 0x400, all).size() == 4);

    generate::Options o;
    o.want = 2;
    auto v = generate::verified(a, 0x100, b, 0x400, o);
    REQUIRE(v.size() == 2);

    o.want = 4;
    REQUIRE(generate::verified(a, 0x100, b, 0x400, o).size() == 4);
}

// ---------------------------------------------------------------------------
// The review fixes: a round-robin budget, RipRef's literal context, the floor
// on a trailing run, order-independent `funcs`, and verified()'s refusal to
// treat one image as two builds.

TEST_CASE("the anchor budget is spent round-robin, not in strategy order",
          "[generate][integration][roundrobin]") {
    // TWENTY call sites, and one target whose own bytes are distinctive. That
    // is more than `want` (4) and more than verified()'s widened `want`
    // (4 * kVerifyOversample = 16), so Xref alone can fill either budget --
    // which is what it used to do. Sequential fill returns four Xrefs from
    // this fixture and reports the target as carrying four independent
    // anchors when it carries one shape sampled four times; the 72% -> 90%
    // figure is about anchors that fail INDEPENDENTLY, and twenty tails
    // harvested from one build's call sites fail together.
    //
    // The measured shape of the real problem is ~768 call sites per target,
    // so this is the normal case and not a corner.
    std::vector<std::pair<size_t, std::vector<uint8_t>>> sites_a, sites_b;
    for (int i = 0; i < 20; ++i) {
        // Distinct first byte per site, so the twenty tails are twenty
        // triples rather than one deduplicated one.
        const std::vector<uint8_t> tail{ (uint8_t)(0xA0 + i), 0x8B, 0xD0, 0x48, 0x85, 0xC0 };
        sites_a.push_back({ (size_t)(0x200 + i * 0x20), tail });
        sites_b.push_back({ (size_t)(0x600 + i * 0x20), tail });
    }
    auto ba = make_xref_image_varied(0x100, sites_a);
    auto bb = make_xref_image_varied(0x180, sites_b);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    // The fixture's own claims, checked rather than assumed: twenty callers,
    // and a Body anchor that really is available.
    REQUIRE(generate::callers_of(a, 0x100).size() == 20);
    REQUIRE(hit_count(ba, "48 89 CC CC") == 1);

    generate::Options o;
    o.want = 4;
    auto cs = generate::candidates(a, 0x100, o);
    REQUIRE(cs.size() == 4);

    std::vector<generate::Strategy> got;
    for (const auto& c : cs)
        got.push_back(c.strategy);
    // One from each non-empty bucket per round, in the fixed strategy order.
    // Two buckets have anything to say here, so the second slot goes to Body
    // and the rest of the budget returns to Xref.
    REQUIRE(got == std::vector<generate::Strategy>{ generate::Strategy::Xref,
                                                    generate::Strategy::Body,
                                                    generate::Strategy::Xref,
                                                    generate::Strategy::Xref });

    // The property that actually matters, stated as a property: more than one
    // SHAPE of anchor is present. Under a sequential fill this set is
    // { Xref } and the assertion fails.
    std::set<generate::Strategy> shapes(got.begin(), got.end());
    REQUIRE(shapes.size() >= 2);

    // And it holds through verified(), where the oversample widens the same
    // budget rather than escaping it: 20 > 16, so a sequential fill never
    // reaches Body there either.
    auto v = generate::verified(a, 0x100, b, 0x180, o);
    REQUIRE(v.size() == 4);
    std::set<generate::Strategy> verified_shapes;
    for (const auto& c : v)
        verified_shapes.insert(c.strategy);
    REQUIRE(verified_shapes.size() >= 2);
    REQUIRE(verified_shapes.count(generate::Strategy::Body) == 1);
}

TEST_CASE("a strategy's bucket is capped at `want`, so a well-called target bounds its work",
          "[generate][integration][roundrobin]") {
    // The other half of the round-robin rule. Twenty callers, `want` of 2:
    // Xref must build at most two candidates, not twenty. Each one costs
    // ~7 full-image scans to shorten, so an uncapped bucket is 768 * 7 scans
    // of a 137MB image for one target on the real thing.
    std::vector<std::pair<size_t, std::vector<uint8_t>>> sites;
    for (int i = 0; i < 20; ++i)
        sites.push_back({ (size_t)(0x200 + i * 0x20),
                          { (uint8_t)(0xA0 + i), 0x8B, 0xD0, 0x48, 0x85, 0xC0 } });
    auto bytes = make_xref_image_varied(0x100, sites);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    generate::Options o;
    o.want = 2;
    auto cs = generate::candidates(img, 0x100, o);
    REQUIRE(cs.size() == 2);
    // Both buckets are non-empty, so a round-robin budget of two spends one
    // on each -- the emitted Xref count is 1, well under the twenty available.
    size_t xrefs = 0;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::Xref)
            ++xrefs;
    REQUIRE(xrefs == 1);
    REQUIRE(cs[1].strategy == generate::Strategy::Body);
}

TEST_CASE("RipRef carries enough context to be unique among instructions sharing its opcode",
          "[generate][ripref][integration]") {
    // WHY EVERY OTHER RipRef FIXTURE HERE MISSES THIS. They fill with 0xCC,
    // where the opcode occurs exactly once and `48 8B 0D $ { ' }` is unique
    // by accident of the fixture. A real image has hundreds of
    // `mov r64, [rip+X]`, and the context-free form is then an INSTRUCTION
    // SELECTOR: many hits, resolves_uniquely rejects it, verified() returns
    // nothing -- and since Xref, Body and StringAnchor all anchor on code and
    // none can name a global, the target has no working strategy at all.
    //
    // Six decoys sharing the exact opcode and modrm bytes, each naming a
    // different global, plus the real site with distinctive bytes behind it.
    auto build = [](uint64_t global) {
        std::vector<uint8_t> b(0x2000, 0xCC);
        for (int i = 0; i < 6; ++i)
            put_rip_insn(b, 0x200 + i * 0x20, { 0x48, 0x8B }, 0x0D, 0x1800, {});
        put_rip_insn(b, 0x400, { 0x48, 0x8B }, 0x0D, global, {});
        put_bytes(b, 0x407, { 0x4C, 0x8B, 0xD0, 0x48, 0x85, 0xC0 });
        return b;
    };
    auto ba = build(0x1A00), bb = build(0x1B00);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    // The fixture's own claim: the context-free form is AMBIGUOUS here, and
    // by how much. The global sits outside `code` and is never called, so
    // RipRef is the only strategy with anything to say -- as it is for any
    // real global.
    REQUIRE(hit_count(ba, "48 8B 0D $ { ' }", 1) == 7);

    auto cs = generate::candidates(a, 0x1A00);
    REQUIRE(cs.size() == 1);
    const auto* c = first_rr(cs);
    REQUIRE(c != nullptr);
    REQUIRE(c->pattern == "48 8B 0D $ { ' } 4C 8B D0 48");
    REQUIRE(hit_count(ba, c->pattern, 1) == 1);      // the tail resolves it
    REQUIRE(captured(ba, c->pattern) == 0x1A00);

    // Two builds, differing only in where the linker put the global.
    auto v = generate::verified(a, 0x1A00, b, 0x1B00);
    REQUIRE(count_rr(v) == 1);

    // And the same candidate stripped of its tail resolves nowhere: seven
    // hits, so resolves_uniquely rejects it and verified() would be empty.
    generate::Candidate bare = *first_rr(v);
    bare.pattern = "48 8B 0D $ { ' }";
    REQUIRE_FALSE(generate::detail::resolves_uniquely(ba, bare, 0x1A00));
}

TEST_CASE("a trailing literal run never shortens below the floor",
          "[generate][integration][prefer_short]") {
    // Uniqueness alone stops at ONE byte: 0xDE occurs exactly once in a
    // 0x90-filled image, so "DE" is already unique and the bisection has no
    // reason of its own to keep going. A one-byte pattern is the worst case
    // twice over -- it is evidence of nothing about the surrounding code, and
    // it makes select_seed's seed a byte value, which hits everywhere.
    std::vector<uint8_t> bytes(0x1000, 0x90);
    put_bytes(bytes, 0x400, { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE });
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    REQUIRE(hit_count(bytes, "DE") == 1);            // the fixture's own claim

    generate::Options o;
    o.max_len = 32;
    auto cs = generate::candidates(img, 0x400, o);
    const auto* body = first_of(cs, generate::Strategy::Body);
    REQUIRE(body != nullptr);
    REQUIRE(body->literals == generate::detail::kMinLiteralRun);
    REQUIRE(body->pattern == "DE AD BE EF");
    REQUIRE(body->anchor_delta == 0);
    REQUIRE(generate::detail::resolves_uniquely(bytes, *body, 0x400));
}

TEST_CASE("enclosing_func and clamp_to_func do not depend on the order of funcs",
          "[generate][funcs]") {
    // `funcs` is caller-supplied and this header states no sortedness or
    // disjointness precondition on it. A first-match rule therefore let the
    // caller's LISTING ORDER decide StringAnchor's depth-0-vs-depth-1 choice
    // and every clamped tail length. The tightest covering range wins
    // instead, which is a total order and so order-independent.
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    std::vector<generate::Range> wide_first{ { 0x200, 0x300 }, { 0x208, 0x220 } };
    std::vector<generate::Range> tight_first{ { 0x208, 0x220 }, { 0x200, 0x300 } };
    generate::Image a{ bytes, code, {}, wide_first };
    generate::Image b{ bytes, code, {}, tight_first };

    REQUIRE(generate::enclosing_func(a, 0x210) != nullptr);
    REQUIRE(generate::enclosing_func(a, 0x210)->end == 0x220);
    REQUIRE(generate::enclosing_func(b, 0x210)->end == 0x220);
    REQUIRE(generate::clamp_to_func(a, 0x210, 64) == 0x10);
    REQUIRE(generate::clamp_to_func(b, 0x210, 64) == 0x10);

    // Uncovered stays distinguishable from covered-by-a-range-beginning-at-0,
    // and stays a no-op for the clamp.
    REQUIRE(generate::enclosing_func(a, 0x400) == nullptr);
    REQUIRE(generate::clamp_to_func(a, 0x400, 64) == 64);
}

TEST_CASE("verified refuses to treat one image as two builds", "[generate][verified]") {
    // The premise of this header is that the second compilation is
    // INDEPENDENT EVIDENCE. Handed the same image twice, verified() would
    // check every candidate against the image it was generated from and pass
    // all of them -- reproducing the 33% state of the art while reporting the
    // 72% figure.
    auto ba = make_all_four_image();
    auto bb = make_all_four_image(0x400, 0x1100, 0x510, 0x610);
    generate::Image a{ ba, kAllFourCode, kAllFourRodata, kAllFourFuncs };
    generate::Image b{ bb, kAllFourCode, kAllFourRodata, kAllFourFuncsB };

    generate::Options o;
    o.want = 8;

    // Against a real second build, four anchors survive.
    REQUIRE(generate::verified(a, 0x100, b, 0x400, o).size() == 4);

    // Every candidate would ALSO have "verified" against its own image --
    // which is precisely the claim being refused, not a weaker version of it.
    auto cs = generate::candidates(a, 0x100, o);
    REQUIRE(cs.size() == 4);
    for (const auto& c : cs)
        REQUIRE(generate::detail::resolves_uniquely(ba, c, 0x100));

    REQUIRE(generate::verified(a, 0x100, a, 0x100, o).empty());
}

TEST_CASE("prefer_short governs tail LENGTH only; deep_anchor governs where Body anchors",
          "[generate][body][prefer_short]") {
    // These were one flag. Turning `prefer_short` off -- an option documented
    // as "shortest sufficient context, not longest" -- also silently
    // downgraded Body to delta 0, which nothing said and no caller asking
    // about length could have wanted.
    //
    // The fixture makes the cost visible: the entry bytes are REPEATED
    // elsewhere, so delta 0 is not distinctive, and the distinctive bytes sit
    // at +4. max_len is 4, so each window is exactly one of the two.
    std::vector<uint8_t> bytes(0x1000, 0x90);
    put_bytes(bytes, 0x400, { 0x48, 0x89, 0x5C, 0x24 });   // the entry, and ...
    put_bytes(bytes, 0x404, { 0xDE, 0xAD, 0xBE, 0xEF });   // ... what is distinctive
    put_bytes(bytes, 0x800, { 0x48, 0x89, 0x5C, 0x24 });   // the entry bytes again
    std::vector<generate::Range> code{ { 0, 0x1000 } };
    generate::Image img{ bytes, code, {}, {} };

    // The fixture's own claims.
    REQUIRE(hit_count(bytes, "48 89 5C 24") == 2);
    REQUIRE(hit_count(bytes, "DE AD BE EF") == 1);

    generate::Options o;
    o.max_len = 4;

    // prefer_short OFF still walks: it is not an option about anchoring.
    o.prefer_short = false;
    auto off = generate::candidates(img, 0x400, o);
    const auto* b_off = first_of(off, generate::Strategy::Body);
    REQUIRE(b_off != nullptr);
    REQUIRE(b_off->anchor_delta == 4);
    REQUIRE(b_off->pattern == "DE AD BE EF");
    REQUIRE(generate::detail::resolves_uniquely(bytes, *b_off, 0x400));

    // prefer_short ON gives the same anchor. The two windows are already at
    // the floor, so there is nothing for it to shorten -- which is the point:
    // the option that changed the anchor was never about length.
    o.prefer_short = true;
    auto on = generate::candidates(img, 0x400, o);
    const auto* b_on = first_of(on, generate::Strategy::Body);
    REQUIRE(b_on != nullptr);
    REQUIRE(b_on->anchor_delta == 4);
    REQUIRE(b_on->pattern == b_off->pattern);

    // deep_anchor is the flag that decides it, and turning it off gives the
    // delta-0 fallback: emitted, undistinctive, and rejected by verification.
    o.deep_anchor = false;
    auto shallow = generate::candidates(img, 0x400, o);
    const auto* b_shallow = first_of(shallow, generate::Strategy::Body);
    REQUIRE(b_shallow != nullptr);
    REQUIRE(b_shallow->anchor_delta == 0);
    REQUIRE(b_shallow->pattern == "48 89 5C 24");
    REQUIRE_FALSE(generate::detail::resolves_uniquely(bytes, *b_shallow, 0x400));
}

// --- residual findings from the whole-branch re-review ---------------------

TEST_CASE("verified's oversample survives the round-robin at want = 1",
          "[generate][verified][oversample]") {
    // The oversample factor reasons per strategy ("roughly one candidate in
    // three clears both images"), but candidates() spends its budget
    // round-robin, so a request for N is SHARED across the live strategies.
    // Ask for want*4 with two live buckets and each gets only ~want*2 attempts.
    //
    // Here only the FOURTH call site's tail survives into B, and a Body
    // candidate is eligible in A but fails in B. At want=1 the widened request
    // must still be deep enough to reach that fourth Xref; scaled by the
    // oversample alone it stopped at `Xref Body Xref Xref` and returned 0.
    auto build = [](bool second) {
        std::vector<uint8_t> b(0x2000, 0xCC);
        const uint64_t target = 0x1000;
        // A distinctive body. EVERY byte moves in build B, not just the tail:
        // prefer_short shortens Body to the kMinLiteralRun floor, so leaving
        // the first four bytes alone let the shortened pattern match both
        // builds and Body survived -- which made this fixture assert the
        // opposite of what it is for. Body must be emitted from A and then
        // legitimately FAIL in B, so that it consumes a round-robin slot
        // without being the answer.
        const uint8_t body[] = { 0x55, 0x48, 0x89, 0xE5, 0xD1, 0xD2, 0xD3, 0xD4 };
        for (size_t i = 0; i < sizeof(body); ++i)
            b[target + i] = (uint8_t)(body[i] + (second ? 0x10 : 0));
        for (int k = 0; k < 4; ++k) {
            const uint64_t site = 0x400 + (uint64_t)k * 0x100;
            b[site] = 0xE8;
            const int32_t rel = (int32_t)((int64_t)target - (int64_t)(site + 5));
            for (int j = 0; j < 4; ++j)
                b[site + 1 + j] = (uint8_t)((uint32_t)rel >> (8 * j));
            // Distinct tails so each Xref pattern is unique in its own image.
            // Sites 0..2 differ between builds; site 3 is identical in both,
            // so it is the only candidate that can survive.
            for (int j = 0; j < 8; ++j) {
                uint8_t v = (uint8_t)(0xA0 + k * 0x10 + j);
                if (second && k < 3)
                    v ^= 0xFF;
                b[site + 5 + j] = v;
            }
        }
        return b;
    };
    const std::vector<uint8_t> ba = build(false), bb = build(true);
    std::vector<generate::Range> code{ { 0, 0x2000 } };
    generate::Image a{ ba, code, {}, {} }, b{ bb, code, {}, {} };

    generate::Options o;
    o.want = 1;
    auto v = generate::verified(a, 0x1000, b, 0x1000, o);
    REQUIRE(v.size() == 1);
    REQUIRE(v[0].strategy == generate::Strategy::Xref);

    // The fixture is only meaningful if a second strategy really does take a
    // slot -- otherwise this would pass with the widening removed.
    generate::Options wide_probe;
    wide_probe.want = 16;
    auto cs = generate::candidates(a, 0x1000, wide_probe);
    int bodies = 0;
    for (const auto& c : cs)
        if (c.strategy == generate::Strategy::Body)
            ++bodies;
    REQUIRE(bodies == 1);
}

TEST_CASE("RipRef emits nothing when there is no room for context",
          "[generate][ripref]") {
    // With max_len at or below the head, the tail is empty and the pattern
    // degenerates to the bare `48 8B 0D $ { ' }` selector -- three literal
    // bytes and a capture, the exact shape that cannot be unique on a real
    // image. Skipping beats emitting something verified() must discard.
    std::vector<uint8_t> bytes(0x800, 0xCC);
    const uint64_t site = 0x100, global = 0x400;
    bytes[site] = 0x48; bytes[site + 1] = 0x8B; bytes[site + 2] = 0x0D;
    const int32_t disp = (int32_t)((int64_t)global - (int64_t)(site + 7));
    for (int j = 0; j < 4; ++j)
        bytes[site + 3 + j] = (uint8_t)((uint32_t)disp >> (8 * j));
    std::vector<generate::Range> code{ { 0, 0x800 } };
    generate::Image img{ bytes, code, {}, {} };

    auto count_rr = [](const std::vector<generate::Candidate>& cs) {
        int n = 0;
        for (const auto& c : cs)
            if (c.strategy == generate::Strategy::RipRef)
                ++n;
        return n;
    };

    generate::Options tight;
    tight.max_len = 3;                       // exactly the head; no room for a tail
    REQUIRE(count_rr(generate::candidates(img, global, tight)) == 0);

    // Positive control: with room, RipRef does fire on this same fixture, so
    // the assertion above is about the budget and not about the site being
    // unrecognised.
    generate::Options roomy;
    roomy.max_len = 32;
    REQUIRE(count_rr(generate::candidates(img, global, roomy)) == 1);
}

TEST_CASE("rip_lea_index agrees with rip_refs_to, target for target",
          "[generate][ripref][index]") {
    // StringAnchor stopped calling rip_refs_to() once per string -- that was
    // 71 minutes for one target on the real image -- and now looks up a
    // single-pass index instead. The two decoders are separate copies of the
    // same `48 8D` / `(modrm & 0xC7) == 0x05` / `site + 7 + disp32`
    // arithmetic, so nothing but this test stops them drifting apart, and a
    // drift would silently change which strings qualify.
    //
    // `code` ranges are deliberately supplied OUT of address order: the index
    // accumulates per target and must still return ascending, deduplicated
    // sites the way rip_refs_to does. Insertion order alone would not.
    std::vector<uint8_t> bytes(0x2000, 0xCC);
    const uint64_t targets[] = { 0x1400, 0x1420, 0x1440 };

    // Sites laid out so one target has two referencing leas and another has
    // none -- the size()==1 test StringAnchor makes is only meaningful if
    // both of those cases are represented.
    struct Site { uint64_t at; uint64_t to; };
    const Site sites[] = {
        { 0x0900, 0x1400 }, { 0x0100, 0x1400 },   // two, in the later range first
        { 0x0940, 0x1420 },                        // one
                                                   // 0x1440: none
    };
    for (const Site& s : sites) {
        bytes[s.at] = 0x48; bytes[s.at + 1] = 0x8D; bytes[s.at + 2] = 0x0D;
        const int32_t disp = (int32_t)((int64_t)s.to - (int64_t)(s.at + 7));
        for (int j = 0; j < 4; ++j)
            bytes[s.at + 3 + j] = (uint8_t)((uint32_t)disp >> (8 * j));
    }
    // Out of address order on purpose.
    std::vector<generate::Range> code{ { 0x0800, 0x1000 }, { 0x0000, 0x0800 } };
    generate::Image img{ bytes, code, {}, {} };

    std::unordered_set<uint64_t> wanted;
    for (uint64_t t : targets)
        wanted.insert(t);
    const auto index = generate::rip_lea_index(img, wanted);

    for (uint64_t t : targets) {
        const std::vector<uint64_t> scanned = generate::rip_refs_to(img, t);
        const auto it = index.find(t);
        const std::vector<uint64_t> indexed =
            it == index.end() ? std::vector<uint64_t>{} : it->second;
        INFO("target 0x" << std::hex << t);
        REQUIRE(indexed == scanned);
    }

    // The fixture is only meaningful if it actually exercises all three
    // cardinalities; otherwise the agreement above is trivial.
    REQUIRE(generate::rip_refs_to(img, 0x1400).size() == 2);
    REQUIRE(generate::rip_refs_to(img, 0x1420).size() == 1);
    REQUIRE(generate::rip_refs_to(img, 0x1440).empty());
    // Ascending despite the ranges being supplied in the other order.
    REQUIRE(index.at(0x1400) == std::vector<uint64_t>{ 0x0100, 0x0900 });
}

// --- structural tests -----------------------------------------------------
//
// Everything above is a hand-built fixture: at most 8KB, and filled with a
// single repeated byte. Both Criticals the whole-branch review found were
// invisible to all of them, and not because the tests were careless:
//
//   * StringAnchor scanned the whole image once per content-unique string. At
//     4KB that is free; on the 133MB image it was 71 minutes for ONE target.
//     No fixture here is large enough for the cost to exist.
//   * RipRef emitted `48 8B 0D $ { ' }` -- three literal bytes and a capture.
//     Against 0xCC filler the opcode occurs once and that is unique. Against
//     real code it has thousands of hits and verifies to nothing.
//
// Both are the same defect in the fixtures rather than in the tests: the
// synthetic image is kinder than any real one. Mutation testing cannot see it,
// because a mutation proves a test discriminates against the CODE, not that
// the fixture resembles the world. These tests encode the two properties a
// real image has that a hand-built one does not -- density, and scale.

namespace {

// An image with the statistical texture of compiled code rather than filler:
// every byte value present, so no short literal run is unique by luck, and
// deliberately many decoy instructions sharing each strategy's opcode.
//
// Deterministic: the same bytes on every platform and every run. A structural
// test that fails one time in twenty teaches people to re-run it.
struct CrowdedImage {
    std::vector<uint8_t> bytes;
    std::vector<generate::Range> code, rodata, funcs;
    uint64_t target = 0;      // a function, reachable by Xref and Body
    uint64_t global = 0;      // a datum, reachable only by RipRef
};

inline uint8_t crowd_byte(uint64_t& s) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return (uint8_t)(s >> 24);
}

inline void put_rel32(std::vector<uint8_t>& b, uint64_t at, uint64_t to, uint64_t end) {
    const int32_t rel = (int32_t)((int64_t)to - (int64_t)end);
    for (int j = 0; j < 4; ++j)
        b[at + j] = (uint8_t)((uint32_t)rel >> (8 * j));
}

// `variant` perturbs the decoys and the target's tail, standing in for a
// second independent compilation: same structure, different addresses and
// register allocation.
inline CrowdedImage make_crowded(unsigned variant, size_t decoys = 400) {
    CrowdedImage img;
    const size_t n = 0x20000;
    img.bytes.assign(n, 0);
    uint64_t s = 0x9E3779B97F4A7C15ull + variant;
    for (size_t i = 0; i < n; ++i)
        img.bytes[i] = crowd_byte(s);

    const uint64_t code_end = 0x18000;
    img.target = 0x1000 + variant * 0x40;   // moves between builds
    img.global = 0x19000;

    // Decoys: the same opcodes every strategy anchors on, pointing elsewhere.
    // This is what makes a three-byte selector ambiguous, which is the whole
    // point of the fixture.
    for (size_t d = 0; d < decoys; ++d) {
        const uint64_t at = 0x2000 + d * 0x30;
        if (at + 16 >= code_end)
            break;
        img.bytes[at + 0] = 0x48; img.bytes[at + 1] = 0x8D; img.bytes[at + 2] = 0x0D;
        put_rel32(img.bytes, at + 3, 0x19100 + d * 4, at + 7);      // lea to other data
        img.bytes[at + 8] = 0x48; img.bytes[at + 9] = 0x8B; img.bytes[at + 10] = 0x0D;
        put_rel32(img.bytes, at + 11, 0x19200 + d * 4, at + 15);    // mov from other data
        img.bytes[at + 16] = 0xE8;
        put_rel32(img.bytes, at + 17, 0x1500, at + 21);             // call elsewhere
    }

    // The target: a distinctive prologue, then bytes that differ per variant so
    // an over-long Body tail cannot survive both builds by accident.
    const uint8_t body[] = { 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
                             0x48, 0x83, 0xEC, 0x40 };
    for (size_t i = 0; i < sizeof body; ++i)
        img.bytes[img.target + i] = body[i];
    for (size_t i = 0; i < 24; ++i)
        img.bytes[img.target + sizeof body + i] = (uint8_t)(0x10 + i);

    // Callers of the target, each with its own tail.
    for (int k = 0; k < 6; ++k) {
        const uint64_t site = 0x10000 + (uint64_t)k * 0x80;
        img.bytes[site] = 0xE8;
        put_rel32(img.bytes, site + 1, img.target, site + 5);
        for (int j = 0; j < 12; ++j)
            img.bytes[site + 5 + j] = (uint8_t)(0xA0 + k * 0x10 + j);
    }

    // One instruction referencing the global, with distinctive context after
    // it -- the context RipRef needs and did not used to emit.
    const uint64_t rr = 0x14000;
    img.bytes[rr] = 0x48; img.bytes[rr + 1] = 0x8B; img.bytes[rr + 2] = 0x0D;
    put_rel32(img.bytes, rr + 3, img.global, rr + 7);
    const uint8_t tail[] = { 0x4C, 0x8B, 0xC1, 0x48, 0x8D, 0x54, 0x24, 0x20,
                             0x33, 0xC0, 0x41, 0xB8 };
    for (size_t i = 0; i < sizeof tail; ++i)
        img.bytes[rr + 7 + i] = tail[i];

    img.code = { { 0, code_end } };
    img.rodata = { { code_end, n } };
    img.funcs = { { img.target, img.target + 0x80 } };
    return img;
}

inline generate::Image view(const CrowdedImage& c) {
    return generate::Image{ c.bytes, c.code, c.rodata, c.funcs };
}

} // namespace

TEST_CASE("the crowded fixture is actually crowded", "[generate][structural]") {
    // Asserted, not assumed. If make_crowded ever stops producing a dense
    // image, every structural test below silently weakens to the sparse case
    // they exist to replace -- which is the exact failure they encode.
    const CrowdedImage c = make_crowded(0);
    const generate::Image img = view(c);

    // The opcodes each strategy anchors on must occur many times, so no
    // three-byte selector is unique by luck.
    auto count = [&](std::initializer_list<uint8_t> op) {
        size_t n = 0;
        const std::vector<uint8_t> pat(op);
        for (size_t i = 0; i + pat.size() <= c.bytes.size(); ++i)
            if (std::equal(pat.begin(), pat.end(), c.bytes.begin() + (long)i))
                ++n;
        return n;
    };
    REQUIRE(count({ 0x48, 0x8D, 0x0D }) > 100);   // StringAnchor's lea
    REQUIRE(count({ 0x48, 0x8B, 0x0D }) > 100);   // RipRef's mov
    REQUIRE(count({ 0xE8 }) > 100);               // Xref's call

    // And the filler must span the byte range, unlike a 0xCC fill.
    bool seen[256] = { false };
    for (uint8_t b : c.bytes)
        seen[b] = true;
    int distinct = 0;
    for (bool v : seen)
        distinct += v ? 1 : 0;
    REQUIRE(distinct == 256);

    REQUIRE(generate::callers_of(img, c.target).size() == 6);
}

TEST_CASE("verified() finds a function in a crowded image", "[generate][structural]") {
    const CrowdedImage a = make_crowded(0), b = make_crowded(1);
    generate::Options o;
    o.want = 4;
    const auto v = generate::verified(view(a), a.target, view(b), b.target, o);
    REQUIRE(!v.empty());

    // Every survivor must genuinely be unique in its own image -- that is what
    // verified() claims, and in a sparse fixture it is true for free.
    for (const auto& c : v) {
        auto comp = locate::compile(c.pattern);
        locate::prime(comp, a.bytes);
        INFO("pattern: " << c.pattern);
        REQUIRE(locate::find_all(a.bytes, comp, c.save_index, 2).size() == 1);
    }
}

TEST_CASE("verified() finds a GLOBAL in a crowded image", "[generate][structural]") {
    // The RipRef regression, as a property rather than a byte string. A global
    // is reachable by no other strategy: Xref, Body and StringAnchor all
    // anchor on code that calls or contains a function. So if RipRef's pattern
    // is too weak to be unique here, this returns nothing and globals have no
    // working strategy at all -- which was true until the tail was added.
    const CrowdedImage a = make_crowded(0), b = make_crowded(1);
    generate::Options o;
    o.want = 4;
    const auto v = generate::verified(view(a), a.global, view(b), b.global, o);
    REQUIRE(!v.empty());
    bool any_ripref = false;
    for (const auto& c : v)
        if (c.strategy == generate::Strategy::RipRef)
            any_ripref = true;
    REQUIRE(any_ripref);
}

TEST_CASE("a well-called target still yields more than one strategy",
          "[generate][structural]") {
    // The budget Critical, as a property. Every emitter shares one
    // `out.size() < want` gate, so with the budget spent in strategy order a
    // target with >= want callers got Xref and nothing else -- four anchors
    // that are four tails from ONE build, which fail together rather than
    // independently. The 72%->90% figure rests on the anchors being
    // INDEPENDENT, so this is the property that claim actually needs.
    //
    // The crowded fixture has 6 callers, which is more than the default want
    // of 4; that is what makes the starvation reachable here and unreachable
    // in a fixture with one call site.
    const CrowdedImage a = make_crowded(0), b = make_crowded(1);
    REQUIRE(generate::callers_of(view(a), a.target).size() > 4);

    generate::Options o;
    o.want = 4;
    const auto cs = generate::candidates(view(a), a.target, o);
    std::set<generate::Strategy> kinds;
    for (const auto& c : cs)
        kinds.insert(c.strategy);
    INFO("got " << cs.size() << " candidates of " << kinds.size() << " kind(s)");
    REQUIRE(kinds.size() >= 2);

    // And the budget is still honoured -- diversity must not come from
    // quietly emitting more than the caller asked for.
    REQUIRE(cs.size() <= (size_t)o.want);
}

TEST_CASE("candidates() cost does not grow with the string count",
          "[generate][structural]") {
    // The cost Critical, as a property. StringAnchor scanned the whole image
    // once per content-unique string: linear in the table, so 8x the strings
    // cost 8x the time. Measured on a 4MB image before the fix -- 250 strings
    // 131 ms, 500 261 ms, 1,000 504 ms, 2,000 1,071 ms -- and on the 133MB
    // image, where the table holds 85,232 content-unique strings, 71 minutes
    // for a SINGLE target.
    //
    // No fixture above can see this: they are 4-8KB, where 85,232 full scans
    // are free. Scale is a property of the input, not of the assertions, and
    // it is the one thing a hand-built fixture cannot fake cheaply.
    //
    // The bound is deliberately loose. Since the reverse index the work is one
    // pass regardless of the table size, so the honest ratio is ~1; the old
    // behaviour was ~8. Anything under 4 distinguishes them with a wide margin
    // and will not flake on a noisy runner.
    auto build = [](size_t k) {
        std::vector<uint8_t> b(4u << 20, 0x90);
        const uint64_t code_end = (4u << 20) / 2;
        for (int i = 0; i < 16; ++i)
            b[0x100 + i] = (uint8_t)(0x40 + i);
        uint64_t rod = code_end;
        for (size_t i = 0; i < k && rod + 16 < b.size(); ++i) {
            char buf[16];
            std::snprintf(buf, sizeof buf, "str_%08zu", i);
            for (size_t j = 0; j < 12; ++j)
                b[rod + j] = (uint8_t)buf[j];
            b[rod + 12] = 0x00;
            rod += 16;
        }
        return b;
    };

    auto best_ms = [](const std::vector<uint8_t>& bytes) {
        std::vector<generate::Range> code{ { 0, (4u << 20) / 2 } },
            rodata{ { (4u << 20) / 2, bytes.size() } };
        generate::Image img{ bytes, code, rodata, {} };
        generate::Options o;
        o.want = 4;
        double best = 1e18;
        for (int r = 0; r < 3; ++r) {
            const auto t0 = std::chrono::steady_clock::now();
            const auto cs = generate::candidates(img, 0x100, o);
            const auto t1 = std::chrono::steady_clock::now();
            (void)cs;
            best = (std::min)(best,
                std::chrono::duration<double, std::milli>(t1 - t0).count());
        }
        return best;
    };

    const std::vector<uint8_t> few = build(500), many = build(4000);

    // The fixture only means something if the string tables really differ by
    // the factor the ratio assumes.
    const size_t n_few = generate::strings(
        generate::Image{ few, {}, std::vector<generate::Range>{
            { (4u << 20) / 2, few.size() } }, {} }).size();
    const size_t n_many = generate::strings(
        generate::Image{ many, {}, std::vector<generate::Range>{
            { (4u << 20) / 2, many.size() } }, {} }).size();
    INFO("string tables: " << n_few << " vs " << n_many);
    REQUIRE(n_many >= n_few * 7);

    const double t_few = (std::max)(best_ms(few), 1.0);   // floor: divide-by-noise
    const double t_many = best_ms(many);
    INFO("8x the strings cost " << t_many / t_few << "x the time ("
         << t_few << "ms -> " << t_many << "ms)");
    REQUIRE(t_many < t_few * 4.0);
}

TEST_CASE("resolve_consensus groups anchors by the address they agree on",
          "[generate][consensus]") {
    // A single clean hit is not proof: measured across four real builds,
    // 5-13% of dual-build-verified patterns that matched EXACTLY ONCE in a
    // later build resolved to the WRONG function. Anchors agreeing on one
    // address were right 25 of 25. This pins the grouping that check needs.
    const CrowdedImage c = make_crowded(0);
    const generate::Image img = view(c);

    generate::Options o;
    o.want = 8;
    const auto cands = generate::candidates(img, c.target, o);
    REQUIRE(cands.size() >= 2);

    const auto groups = generate::resolve_consensus(c.bytes, cands);
    REQUIRE(!groups.empty());

    // The leader is the target, and it is a CONSENSUS -- more than one anchor
    // independently landed there.
    REQUIRE(groups[0].address == c.target);
    REQUIRE(groups[0].anchors.size() >= 2);

    // Ordering cannot be tested here: every anchor for this target resolves
    // to the target, so there is exactly ONE group and any order satisfies it.
    // Reversing the sort left this test green. See the disagreement test below.
    REQUIRE(groups.size() == 1);

    // Every reported anchor index is real, and no anchor is counted twice.
    std::set<size_t> seen;
    for (const auto& g : groups)
        for (size_t a : g.anchors) {
            REQUIRE(a < cands.size());
            REQUIRE(seen.insert(a).second);
        }
}

TEST_CASE("resolve_consensus drops anchors that are not unique in the new image",
          "[generate][consensus]") {
    // An anchor matching twice has said nothing, and must not be allowed to
    // vote -- otherwise ambiguity would inflate a consensus rather than being
    // excluded from it.
    std::vector<uint8_t> bytes(0x800, 0xCC);
    const uint8_t run[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    for (size_t k = 0; k < sizeof run; ++k) {
        bytes[0x100 + k] = run[k];
        bytes[0x400 + k] = run[k];   // the SAME bytes twice: not unique
    }
    generate::Candidate amb;
    amb.pattern = generate::hex_bytes(bytes.data() + 0x100, sizeof run);
    amb.save_index = 0;
    amb.anchor_delta = 0;
    amb.strategy = generate::Strategy::Body;

    const auto groups = generate::resolve_consensus(bytes, { amb });
    REQUIRE(groups.empty());

    // Positive control: made unique, the same anchor does vote.
    for (size_t k = 0; k < sizeof run; ++k)
        bytes[0x400 + k] = 0xCC;
    const auto ok = generate::resolve_consensus(bytes, { amb });
    REQUIRE(ok.size() == 1);
    REQUIRE(ok[0].address == 0x100);
}

TEST_CASE("resolve_consensus puts the most-agreed address first",
          "[generate][consensus]") {
    // Ordering is only observable when anchors DISAGREE. The crowded fixture
    // cannot show it -- every anchor there resolves to the target, so there is
    // one group and reversing the comparator changes nothing. This builds the
    // disagreement by hand: two anchors landing on one address, one on another.
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    const uint8_t a1[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const uint8_t a2[] = { 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCD };
    const uint8_t lone[] = { 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6 };
    for (size_t k = 0; k < 6; ++k) {
        bytes[0x200 + k] = a1[k];     // resolves to 0x200 - 0 = 0x200
        bytes[0x300 + k] = a2[k];     // delta 0x100 -> resolves to 0x200 too
        bytes[0x500 + k] = lone[k];   // resolves to 0x500, on its own
    }
    auto mk = [&](uint64_t at, int64_t delta) {
        generate::Candidate c;
        c.pattern = generate::hex_bytes(bytes.data() + at, 6);
        c.save_index = 0;
        c.anchor_delta = delta;
        c.strategy = generate::Strategy::Body;
        return c;
    };
    // Deliberately ordered with the LONE anchor first, so a stable sort that
    // does not reorder would fail this rather than pass by luck.
    const std::vector<generate::Candidate> cands{
        mk(0x500, 0), mk(0x200, 0), mk(0x300, 0x100)
    };

    const auto groups = generate::resolve_consensus(bytes, cands);
    REQUIRE(groups.size() == 2);
    REQUIRE(groups[0].address == 0x200);        // two agreed
    REQUIRE(groups[0].anchors.size() == 2);
    REQUIRE(groups[1].address == 0x500);        // one did not
    REQUIRE(groups[1].anchors.size() == 1);
}
