// Regression tests for the shipped patterns.
// These encode an xref pattern validated against BOTH builds of one version
// (the pre-release build and the release build), which is the standard a
// pattern has to meet before it is worth keeping.
#include "catch.hpp"
#include "maml.hpp"
#include <vector>
using namespace maml;
using namespace maml::compiler;

// The object-manager lookup, anchored on a call site rather than its entry.
// The tail is byte-identical across builds; the gap after the call is not
// (pre-release: `mov byte [rdi+r12],0` = 5 bytes, release: `mov byte [rdi],0` = 3).
static const char* OBJ_MGR_LOOKUP_XREF =
    "E8 $ { ' } [3-5] 4C 8B D0 48 85 C0 74 ? 0F B6 48 24";

// Build a buffer with the callee at `callee_off` and the call site at
// `site_off`, using the real instruction bytes from each build.
static std::vector<uint8_t> make_image(const std::vector<uint8_t>& gap,
                                       size_t callee_off, size_t site_off) {
    std::vector<uint8_t> buf(0x400, 0xCC);
    buf[callee_off] = 0x48; buf[callee_off+1] = 0x89;      // callee prologue, arbitrary
    size_t p = site_off;
    buf[p++] = 0xE8;                                        // call rel32
    int32_t rel = (int32_t)(callee_off - (site_off + 5));
    for (int i = 0; i < 4; ++i) buf[p++] = (uint8_t)((uint32_t)rel >> (8*i));
    for (uint8_t b : gap) buf[p++] = b;                     // build-specific gap
    const uint8_t tail[] = { 0x4C,0x8B,0xD0, 0x48,0x85,0xC0, 0x74,0xC8,
                             0x0F,0xB6,0x48,0x24 };
    for (uint8_t b : tail) buf[p++] = b;
    return buf;
}

TEST_CASE("object-manager lookup xref pattern", "[patterns]") {
    auto pat = optimize_pattern(parse_pattern(OBJ_MGR_LOOKUP_XREF));

    SECTION("pre-release build: 5-byte gap (mov byte [rdi+r12], 0)") {
        auto img = make_image({0x42,0xC6,0x04,0x27,0x00}, 0x100, 0x200);
        SpanMatchTarget t(img);
        BinaryMatcher m(pat, t);
        auto r = m.next_match();
        REQUIRE(r.has_value());
        REQUIRE(r->size() == 2);          // [0] = match offset, [1] = saved cursor
        REQUIRE((*r)[0] == 0x200);
        REQUIRE((*r)[1] == 0x100);        // '  captured the call target
    }
    SECTION("release build: 3-byte gap (mov byte [rdi], 0)") {
        auto img = make_image({0xC6,0x07,0x00}, 0x100, 0x200);
        SpanMatchTarget t(img);
        BinaryMatcher m(pat, t);
        auto r = m.next_match();
        REQUIRE(r.has_value());
        REQUIRE((*r)[0] == 0x200);
        REQUIRE((*r)[1] == 0x100);
    }
    SECTION("gap outside [3-5] must NOT match") {
        auto img = make_image({0x90,0x90,0x90,0x90,0x90,0x90}, 0x100, 0x200);  // 6
        SpanMatchTarget t(img);
        BinaryMatcher m(pat, t);
        REQUIRE(!m.next_match().has_value());
    }
}

TEST_CASE("ImageMatchTarget resolves absolute VAs", "[patterns]") {
    // A qword holding an image VA; SpanMatchTarget would resolve this against
    // the host heap address and fail. ImageMatchTarget knows the image base.
    const uint64_t BASE = 0x140000000ull;
    std::vector<uint8_t> img(0x200, 0x00);
    uint64_t va = BASE + 0x180;
    for (int i = 0; i < 8; ++i) img[0x10 + i] = (uint8_t)(va >> (8*i));
    img[0x180] = 0xAB;

    auto pat = optimize_pattern(parse_pattern("* '"));
    ImageMatchTarget t(img, BASE);
    BinaryMatcher m(pat, t);
    auto r = m.next_match();
    REQUIRE(r.has_value());
    REQUIRE((*r)[1] == 0x180);
    REQUIRE(t.to_va(0x180) == BASE + 0x180);
}

// ---------------------------------------------------------------------------
// RIP-relative operands with a trailing immediate.
//
// `$` (JumpType::RelDWord) computes (cursor + 4) + disp32. That is correct when
// the disp32 is the LAST field of the instruction, which is the common case:
//
//     48 8B 0D <disp32>            mov rcx, [rip+disp]
//
// It is 4 bytes short when an immediate follows the displacement, because
// RIP-relative addressing is relative to the END of the instruction:
//
//     48 69 15 <disp32> <imm32>    imul rdx, qword ptr [rip+disp], 0x98
//
// No new syntax is needed. The jump leaves the cursor ON the (low) target, so a
// `[N]` skip INSIDE the block walks it to the real address before `'` saves it.
// This came out of a real miss: an offset resolved to 0x76969a4 instead of
// 0x76969a8 in both images of one build pair -- a wrong answer that looked
// entirely plausible, which is the failure mode worth a regression test.
static std::vector<uint8_t> make_imul_ripref(size_t site_off, size_t global_off) {
    std::vector<uint8_t> buf(0x400, 0xCC);
    size_t p = site_off;
    buf[p++] = 0x48; buf[p++] = 0x69; buf[p++] = 0x15;      // imul rdx, [rip+d], imm32
    int32_t disp = (int32_t)(global_off - (site_off + 11));  // 11 = 3 + disp32 + imm32
    for (int i = 0; i < 4; ++i) buf[p++] = (uint8_t)((uint32_t)disp >> (8*i));
    const uint8_t imm[] = { 0x98, 0x00, 0x00, 0x00 };        // the 0x98 stride
    for (uint8_t b : imm) buf[p++] = b;
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0xC8;       // mov rcx, rax
    return buf;
}

TEST_CASE("rip-relative with a trailing immediate", "[patterns][jump]") {
    const size_t SITE = 0x200, GLOBAL = 0x340;
    auto img = make_imul_ripref(SITE, GLOBAL);

    SECTION("bare $ lands one immediate-width short") {
        auto pat = optimize_pattern(parse_pattern("48 69 15 $ { ' } 98 00 00 00 48 8B C8"));
        SpanMatchTarget t(img); BinaryMatcher m(pat, t);
        auto r = m.next_match();
        REQUIRE(r.has_value());
        REQUIRE((*r)[0] == SITE);
        REQUIRE((*r)[1] == GLOBAL - 4);     // the trap: plausible, and wrong
    }
    SECTION("[4] inside the block corrects it") {
        auto pat = optimize_pattern(parse_pattern("48 69 15 $ { [4] ' } 98 00 00 00 48 8B C8"));
        SpanMatchTarget t(img); BinaryMatcher m(pat, t);
        auto r = m.next_match();
        REQUIRE(r.has_value());
        REQUIRE((*r)[0] == SITE);
        REQUIRE((*r)[1] == GLOBAL);         // the real global
    }
    SECTION("the cursor still resumes after the disp32, so the imm32 matches") {
        // If the pop advance were wrong the trailing `98 00 00 00 48 8B C8`
        // would not line up and the match would fail outright.
        auto pat = optimize_pattern(parse_pattern("48 69 15 $ { [4] ' } 98 00 00 00 48 8B C8"));
        SpanMatchTarget t(img); BinaryMatcher m(pat, t);
        REQUIRE(m.next_match().has_value());
    }
}
