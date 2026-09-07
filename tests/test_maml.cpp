#include "catch.hpp"
#include "maml.hpp"
#include "maml.hpp"
using namespace maml;
using namespace maml::compiler;
TEST_CASE("Lexer Tests", "[compiler][lexer]") {
    SECTION("Lexer Text") {
        auto p1 = parse_pattern("12 3");
        REQUIRE(p1.atoms().size() == 2);
    }
    SECTION("Lexer Comments") {
        auto p = parse_pattern("00 // Hello World \n 01 /* comment */ 02");
        REQUIRE(p.atoms().size() == 3);
    }
}
TEST_CASE("Parser Tests", "[compiler][parser]") {
    SECTION("Byte Sequence Mask") {
        auto p = parse_pattern("FFEE & F0F0");
        REQUIRE(p.atoms().size() == 1);
        REQUIRE(std::get<AtomByteSequenceMasked>(p.atoms()[0]) == AtomByteSequenceMasked{0,2,2});
        REQUIRE_THROWS_AS(parse_pattern("FFFF & FF"), ParseException);
    }
    SECTION("Jump Block") {
        auto p = parse_pattern("$ { FE }");
        REQUIRE(p.atoms().size() == 4);
        REQUIRE(std::get<AtomCursorPop>(p.atoms()[3]) == AtomCursorPop{4});
    }
    SECTION("Group parsing") {
        auto p = parse_pattern("( 01 | 02 03 )");
        REQUIRE(p.atoms().size() == 4);
        REQUIRE(std::get<AtomBranch>(p.atoms()[0]) == AtomBranch{1,2});
    }
    SECTION("Range parsing") {
        auto p = parse_pattern("[10-20]");
        REQUIRE(std::get<AtomWildcardRange>(p.atoms()[0]) == AtomWildcardRange{10,20});
    }
}
TEST_CASE("Optimizer Tests", "[compiler][optimizer]") {
    SECTION("Join Byte Sequences") {
        auto p = parse_pattern("11 22 33"); auto o = optimize_pattern(p);
        REQUIRE(o.atoms().size() == 1);
        REQUIRE(std::get<AtomByteSequence>(o.atoms()[0]) == AtomByteSequence{0,3});
    }
    SECTION("Join Wildcards") {
        auto p = parse_pattern("? ? [2]"); auto o = optimize_pattern(p);
        REQUIRE(o.atoms().size() == 1);
        REQUIRE(std::get<AtomWildcardFixed>(o.atoms()[0]) == AtomWildcardFixed{4});
    }
    SECTION("Join Wildcard Range and Fixed") {
        auto p = parse_pattern("[2] [10-20] ?"); auto o = optimize_pattern(p);
        REQUIRE(o.atoms().size() == 1);
        REQUIRE(std::get<AtomWildcardRange>(o.atoms()[0]) == AtomWildcardRange{13,23});
    }
    SECTION("Branch Optimization") {
        auto p = parse_pattern("( 11 22 | 33 )"); auto o = optimize_pattern(p);
        REQUIRE(o.atoms().size() == 3);
        REQUIRE(std::get<AtomBranch>(o.atoms()[0]) == AtomBranch{1,1});
    }
}
TEST_CASE("Matcher Tests", "[matcher]") {
    static const uint8_t DATA[] = {
        0xCA,0x70,0x11,0xB5,0x0A,0x9D,0x91,0x83,0xC4,0x5A,0xFC,0xC7,0x31,0x26,0xC3,
        0x48,0x3D,0x6C,0x16,0xD7,0x15,0x91,0xDB,0xC4,0x21,0x02,0x31,0x4D,0xE9,0xD5,
        0x52,0xFB,0xB7,0x31,0x91,0x45,0x35,0xC7,0xDA,0xA9,0x77,0xFC,0x9C,0x3E,0x65,
        0x19,0xF2,0x5A,0x68,0x99,0x21,0x0C,0xED,0xDC,0x21,0x8C,0xA2,0x7B,0xBA,0xC0,
        0x9A,0x94,0x99,0x9B,0xB2,0xB7,0x69,0x2D,0x17,0xA9,0x85,0x2C,0xD7,0x42,0x43,
        0x91,0xF6,0x6E,0x34,0xBC,0x2F,0xF7,0xAE,0xAA,0xAE,0xBF,0x04,0xE5,0xD5,0x9B,
        0x13,0x60,0x17,0x31,0x87,0xEF,0xF1,0x24,0x43,0xB4,0x60,0xBC,0x9F,0x16,0x86,
        0x39,0x3D,0x9E,0x01,0x68,0x74,0x8D,0xD3,0xC8,0x06,0x25,0x88,0xB0,0x95,0x99,
        0xB4,0x5D,0xBE,0x8B,0xD3,0x26,0xCB,0x3C };
    SpanMatchTarget target(DATA);
    SECTION("Simple match") {
        auto p = optimize_pattern(parse_pattern("B7 69 2D"));
        BinaryMatcher matcher(p, target);
        auto m = matcher.next_match();
        REQUIRE(m.has_value()); REQUIRE((*m)[0] == 0x41);
    }
    SECTION("Save cursor") {
        auto p = optimize_pattern(parse_pattern("B7 69 ' 2D"));
        BinaryMatcher matcher(p, target);
        auto m = matcher.next_match();
        REQUIRE(m.has_value()); REQUIRE((*m).size() == 2);
        REQUIRE((*m)[0] == 0x41); REQUIRE((*m)[1] == 0x43);
    }
    SECTION("Branch match") {
        auto p = optimize_pattern(parse_pattern("B7 (70 | 69) 2D"));
        BinaryMatcher matcher(p, target);
        auto m = matcher.next_match();
        REQUIRE(m.has_value()); REQUIRE((*m)[0] == 0x41);
    }
    SECTION("Wildcard range") {
        auto p = optimize_pattern(parse_pattern("B7 69 2D [1-5] A9 85"));
        BinaryMatcher matcher(p, target);
        auto m = matcher.next_match();
        REQUIRE(m.has_value()); REQUIRE((*m)[0] == 0x41);
    }
}

// ---------------------------------------------------------------------------
// Seeded / bounded scanning.
//
// next_match() scans forward from its start offset until it matches or runs out
// of target. A caller driving the matcher from a literal prefilter already knows
// where the candidate begins and wants "does it match HERE"; without a bound, a
// rejected candidate costs a scan of everything after it. Against a 133MB image
// that turned 950 rejected candidates into a six-minute search.
// ---------------------------------------------------------------------------
TEST_CASE("BinaryMatcher can start at an offset", "[seek]") {
    // "AA BB" occurs at 0 and again at 4.
    const std::vector<uint8_t> data{0xAA, 0xBB, 0x00, 0x00, 0xAA, 0xBB, 0x00};
    auto pat = maml::compiler::optimize_pattern(
        maml::compiler::parse_pattern("AA BB"));
    maml::SpanMatchTarget target(std::span<const uint8_t>(data.data(), data.size()));

    SECTION("default start finds the first occurrence") {
        maml::BinaryMatcher<> m(pat, target);
        auto h = m.next_match();
        REQUIRE(h);
        REQUIRE((*h)[0] == 0);
    }
    SECTION("seeking past the first finds the second") {
        maml::BinaryMatcher<> m(pat, target, 1);
        auto h = m.next_match();
        REQUIRE(h);
        REQUIRE((*h)[0] == 4);
    }
    SECTION("a limit of 1 tries only the seeded offset") {
        maml::BinaryMatcher<> m(pat, target, 1, 1);   // pattern does not match here
        REQUIRE_FALSE(m.next_match());
    }
    SECTION("a limit of 1 still matches when the seed is right") {
        maml::BinaryMatcher<> m(pat, target, 4, 1);
        auto h = m.next_match();
        REQUIRE(h);
        REQUIRE((*h)[0] == 4);
    }
    SECTION("a seed past the end yields nothing rather than misbehaving") {
        maml::BinaryMatcher<> m(pat, target, data.size() + 10, 1);
        REQUIRE_FALSE(m.next_match());
    }
}
