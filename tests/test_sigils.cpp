// The punctuation budget, pinned against the pattern lexer.
//
// tests/python/test_sigils.py makes the same claims and makes more of them --
// it can read the doc and check the free list has not drifted. This file
// exists anyway for one reason: maml.hpp is VENDORED downstream by file
// copy, and a project that copies it gets no Python leg. The half of the
// budget that belongs to the vendored header has to be checkable with a C++
// compiler and nothing else.
#include "catch.hpp"
#include "maml.hpp"
#include <string>

using namespace maml;
using namespace maml::compiler;

namespace {

    bool parses(const std::string& src) {
        try {
            (void)parse_pattern(src);
            return true;
        } catch (...) {
            return false;
        }
    }

    // The 12 ASCII punctuation characters neither dialect
    // claims. Spelled out rather than derived, so spending one forces an edit
    // here and, through it, an edit to the doc.
    constexpr const char* kFree = "!#+,.;<=@^`~";

    // The 15 the pattern dialect does claim.
    constexpr const char* kPatternTaken = "?&[]-{}()|%$*'/";

} // namespace

TEST_CASE("every character the pattern dialect spends still parses",
          "[sigils]") {
    // One row per operator in the README's table. Exercised, not described:
    // a table in a README cannot fail.
    REQUIRE(parses("48 ? 8B"));         // ?  one wildcard byte, never a run
    REQUIRE(parses("48 ?? 8B"));        //    so two of them are two bytes
    REQUIRE(parses("48 & F0"));         // &  mask
    REQUIRE(parses("48 [4] 8B"));       // [] fixed skip
    REQUIRE(parses("48 [2-6] 8B"));     // -  range separator
    REQUIRE(parses("E8 $"));            // $  follow a rel32
    REQUIRE(parses("E8 $ { ' }"));      // {} ' capture, then restore the cursor
    REQUIRE(parses("E8 $ { [4] ' }"));  //    the trailing-immediate form
    REQUIRE(parses("EB %"));            // %  follow a rel8
    REQUIRE(parses("48 8B 05 $ *"));    // *  follow an absolute 64-bit pointer
    REQUIRE(parses("48 (8B|89) 05"));   // () | alternation
    REQUIRE(parses("48 // c\n8B"));     // /  line comment
    REQUIRE(parses("48 /* c */ 8B"));   // /  block comment

    // `-` and `$` are also pipeline characters (`->`, and `$` is not). The
    // dialects never mix outside quotes, which is what makes that safe.
    REQUIRE(std::string(kPatternTaken).size() == 15);
}

TEST_CASE("every free character is rejected by the pattern dialect",
          "[sigils]") {
    // This is the assertion that makes the budget a fact rather than a note.
    // Spending one of these in maml.hpp fails here, in the vendored
    // header's own suite, rather than only in the Python leg.
    for (const char* p = kFree; *p; ++p) {
        const std::string one(1, *p);
        INFO("free character: " << one);
        REQUIRE_FALSE(parses("48 " + one + " 8B"));
    }
    REQUIRE(std::string(kFree).size() == 12);

    // 15 spent here + 5 more in the pipeline dialect + 12 free = the 32 ASCII
    // punctuation characters, with no overlap between the two spent sets.
    REQUIRE(std::string(kPatternTaken).size() + 5 + std::string(kFree).size()
            == 32);
}

TEST_CASE("a sigil needs the breaker set, not only the switch", "[sigils]") {
    // THE TRAP, and the reason SIGILS.md tells anyone adding a sigil to touch
    // two places. The switch in next_token() handles a character at the START
    // of a token; mid-token, the text scanner keeps consuming until it hits
    // whitespace or a character in its breaker set ("?&[]{}()|%*'-").
    //
    // `/` is in the switch and NOT in the breaker set, so it is the live
    // instance of the trap:
    REQUIRE(parses("48 // c\n8B"));       // whitespace before it: fine
    REQUIRE_FALSE(parses("48// c\n8B"));  // none: swallowed, then a hex error

    // A character in BOTH needs no such whitespace.
    REQUIRE(parses("48?8B"));
    REQUIRE(parses("48[4]8B"));
    REQUIRE(parses("48'8B"));

    // If `/` is ever added to the breaker set, the second line above starts
    // passing and this test fails -- which is the signal to edit the doc.
}
