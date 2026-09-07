// The locator pipeline: compose substrate into a search for an address.
//
// Fixtures here are CROWDED by construction -- every byte value present,
// hundreds of decoy instructions carrying each stage's opcode -- following
// tests/test_generate.cpp's structural fixtures rather than the 0xCC filler
// the older tests use. A sparse image makes a three-byte selector unique for
// free, and once made a Critical invisible in this repo.
#include "catch.hpp"
#include "maml/pipeline.hpp"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

using namespace maml;
using pipeline::Op;

namespace {

uint8_t pipe_byte(uint64_t& s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return (uint8_t)(s >> 24);
}

void put_rel32(std::vector<uint8_t>& b, uint64_t at, uint64_t to, uint64_t end) {
    const int32_t rel = (int32_t)((int64_t)to - (int64_t)end);
    for (int j = 0; j < 4; ++j)
        b[at + j] = (uint8_t)((uint32_t)rel >> (8 * j));
}

void put_str(std::vector<uint8_t>& b, uint64_t at, const std::string& s) {
    // The byte BEFORE the run matters: strings() reports MAXIMAL printable
    // runs, so a printable filler byte in front would make the run start
    // earlier and its content differ from `s`. In a crowded image ~37% of
    // filler bytes are printable, so leaving this out gives a fixture that
    // works most of the time.
    b[at - 1] = 0x00;
    for (size_t i = 0; i < s.size(); ++i)
        b[at + i] = (uint8_t)s[i];
    b[at + s.size()] = 0x00;
}

// A `lea reg, [rip+disp]` reaching `to`, the exact form rip_lea_index decodes
// (`48 8D <modrm 0x0D> <disp32>`, target = site + 7 + disp32).
void put_lea(std::vector<uint8_t>& b, uint64_t at, uint64_t to) {
    b[at] = 0x48;
    b[at + 1] = 0x8D;
    b[at + 2] = 0x0D;
    put_rel32(b, at + 3, to, at + 7);
}

// `test dword ptr [rax+disp32], imm32` -- the F7 /0 form whose disp32 is a
// structure field offset. This is the shape `find` + `read` exist for: the
// 3-byte prefix `F7 80 58` is everywhere in the image, and unique inside one
// function.
void put_field(std::vector<uint8_t>& b, uint64_t at, uint32_t disp) {
    b[at] = 0xF7;
    b[at + 1] = 0x80;
    for (int j = 0; j < 4; ++j)
        b[at + 2 + j] = (uint8_t)(disp >> (8 * j));
    for (int j = 0; j < 4; ++j)
        b[at + 6 + j] = 0x00; // the imm32; the pattern says nothing about it
}

void put_call(std::vector<uint8_t>& b, uint64_t at, uint64_t to) {
    b[at] = 0xE8;
    put_rel32(b, at + 1, to, at + 5);
}

// One image, crowded, carrying everything the stages need:
//
//   kOnce   a string referenced by exactly ONE lea, inside func fn_once
//   kTwice  a string referenced by TWO leas, in two different funcs
//   callee  a function with three call sites, each inside a func of its own
//
// `variant` perturbs the decoys, so two independent images can be built.
struct PipeImage {
    std::vector<uint8_t> bytes;
    std::vector<generate::Range> code, rodata, funcs;

    uint64_t str_once = 0, str_twice = 0;
    uint64_t ref_once = 0;                  // the lea that loads str_once
    uint64_t fn_once = 0;                   // the function containing it
    std::vector<uint64_t> refs_twice;       // the two leas loading str_twice
    std::vector<uint64_t> fns_twice;        // and their functions
    uint64_t callee = 0;
    std::vector<uint64_t> call_sites, caller_fns;

    // Two strings sharing a prefix, whose references are in the OPPOSITE
    // order to the strings themselves: the lower string is referenced from
    // the higher address. A stage that emitted its output in discovery order
    // would return these two the wrong way round.
    uint64_t str_alpha = 0, str_bravo = 0, ref_alpha = 0, ref_bravo = 0;

    // The `find`/`read` fixture. `field_site` is the one F7 80 inside
    // fn_once; `field_decoys` are the same six bytes planted outside every
    // function, so the 3-byte prefix is hopelessly ambiguous image-wide and
    // unique within fn_once. `field_other` sits inside a DIFFERENT function
    // with a different displacement, so a `find` that leaked out of its
    // scope would be caught by the value, not just by the count.
    uint64_t field_site = 0, field_disp_at = 0, field_other = 0;
    size_t field_decoys = 0;
    std::vector<uint64_t> field_sites_twice; // one in each of the two fns_twice

    // The last four bytes of the image, so `read 4` succeeds there and
    // `read 8` runs off the end.
    uint64_t tail = 0;
};

// The displacement `find "F7 80 ' ? ? 00 00" -> read 4` must come back with.
const uint32_t kFieldOffset = 0x1C58;
const uint32_t kOtherOffset = 0x2A58;  // shares the `58`, differs in the value

const char* kOnce = "PipelineOnlyReferentOnce";
const char* kTwice = "PipelineReferentTwice";
const char* kPrefix = "PipelineOrder"; // shared by the two strings below

PipeImage make_pipe_image(unsigned variant = 0, size_t decoys = 300) {
    PipeImage p;
    const size_t n = 0x20000;
    const uint64_t code_end = 0x18000;
    p.bytes.assign(n, 0);
    uint64_t s = 0x9E3779B97F4A7C15ull + variant;
    for (size_t i = 0; i < n; ++i)
        p.bytes[i] = pipe_byte(s);

    // Decoys: the same opcodes every stage keys on, pointing elsewhere.
    for (size_t d = 0; d < decoys; ++d) {
        const uint64_t at = 0x2000 + d * 0x30;
        if (at + 24 >= code_end)
            break;
        put_lea(p.bytes, at, 0x19800 + d * 4);          // lea to other data
        put_call(p.bytes, at + 8, 0x1500 + variant);    // call elsewhere
        p.bytes[at + 16] = 0x48;
        p.bytes[at + 17] = 0x8B;
        p.bytes[at + 18] = 0x0D;
        put_rel32(p.bytes, at + 19, 0x19900 + d * 4, at + 23);
    }

    // Strings, in rodata, well clear of the decoy targets.
    p.str_once = 0x18400;
    p.str_twice = 0x18500;
    put_str(p.bytes, p.str_once, kOnce);
    put_str(p.bytes, p.str_twice, kTwice);

    // One reference to kOnce, inside its own function.
    p.fn_once = 0x11000;
    p.ref_once = p.fn_once + 0x20;
    put_lea(p.bytes, p.ref_once, p.str_once);

    // Two references to kTwice, in two distinct functions.
    for (int k = 0; k < 2; ++k) {
        const uint64_t fn = 0x11800 + (uint64_t)k * 0x400;
        const uint64_t site = fn + 0x10 + (uint64_t)k * 8;
        put_lea(p.bytes, site, p.str_twice);
        p.refs_twice.push_back(site);
        p.fns_twice.push_back(fn);
    }

    // The out-of-order pair: alpha sorts first but is referenced LAST.
    p.str_alpha = 0x18600;
    p.str_bravo = 0x18700;
    put_str(p.bytes, p.str_alpha, "PipelineOrderAlpha");
    put_str(p.bytes, p.str_bravo, "PipelineOrderBravo");
    p.ref_alpha = 0x12400;
    p.ref_bravo = 0x11400;
    put_lea(p.bytes, p.ref_alpha, p.str_alpha);
    put_lea(p.bytes, p.ref_bravo, p.str_bravo);

    // A called function with three call sites, each in a function of its own.
    p.callee = 0x1000;
    const uint8_t body[] = { 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56 };
    for (size_t i = 0; i < sizeof body; ++i)
        p.bytes[p.callee + i] = body[i];
    for (int k = 0; k < 3; ++k) {
        const uint64_t fn = 0x13000 + (uint64_t)k * 0x200;
        const uint64_t site = fn + 0x30;
        put_call(p.bytes, site, p.callee);
        p.call_sites.push_back(site);
        p.caller_fns.push_back(fn);
    }

    // The field-offset fixture. 220 copies of the exact six bytes, planted
    // between the decoy block and the functions, so they are inside `code`
    // and inside NO function.
    for (size_t d = 0; d < 220; ++d) {
        put_field(p.bytes, 0x8000 + d * 0x20, kFieldOffset);
        ++p.field_decoys;
    }
    p.field_site = p.fn_once + 0x40;      // inside fn_once, past ref_once
    p.field_disp_at = p.field_site + 2;   // where the capture lands
    put_field(p.bytes, p.field_site, kFieldOffset);
    p.field_other = p.caller_fns[0] + 0x50;
    put_field(p.bytes, p.field_other, kOtherOffset);
    for (uint64_t fn : p.fns_twice) {
        // The same displacement in two different functions, so two found
        // addresses collapse to one VALUE.
        put_field(p.bytes, fn + 0x80, kFieldOffset);
        p.field_sites_twice.push_back(fn + 0x80);
    }

    // A distinctive marker in the last four bytes of the image.
    p.tail = n - 4;
    p.bytes[p.tail] = 0xC7;
    p.bytes[p.tail + 1] = 0x3D;
    p.bytes[p.tail + 2] = 0x9A;
    p.bytes[p.tail + 3] = 0x5E;

    p.code = { { 0, code_end } };
    p.rodata = { { code_end, n } };
    p.funcs = { { p.callee, p.callee + 0x100 }, { p.fn_once, p.fn_once + 0x200 } };
    for (uint64_t f : p.fns_twice)
        p.funcs.push_back({ f, f + 0x200 });
    for (uint64_t f : p.caller_fns)
        p.funcs.push_back({ f, f + 0x100 });
    std::sort(p.funcs.begin(), p.funcs.end(),
        [](const generate::Range& a, const generate::Range& b) { return a.begin < b.begin; });
    return p;
}

generate::Image view(const PipeImage& p) {
    return generate::Image{ p.bytes, p.code, p.rodata, p.funcs };
}

// The image with one piece of substrate withheld, which is what R4 is about:
// "not configured" must not read as "not found".
generate::Image view_no_funcs(const PipeImage& p) {
    return generate::Image{ p.bytes, p.code, p.rodata, {} };
}
generate::Image view_no_rodata(const PipeImage& p) {
    return generate::Image{ p.bytes, p.code, {}, p.funcs };
}
generate::Image view_no_code(const PipeImage& p) {
    return generate::Image{ p.bytes, {}, p.rodata, p.funcs };
}

std::string hex_of(const char* text) {
    return generate::hex_bytes(reinterpret_cast<const uint8_t*>(text), strlen(text));
}

std::string q(const char* s) {
    return std::string("\"") + s + "\"";
}

} // namespace

// ── the fixture itself ────────────────────────────────────────────────

TEST_CASE("the pipeline fixture is actually crowded", "[pipeline][structural]") {
    // Asserted, not assumed: a helper that quietly stopped producing density
    // would weaken every test below to the sparse case they exist to replace.
    const PipeImage p = make_pipe_image(0);

    auto count = [&](std::initializer_list<uint8_t> op) {
        size_t k = 0;
        const std::vector<uint8_t> pat(op);
        for (size_t i = 0; i + pat.size() <= p.bytes.size(); ++i)
            if (std::equal(pat.begin(), pat.end(), p.bytes.begin() + (long)i))
                ++k;
        return k;
    };
    REQUIRE(count({ 0x48, 0x8D, 0x0D }) > 100); // xref's lea
    REQUIRE(count({ 0xE8 }) > 100);             // callers' call

    bool seen[256] = { false };
    for (uint8_t b : p.bytes)
        seen[b] = true;
    int distinct = 0;
    for (bool v : seen)
        distinct += v ? 1 : 0;
    REQUIRE(distinct == 256);
}

// ── parsing ───────────────────────────────────────────────────────────

TEST_CASE("the arrow separates stages", "[pipeline][parse]") {
    const pipeline::Program p = pipeline::parse("str \"hello!\" -> xref -> func -> unique");
    REQUIRE(p.ok);
    REQUIRE(p.stages.size() == 4);
    REQUIRE(p.stages[0].op == Op::Str);
    REQUIRE(p.stages[0].text == "hello!");
    REQUIRE(p.stages[1].op == Op::Xref);
    REQUIRE(p.stages[2].op == Op::Func);
    REQUIRE(p.stages[3].op == Op::Unique);
}

TEST_CASE("whitespace around the arrow is optional", "[pipeline][parse]") {
    const pipeline::Program p = pipeline::parse("str \"hello!\"->xref->nth 2");
    REQUIRE(p.ok);
    REQUIRE(p.stages.size() == 3);
    REQUIRE(p.stages[2].op == Op::Nth);
    REQUIRE(p.stages[2].n == 2);
}

TEST_CASE("every stage parses, with its argument", "[pipeline][parse]") {
    const pipeline::Program a = pipeline::parse("bytes \"48 89 5C 24 08\" -> callers -> limit 3");
    REQUIRE(a.ok);
    REQUIRE(a.stages[0].op == Op::Bytes);
    REQUIRE(a.stages[0].text == "48 89 5C 24 08");
    REQUIRE(a.stages[1].op == Op::Callers);
    REQUIRE(a.stages[2].op == Op::Limit);
    REQUIRE(a.stages[2].n == 3);
}

TEST_CASE("a pattern with an alternation survives the arrow syntax", "[pipeline][parse]") {
    // `->` rather than `|` exists precisely so a `bytes` stage can embed the
    // pattern dialect whole, and that dialect uses `|` for alternation.
    const pipeline::Program p = pipeline::parse("bytes \"48 (8B | 89) 05 ? ? ? ?\" -> func");
    REQUIRE(p.ok);
    REQUIRE(p.stages[0].text == "48 (8B | 89) 05 ? ? ? ?");
    REQUIRE(p.stages.size() == 2);
}

TEST_CASE("string escapes decode", "[pipeline][parse]") {
    const pipeline::Program p =
        pipeline::parse("str \"a\\\"b\\\\c\\nd\\te\\x41f\"");
    REQUIRE(p.ok);
    REQUIRE(p.stages[0].text == std::string("a\"b\\c\nd\te") + "Af");
}

TEST_CASE("a stage renders back to what parses to it", "[pipeline][parse]") {
    const pipeline::Program p = pipeline::parse("str \"tab\\there\" -> nth 7");
    REQUIRE(p.ok);
    REQUIRE(p.stages[0].repr == "str \"tab\\there\"");
    REQUIRE(p.stages[1].repr == "nth 7");
    const pipeline::Program again =
        pipeline::parse(p.stages[0].repr + " -> " + p.stages[1].repr);
    REQUIRE(again.ok);
    REQUIRE(again.stages[0].text == p.stages[0].text);
    REQUIRE(again.stages[1].n == 7);
}

// ── R1: a parse error is a result, not an exception ───────────────────

TEST_CASE("a parse error is a result naming the offending stage", "[pipeline][parse][R1]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    // Never throws: the CLI must survive a malformed pipeline out of a
    // jobfile, and every one of these used to be a candidate for an
    // exception escaping into main().
    const pipeline::PipelineResult unknown = pipeline::run(img, "str \"hello!\" -> xrefs");
    REQUIRE_FALSE(unknown.ok);
    REQUIRE(pipeline::failed(unknown));
    REQUIRE(unknown.failed_stage == 1);
    REQUIRE(unknown.error.find("unknown stage") != std::string::npos);
    REQUIRE(unknown.trace.empty());

    const pipeline::PipelineResult unterminated = pipeline::run(img, "str \"no closing");
    REQUIRE(pipeline::failed(unterminated));
    REQUIRE(unterminated.failed_stage == 0);

    const pipeline::PipelineResult bad_escape = pipeline::run(img, "str \"bad \\q escape\"");
    REQUIRE(pipeline::failed(bad_escape));
    REQUIRE(bad_escape.failed_stage == 0);

    const pipeline::PipelineResult no_arg = pipeline::run(img, "str \"hello!\" -> nth");
    REQUIRE(pipeline::failed(no_arg));
    REQUIRE(no_arg.failed_stage == 1);

    const pipeline::PipelineResult trailing = pipeline::run(img, "str \"hello!\" -> xref ->");
    REQUIRE(pipeline::failed(trailing));
    REQUIRE(trailing.failed_stage == 2);

    const pipeline::PipelineResult empty = pipeline::run(img, "   ");
    REQUIRE(pipeline::failed(empty));
    REQUIRE(empty.failed_stage == 0);

    // A seed anywhere but first would silently discard everything to its
    // left; a non-seed first stage has nothing to work on.
    const pipeline::PipelineResult late_seed =
        pipeline::run(img, "str \"hello!\" -> xref -> str \"other!\"");
    REQUIRE(pipeline::failed(late_seed));
    REQUIRE(late_seed.failed_stage == 2);

    const pipeline::PipelineResult no_seed = pipeline::run(img, "xref -> func");
    REQUIRE(pipeline::failed(no_seed));
    REQUIRE(no_seed.failed_stage == 0);

    // A malformed maml pattern inside `bytes` lands the same way, rather
    // than as a ParseException out of locate::compile.
    const pipeline::PipelineResult bad_pattern = pipeline::run(img, "bytes \"48 (8B\"");
    REQUIRE(pipeline::failed(bad_pattern));
    REQUIRE(bad_pattern.failed_stage == 0);
}

// ── seeds ─────────────────────────────────────────────────────────────

TEST_CASE("str seeds on exact NUL-terminated content", "[pipeline][stages]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r = pipeline::run(img, "str " + q(kOnce));
    REQUIRE(r.ok);
    REQUIRE(r.addresses == std::vector<uint64_t>{ p.str_once });
    REQUIRE(r.trace.size() == 1);
    REQUIRE(r.trace[0].in == 0);
    REQUIRE(r.trace[0].out == 1);

    // Exact content only: a prefix of a real string is not a match, because
    // strings() reports maximal runs and substring matching would quietly
    // reintroduce ambiguity at the seed.
    const pipeline::PipelineResult prefix = pipeline::run(img, "str \"PipelineOnly\"");
    REQUIRE_FALSE(prefix.ok);
    REQUIRE_FALSE(pipeline::failed(prefix));
    REQUIRE(prefix.addresses.empty());
}

TEST_CASE("bytes seeds on a maml pattern's match offsets", "[pipeline][stages]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    // The callee's prologue. save_index 0, so the addresses are match
    // offsets, not capture slots.
    const pipeline::PipelineResult r =
        pipeline::run(img, "bytes \"55 48 89 E5 41 57 41 56\"");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == std::vector<uint64_t>{ p.callee });
}

// ── walking stages ────────────────────────────────────────────────────

TEST_CASE("xref on a data address uses the rip index", "[pipeline][stages]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r = pipeline::run(img, "str " + q(kOnce) + " -> xref");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == std::vector<uint64_t>{ p.ref_once });
}

TEST_CASE("xref on a code address uses the call graph", "[pipeline][stages]") {
    // The ruling, exercised: inside a `code` range the call graph answers, so
    // xref on the callee finds its call sites -- and would not find a lea
    // that took the function's address. `callers` stays available for the
    // cases where the caller knows better than the heuristic.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "bytes \"55 48 89 E5 41 57 41 56\" -> xref");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == p.call_sites);
}

TEST_CASE("callers finds call sites targeting the input", "[pipeline][stages]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "bytes \"55 48 89 E5 41 57 41 56\" -> callers");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == p.call_sites);
}

TEST_CASE("func maps to the enclosing function, dropping addresses without one",
    "[pipeline][stages]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "bytes \"55 48 89 E5 41 57 41 56\" -> callers -> func");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == p.caller_fns);

    // A seed inside no function at all is dropped -- not an error, because
    // `funcs` IS configured here, so "no enclosing function" is a real answer
    // rather than a missing index.
    const pipeline::PipelineResult none =
        pipeline::run(img, "str " + q(kOnce) + " -> func");
    REQUIRE_FALSE(none.ok);
    REQUIRE_FALSE(pipeline::failed(none));
    REQUIRE(none.trace.back().in == 1);
    REQUIRE(none.trace.back().out == 0);
}

TEST_CASE("nth and limit take from the ascending order", "[pipeline][stages]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    const std::string base = "bytes \"55 48 89 E5 41 57 41 56\" -> callers";

    for (size_t k = 0; k < p.call_sites.size(); ++k) {
        const pipeline::PipelineResult r =
            pipeline::run(img, base + " -> nth " + std::to_string(k));
        REQUIRE(r.ok);
        REQUIRE(r.addresses == std::vector<uint64_t>{ p.call_sites[k] });
    }

    const pipeline::PipelineResult two = pipeline::run(img, base + " -> limit 2");
    REQUIRE(two.ok);
    REQUIRE(two.addresses ==
        std::vector<uint64_t>{ p.call_sites[0], p.call_sites[1] });

    const pipeline::PipelineResult all = pipeline::run(img, base + " -> limit 99");
    REQUIRE(all.addresses == p.call_sites);
}

// ── R2 / R3: empty is not an error, and the edges are clean ───────────

TEST_CASE("an empty result is not an error", "[pipeline][R2]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r = pipeline::run(img, "str \"NoSuchStringHere\"");
    REQUIRE_FALSE(r.ok);          // ok means "ended with at least one address"
    REQUIRE_FALSE(pipeline::failed(r));
    REQUIRE(r.error.empty());
    REQUIRE(r.failed_stage == SIZE_MAX);
    REQUIRE(r.trace.size() == 1); // and every stage still ran
}

TEST_CASE("nth past the end and limit 0 are empty, not errors", "[pipeline][R3]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    const std::string base = "bytes \"55 48 89 E5 41 57 41 56\" -> callers";

    const pipeline::PipelineResult past = pipeline::run(img, base + " -> nth 99");
    REQUIRE_FALSE(past.ok);
    REQUIRE_FALSE(pipeline::failed(past));
    REQUIRE(past.addresses.empty());
    REQUIRE(past.trace.back().in == 3);
    REQUIRE(past.trace.back().out == 0);

    const pipeline::PipelineResult zero = pipeline::run(img, base + " -> limit 0");
    REQUIRE_FALSE(zero.ok);
    REQUIRE_FALSE(pipeline::failed(zero));
    REQUIRE(zero.addresses.empty());
}

// ── unique, and the stage index it names ──────────────────────────────

TEST_CASE("unique passes a single address through unchanged", "[pipeline][unique]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "str " + q(kOnce) + " -> xref -> func -> unique");
    REQUIRE(r.ok);
    REQUIRE_FALSE(pipeline::failed(r));
    REQUIRE(r.addresses == std::vector<uint64_t>{ p.fn_once });
    REQUIRE(r.trace.size() == 4);
}

TEST_CASE("unique fails at the stage that introduced the ambiguity",
    "[pipeline][unique]") {
    // THE point of the trace. `str -> xref -> func -> unique` over a string
    // with two referents fails, and the index it names says WHICH question
    // had several answers: the string was referenced from two places (stage
    // 1). Naming `unique`'s own index instead would report 3 here and 3 for
    // every other ambiguity too, which distinguishes nothing.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "str " + q(kTwice) + " -> xref -> func -> unique");
    REQUIRE(pipeline::failed(r));
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.failed_stage == 1); // xref, not unique
    REQUIRE(r.error.find("got 2") != std::string::npos);
    REQUIRE(r.addresses.empty());

    // The trace holds every stage that COMPLETED -- three of them -- and
    // shows the set widening at stage 1 and staying wide.
    REQUIRE(r.trace.size() == 3);
    REQUIRE(r.trace[0].out == 1);
    REQUIRE(r.trace[1].out == 2);
    REQUIRE(r.trace[2].out == 2);

    // A DIFFERENT problem, and a different index: the seed is unique and so
    // is its function -- it is the CALLERS that are several, so the same
    // `unique` failure now names stage 2 rather than stage 1.
    const pipeline::PipelineResult callers = pipeline::run(img,
        "bytes \"55 48 89 E5 41 57 41 56\" -> func -> callers -> unique");
    REQUIRE(pipeline::failed(callers));
    REQUIRE(callers.failed_stage == 2); // callers
    REQUIRE(callers.error.find("got 3") != std::string::npos);

    // The seed itself being ambiguous names stage 0.
    const pipeline::PipelineResult seed =
        pipeline::run(img, "bytes \"48 8D 0D\" -> unique");
    REQUIRE(pipeline::failed(seed));
    REQUIRE(seed.failed_stage == 0);

    // And the same chain over the once-referenced string reaches `unique`
    // without failing -- so the failure above is about the referent count,
    // not about the chain.
    const pipeline::PipelineResult ok =
        pipeline::run(img, "str " + q(kOnce) + " -> xref -> func -> unique");
    REQUIRE(ok.ok);
}

TEST_CASE("unique over an empty set fails at the stage that emptied it",
    "[pipeline][unique]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    // `func` drops the string address (it is in no function), so the set is
    // empty at stage 1 and that is the stage to look at.
    const pipeline::PipelineResult r =
        pipeline::run(img, "str " + q(kOnce) + " -> func -> unique");
    REQUIRE(pipeline::failed(r));
    REQUIRE(r.failed_stage == 1);
    REQUIRE(r.error.find("got 0") != std::string::npos);
}

// ── the chain that matters ────────────────────────────────────────────

TEST_CASE("str -> xref -> func resolves to a known function", "[pipeline][structural]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "str " + q(kOnce) + " -> xref -> func");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == std::vector<uint64_t>{ p.fn_once });

    // The trace carries the cardinality after EVERY stage, which is what lets
    // a caller see that its single answer really was single all the way
    // through rather than one of several silently taken first.
    REQUIRE(r.trace.size() == 3);
    REQUIRE(r.trace[0].stage == std::string("str \"") + kOnce + "\"");
    REQUIRE(r.trace[0].in == 0);
    REQUIRE(r.trace[0].out == 1);
    REQUIRE(r.trace[1].stage == "xref");
    REQUIRE(r.trace[1].in == 1);
    REQUIRE(r.trace[1].out == 1);
    REQUIRE(r.trace[2].stage == "func");
    REQUIRE(r.trace[2].out == 1);
}

TEST_CASE("the chain holds in an independently built image", "[pipeline][structural]") {
    // A pipeline never encodes a literal address, so the SAME text finds the
    // function in a second image whose decoys and call targets differ. This
    // is not a durability claim -- these two images are one generator apart,
    // not one compiler apart -- only evidence that no stage is reading a
    // baked-in address.
    const PipeImage b = make_pipe_image(1);
    const pipeline::PipelineResult r =
        pipeline::run(view(b), "str " + q(kOnce) + " -> xref -> func -> unique");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == std::vector<uint64_t>{ b.fn_once });
}

// ── R4: missing substrate is named, never answered with silence ───────

TEST_CASE("a stage whose substrate is missing says so", "[pipeline][R4]") {
    const PipeImage p = make_pipe_image(0);

    // func with no `funcs` ranges. An empty answer here would be
    // indistinguishable from "the address is in no function".
    const pipeline::PipelineResult nf = pipeline::run(view_no_funcs(p),
        "bytes \"55 48 89 E5 41 57 41 56\" -> callers -> func");
    REQUIRE(pipeline::failed(nf));
    REQUIRE(nf.failed_stage == 2);
    REQUIRE(nf.error.find("func:") == 0);
    REQUIRE(nf.error.find("funcs") != std::string::npos);
    REQUIRE(nf.addresses.empty());

    // str with no `rodata` ranges: there is no string table to search.
    const pipeline::PipelineResult ns =
        pipeline::run(view_no_rodata(p), "str " + q(kOnce));
    REQUIRE(pipeline::failed(ns));
    REQUIRE(ns.failed_stage == 0);
    REQUIRE(ns.error.find("rodata") != std::string::npos);

    // xref on a data address with no `rodata`: the address is in neither
    // index's territory, so "which index" has no answer. Reached here through
    // a `bytes` seed, since `str` needs the rodata that is being withheld.
    // 12 bytes, not 8: "PipelineOnly" is where the two fixture strings
    // diverge, so a shorter literal would seed on both of them.
    const std::string pat =
        "bytes \"" + generate::hex_bytes(&p.bytes[p.str_once], 12) + "\"";
    const pipeline::PipelineResult nx =
        pipeline::run(view_no_rodata(p), pat + " -> xref");
    REQUIRE(pipeline::failed(nx));
    REQUIRE(nx.failed_stage == 1);
    REQUIRE(nx.error.find("neither") != std::string::npos);

    // xref and callers with no `code` ranges: nothing to search for a
    // reference, so every answer would be empty for the wrong reason.
    const pipeline::PipelineResult nc =
        pipeline::run(view_no_code(p), "str " + q(kOnce) + " -> xref");
    REQUIRE(pipeline::failed(nc));
    REQUIRE(nc.failed_stage == 1);
    REQUIRE(nc.error.find("code") != std::string::npos);

    const pipeline::PipelineResult ncc =
        pipeline::run(view_no_code(p), "str " + q(kOnce) + " -> callers");
    REQUIRE(pipeline::failed(ncc));
    REQUIRE(ncc.failed_stage == 1);
    REQUIRE(ncc.error.find("code") != std::string::npos);
}

TEST_CASE("output is ascending, not discovery order", "[pipeline][R6]") {
    // The set is SORTED after every stage, not merely deduplicated. Here the
    // two seeds are found in ascending order but their references are in the
    // opposite order, so a stage emitting what it discovered would answer
    // { ref_alpha, ref_bravo } -- the same two addresses, the wrong way
    // round, and `nth 0` would then mean "whichever the scan happened to hit
    // first" rather than "the lowest".
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    REQUIRE(p.ref_bravo < p.ref_alpha);
    REQUIRE(p.str_alpha < p.str_bravo);

    const pipeline::PipelineResult r =
        pipeline::run(img, "bytes \"" + hex_of(kPrefix) + "\" -> xref");
    REQUIRE(r.ok);
    REQUIRE(r.trace[0].out == 2);
    REQUIRE(r.addresses == std::vector<uint64_t>{ p.ref_bravo, p.ref_alpha });
    REQUIRE(std::is_sorted(r.addresses.begin(), r.addresses.end()));

    const pipeline::PipelineResult first =
        pipeline::run(img, "bytes \"" + hex_of(kPrefix) + "\" -> xref -> nth 0");
    REQUIRE(first.addresses == std::vector<uint64_t>{ p.ref_bravo });
}

// ── R6: determinism ───────────────────────────────────────────────────

TEST_CASE("the same input always gives the same output", "[pipeline][R6]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    const std::string src = "str " + q(kTwice) + " -> xref -> func";

    const pipeline::PipelineResult first = pipeline::run(img, src);
    for (int i = 0; i < 4; ++i) {
        const pipeline::PipelineResult again = pipeline::run(img, src);
        REQUIRE(again.ok == first.ok);
        REQUIRE(again.addresses == first.addresses);
        REQUIRE(again.trace.size() == first.trace.size());
        for (size_t k = 0; k < again.trace.size(); ++k) {
            REQUIRE(again.trace[k].stage == first.trace[k].stage);
            REQUIRE(again.trace[k].in == first.trace[k].in);
            REQUIRE(again.trace[k].out == first.trace[k].out);
        }
    }

    // Sorted and deduplicated, so the answer cannot depend on the order the
    // stages discovered things -- and permuting the caller-supplied `funcs`
    // must not change it either.
    REQUIRE(std::is_sorted(first.addresses.begin(), first.addresses.end()));
    REQUIRE(std::adjacent_find(first.addresses.begin(), first.addresses.end()) ==
        first.addresses.end());

    PipeImage shuffled = make_pipe_image(0);
    std::reverse(shuffled.funcs.begin(), shuffled.funcs.end());
    const pipeline::PipelineResult permuted = pipeline::run(view(shuffled), src);
    REQUIRE(permuted.addresses == first.addresses);
}

TEST_CASE("a repeated input address contributes its references once",
    "[pipeline][R6]") {
    // Both referents of kTwice sit in different functions, so `func` maps 2
    // to 2; but a single function containing both would map 2 to 1, and the
    // dedup is what makes that 1 rather than a duplicated pair.
    const PipeImage p = make_pipe_image(0);
    PipeImage merged = p;
    merged.funcs = { { merged.fns_twice[0], merged.fns_twice[1] + 0x200 } };
    const generate::Image img{ merged.bytes, merged.code, merged.rodata, merged.funcs };

    const pipeline::PipelineResult r =
        pipeline::run(img, "str " + q(kTwice) + " -> xref -> func");
    REQUIRE(r.ok);
    REQUIRE(r.addresses.size() == 1);
    REQUIRE(r.trace[1].out == 2);
    REQUIRE(r.trace[2].in == 2);
    REQUIRE(r.trace[2].out == 1);
}

TEST_CASE("Session agrees with run(), job for job", "[pipeline][session]") {
    // A Session exists only to avoid rebuilding substrate per job. If it ever
    // disagreed with run() it would be a different tool wearing the same name,
    // and the disagreement would show up as a durability result rather than as
    // a bug.
    const PipeImage p = make_pipe_image();
    const generate::Image img = view(p);
    const std::string once = std::string("str \"") + kOnce + "\"";

    const std::vector<std::string> jobs{
        once + " -> xref",
        once + " -> xref -> func",
        once + " -> xref -> func -> unique",
        "str \"no such string anywhere\" -> xref",
        "bytes \"48 8D 0D\" -> limit 3",
        once + " -> xref -> nth 0",
        "this is not a pipeline",
    };

    pipeline::Session s(img);
    s.preload_string_targets();
    for (const std::string& j : jobs) {
        const auto a = pipeline::run(img, j);
        const auto b = s.run(j);
        INFO("job: " << j);
        REQUIRE(a.ok == b.ok);
        REQUIRE(a.addresses == b.addresses);
        REQUIRE(a.failed_stage == b.failed_stage);
        REQUIRE(a.error == b.error);
    }

    // The fixture is only meaningful if some job actually resolves; otherwise
    // this compares two empty results seven times.
    REQUIRE(pipeline::run(img, jobs[0]).ok);
}

TEST_CASE("Session survives a temporary Image", "[pipeline][session]") {
    // `Session s(img.view())` is the natural call, and view() returns a
    // temporary. Holding it by reference made that dangle -- it segfaulted
    // rather than reading freed memory, which was luck. Image is four spans
    // over storage the caller owns, so the Session copies it.
    const PipeImage p = make_pipe_image();
    pipeline::Session s(view(p));          // temporary dies right here
    s.preload_string_targets();
    const auto r = s.run(std::string("str \"") + kOnce + "\" -> xref");
    REQUIRE(r.ok);
    REQUIRE(r.addresses.size() == 1);
}

TEST_CASE("func reports that it REPLACED a mid-function address",
          "[pipeline][func]") {
    // A pipeline ending in `func` can only ever answer with a function ENTRY.
    // Given a target that sits mid-function it returns the enclosing entry and
    // reports OK -- a category error, not a miss, and silent. Downstream this
    // produced three targets at entry+0xc0, +0xaf and +0xe0 all resolving
    // "successfully" to one address, none of them a function start.
    //
    // `moved` is how a caller sees it: on a `func` stage it counts addresses
    // that were REPLACED rather than merely located.
    const PipeImage p = make_pipe_image();
    const generate::Image img = view(p);

    // Entry in, entry out: nothing was replaced.
    const auto at_entry = pipeline::run(img,
        "bytes \"" + generate::hex_bytes(p.bytes.data() + p.fn_once, 8) + "\" -> func");
    REQUIRE(at_entry.ok);
    REQUIRE(at_entry.trace.back().stage == "func");
    REQUIRE(at_entry.trace.back().moved == 0);

    // Mid-function in: `func` still answers, and says the address moved.
    const auto mid = pipeline::run(img,
        "bytes \"" + generate::hex_bytes(p.bytes.data() + p.ref_once, 8) + "\" -> func");
    REQUIRE(mid.ok);
    REQUIRE(mid.addresses.size() == 1);
    REQUIRE(mid.addresses[0] == p.fn_once);       // the entry, not what we asked
    REQUIRE(mid.trace.back().moved == 1);         // and it says so

    // The fixture is only meaningful if those two addresses really differ;
    // otherwise both cases are the same case.
    REQUIRE(p.ref_once != p.fn_once);
}

// ── find: the pattern is matched INSIDE the enclosing function ─────────

TEST_CASE("find scopes the search to the enclosing function", "[pipeline][find]") {
    // The whole point. `F7 80 58` is three bytes; image-wide it matches
    // hundreds of times, so `bytes "F7 80 58"` is useless as a locator. The
    // same three bytes inside fn_once match exactly once, because the set
    // arriving at `find` has already been narrowed to that one function.
    //
    // Measured downstream over 71 targets, the minimal unique byte prefix is
    // a median of 14 bytes image-wide against 3 bytes within the function --
    // which is the 4.7x this stage buys.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult wide = pipeline::run(img, "bytes \"F7 80 58\"");
    REQUIRE(wide.ok);
    REQUIRE(wide.addresses.size() > 200);   // hopeless image-wide

    const pipeline::PipelineResult scoped = pipeline::run(img,
        "str " + q(kOnce) + " -> xref -> func -> find \"F7 80 58\"");
    REQUIRE(scoped.ok);
    REQUIRE(scoped.addresses == std::vector<uint64_t>{ p.field_site });
    REQUIRE(scoped.kind == pipeline::ResultKind::Address);
    REQUIRE(scoped.trace.size() == 4);
    REQUIRE(scoped.trace[3].stage == "find \"F7 80 58\"");
    REQUIRE(scoped.trace[3].in == 1);
    REQUIRE(scoped.trace[3].out == 1);

    // Not merely "inside SOME function": the identical prefix sits inside a
    // caller function too, and scoping to fn_once excludes it.
    REQUIRE(generate::enclosing_func(img, p.field_other) != nullptr);
    REQUIRE(std::find(scoped.addresses.begin(), scoped.addresses.end(),
                p.field_other) == scoped.addresses.end());

    // `bytes` is unchanged and still image-wide -- the two stages are not
    // variants of each other, and an existing chain keeps its meaning.
    REQUIRE(pipeline::run(img, "bytes \"F7 80 58\"").addresses.size() ==
            wide.addresses.size());
}

TEST_CASE("find searches every scope in the incoming set", "[pipeline][find]") {
    // Two input addresses in two different functions, each holding one match:
    // `find` is a filter over the whole set, not over its first member.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r = pipeline::run(img,
        "str " + q(kTwice) + " -> xref -> func -> find \"F7 80 58\"");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == p.field_sites_twice);
    REQUIRE(r.trace.back().in == 2);
    REQUIRE(r.trace.back().out == 2);
}

TEST_CASE("find emits the capture when the pattern has one", "[pipeline][find]") {
    // save_index 1 when the pattern contains a `'`, 0 otherwise. Here the
    // capture lands on the disp32, two bytes past the match.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    const std::string base = "str " + q(kOnce) + " -> xref -> func -> find ";

    const pipeline::PipelineResult captured =
        pipeline::run(img, base + "\"F7 80 ' ? ? 00 00\"");
    REQUIRE(captured.ok);
    REQUIRE(captured.addresses == std::vector<uint64_t>{ p.field_disp_at });

    // The same pattern without the `'` reports the match offset instead, and
    // the two differ -- otherwise this test would pass either way.
    const pipeline::PipelineResult plain =
        pipeline::run(img, base + "\"F7 80 ? ? 00 00\"");
    REQUIRE(plain.addresses == std::vector<uint64_t>{ p.field_site });
    REQUIRE(p.field_disp_at != p.field_site);
}

TEST_CASE("find with no funcs says so rather than answering empty",
    "[pipeline][find][R4]") {
    // R4 again: "not configured" and "not found" must stay distinguishable.
    // `find` has no scope at all without `funcs`, and an empty answer would
    // read as "the pattern is not in the function".
    const PipeImage p = make_pipe_image(0);

    const pipeline::PipelineResult r = pipeline::run(view_no_funcs(p),
        "bytes \"55 48 89 E5 41 57 41 56\" -> find \"F7 80 58\"");
    REQUIRE(pipeline::failed(r));
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.failed_stage == 1);
    REQUIRE(r.error.find("find:") == 0);
    REQUIRE(r.error.find("funcs") != std::string::npos);
    REQUIRE(r.addresses.empty());
}

TEST_CASE("find skips an address with no enclosing function", "[pipeline][find]") {
    // Not an error: `funcs` IS configured, so an address outside every one of
    // them genuinely has no scope -- the same ruling `func` follows.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    const pipeline::PipelineResult r =
        pipeline::run(img, "str " + q(kOnce) + " -> find \"F7 80 58\"");
    REQUIRE_FALSE(r.ok);
    REQUIRE_FALSE(pipeline::failed(r));
    REQUIRE(r.addresses.empty());
    REQUIRE(r.trace.back().in == 1);
    REQUIRE(r.trace.back().out == 0);

    // A pattern that is genuinely absent from the scope is also empty, and
    // also not an error.
    const pipeline::PipelineResult absent = pipeline::run(img,
        "str " + q(kOnce) + " -> xref -> func -> find \"0F 0B 0F 0B 0F 0B 0F 0B\"");
    REQUIRE_FALSE(absent.ok);
    REQUIRE_FALSE(pipeline::failed(absent));
}

TEST_CASE("a bad pattern in find is a result, not an exception", "[pipeline][find]") {
    const PipeImage p = make_pipe_image(0);
    const pipeline::PipelineResult r = pipeline::run(view(p),
        "str " + q(kOnce) + " -> xref -> func -> find \"48 (8B\"");
    REQUIRE(pipeline::failed(r));
    REQUIRE(r.failed_stage == 3);
    REQUIRE(r.error.find("find:") == 0);
}

TEST_CASE("find is not a seed, and cannot start a pipeline", "[pipeline][find][parse]") {
    const pipeline::Program first = pipeline::parse("find \"F7 80 58\" -> func");
    REQUIRE_FALSE(first.ok);
    REQUIRE(first.failed_stage == 0);

    // But it IS allowed more than once, and in the middle: it is a filter.
    const pipeline::Program mid =
        pipeline::parse("str \"x\" -> xref -> func -> find \"F7 80\" -> find \"58\"");
    REQUIRE(mid.ok);
    REQUIRE(mid.stages.size() == 5);
    REQUIRE(mid.stages[3].op == Op::Find);
    REQUIRE(mid.stages[3].text == "F7 80");
    REQUIRE(mid.stages[3].repr == "find \"F7 80\"");
}

// ── read: the terminal stage, and the values it yields ────────────────

TEST_CASE("read loads N little-endian bytes", "[pipeline][read]") {
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    const std::string to_disp =
        "str " + q(kOnce) + " -> xref -> func -> find \"F7 80 ' ? ? 00 00\"";

    // The chain the whole feature exists for: a structure field offset,
    // reached with seven bytes of context.
    const pipeline::PipelineResult four = pipeline::run(img, to_disp + " -> read 4");
    REQUIRE(four.ok);
    REQUIRE(four.addresses == std::vector<uint64_t>{ kFieldOffset });
    REQUIRE(four.kind == pipeline::ResultKind::Value);

    // Little-endian, and every width: the same address read 1, 2, 4 and 8
    // bytes wide gives the successive truncations of the same number.
    const uint64_t at = p.field_disp_at;
    uint64_t expect8 = 0;
    for (int k = 0; k < 8; ++k)
        expect8 |= (uint64_t)p.bytes[at + k] << (8 * k);
    REQUIRE(pipeline::run(img, to_disp + " -> read 1").addresses ==
        std::vector<uint64_t>{ expect8 & 0xFF });
    REQUIRE(pipeline::run(img, to_disp + " -> read 2").addresses ==
        std::vector<uint64_t>{ expect8 & 0xFFFF });
    REQUIRE(pipeline::run(img, to_disp + " -> read 4").addresses ==
        std::vector<uint64_t>{ expect8 & 0xFFFFFFFF });
    REQUIRE(pipeline::run(img, to_disp + " -> read 8").addresses ==
        std::vector<uint64_t>{ expect8 });

    // Big-endian would give a different number for every width but 1, which
    // is what makes the four assertions above load-bearing.
    REQUIRE((expect8 & 0xFFFF) != 0);
    REQUIRE((expect8 & 0xFF) != ((expect8 >> 8) & 0xFF));
}

TEST_CASE("read past the end of the image drops the address", "[pipeline][read]") {
    // R10: DROPPED, not truncated. Half a displacement is not a smaller
    // displacement, it is a different number, and a zero-padded one would be
    // indistinguishable from a field at offset 0.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    REQUIRE(p.tail + 4 == p.bytes.size());

    const pipeline::PipelineResult marker = pipeline::run(img, "bytes \"C7 3D 9A 5E\"");
    REQUIRE(marker.addresses == std::vector<uint64_t>{ p.tail });

    const pipeline::PipelineResult four =
        pipeline::run(img, "bytes \"C7 3D 9A 5E\" -> read 4");
    REQUIRE(four.ok);
    REQUIRE(four.addresses == std::vector<uint64_t>{ 0x5E9A3DC7ull });

    const pipeline::PipelineResult eight =
        pipeline::run(img, "bytes \"C7 3D 9A 5E\" -> read 8");
    REQUIRE_FALSE(eight.ok);
    REQUIRE_FALSE(pipeline::failed(eight)); // empty is not an error
    REQUIRE(eight.addresses.empty());
    REQUIRE(eight.kind == pipeline::ResultKind::Value);
    REQUIRE(eight.trace.back().in == 1);
    REQUIRE(eight.trace.back().out == 0);
}

TEST_CASE("read yields values, sorted and deduplicated", "[pipeline][read]") {
    // The same displacement in two different functions: two addresses in,
    // ONE value out. Documented in pipeline.hpp -- values go through the
    // same sort_unique as addresses, so N addresses can yield fewer than N
    // values.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);
    const std::string base =
        "str " + q(kTwice) + " -> xref -> func -> find \"F7 80 ' ? ? 00 00\"";

    const pipeline::PipelineResult addrs = pipeline::run(img, base);
    REQUIRE(addrs.addresses.size() == 2);
    REQUIRE(addrs.kind == pipeline::ResultKind::Address);

    const pipeline::PipelineResult vals = pipeline::run(img, base + " -> read 4");
    REQUIRE(vals.ok);
    REQUIRE(vals.addresses == std::vector<uint64_t>{ kFieldOffset });
    REQUIRE(vals.kind == pipeline::ResultKind::Value);
    REQUIRE(vals.trace.back().in == 2);
    REQUIRE(vals.trace.back().out == 1);

    // And a DIFFERENT displacement reads back differently: otherwise the
    // collapse above would be indistinguishable from `read` dropping one,
    // or from every read returning the same constant.
    const pipeline::PipelineResult other = pipeline::run(img,
        "bytes \"55 48 89 E5 41 57 41 56\" -> callers -> func"
        " -> find \"F7 80 ' ? ? 00 00\" -> read 4");
    REQUIRE(other.ok);
    REQUIRE(other.addresses == std::vector<uint64_t>{ kOtherOffset });
    REQUIRE(kOtherOffset != kFieldOffset);
}

TEST_CASE("kind is Address unless read ran", "[pipeline][read]") {
    // Without this a consumer cannot tell a field displacement from an RVA,
    // and dereferencing the former is silent garbage.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    REQUIRE(pipeline::PipelineResult{}.kind == pipeline::ResultKind::Address);
    REQUIRE(pipeline::run(img, "str " + q(kOnce)).kind ==
        pipeline::ResultKind::Address);
    REQUIRE(pipeline::run(img, "str " + q(kOnce) + " -> xref -> func").kind ==
        pipeline::ResultKind::Address);
    REQUIRE(pipeline::run(img, "str \"NoSuchStringHere\"").kind ==
        pipeline::ResultKind::Address);
    REQUIRE(pipeline::run(img, "bytes \"C7 3D 9A 5E\" -> read 2").kind ==
        pipeline::ResultKind::Value);
}

TEST_CASE("read is terminal: a stage after it is a parse error",
    "[pipeline][read][parse]") {
    // Enforced in the PARSER, not at run time: a following `xref` or `func`
    // would take a structure field displacement for an RVA and answer
    // confidently from an unrelated part of the image. A jobfile carrying
    // that mistake is rejected before any image is touched.
    const PipeImage p = make_pipe_image(0);
    const generate::Image img = view(p);

    for (const char* tail : { "xref", "func", "callers", "unique", "nth 0",
             "limit 1", "read 4", "find \"90\"" }) {
        const std::string src =
            "str " + q(kOnce) + " -> read 4 -> " + tail;
        INFO("tail: " << tail);
        const pipeline::Program prog = pipeline::parse(src);
        REQUIRE_FALSE(prog.ok);
        REQUIRE(prog.failed_stage == 2);
        REQUIRE(prog.error.find("read 4") != std::string::npos);

        // And the same through run(), which is where a caller meets it.
        const pipeline::PipelineResult r = pipeline::run(img, src);
        REQUIRE(pipeline::failed(r));
        REQUIRE(r.failed_stage == 2);
        REQUIRE(r.trace.empty());
    }

    // Ending in `read` is of course fine.
    REQUIRE(pipeline::parse("str \"x\" -> read 4").ok);
}

TEST_CASE("read takes a width of 1, 2, 4 or 8 only", "[pipeline][read][parse]") {
    // A `read 3` has no little-endian meaning a caller and this code would
    // agree on, and rounding it up to 4 would read a byte the pattern never
    // claimed.
    for (const char* bad : { "read 0", "read 3", "read 5", "read 6", "read 7",
             "read 9", "read 16", "read", "read x" }) {
        const std::string src = std::string("str \"x\" -> ") + bad;
        INFO("stage: " << bad);
        const pipeline::Program prog = pipeline::parse(src);
        REQUIRE_FALSE(prog.ok);
        REQUIRE(prog.failed_stage == 1);
    }
    for (const char* good : { "read 1", "read 2", "read 4", "read 8" }) {
        const pipeline::Program prog =
            pipeline::parse(std::string("str \"x\" -> ") + good);
        INFO("stage: " << good);
        REQUIRE(prog.ok);
        REQUIRE(prog.stages[1].op == Op::Read);
        REQUIRE(prog.stages[1].repr == std::string(good));
    }
}

TEST_CASE("the find/read chain holds in an independently built image",
    "[pipeline][find][read][structural]") {
    // The same TEXT, a second image whose decoys and addresses differ. Not a
    // durability claim -- these two images are one generator apart, not one
    // compiler apart -- only evidence that neither stage reads a baked-in
    // address.
    const PipeImage b = make_pipe_image(1);
    const pipeline::PipelineResult r = pipeline::run(view(b),
        "str " + q(kOnce) + " -> xref -> func -> find \"F7 80 ' ? ? 00 00\""
        " -> read 4");
    REQUIRE(r.ok);
    REQUIRE(r.addresses == std::vector<uint64_t>{ kFieldOffset });
    REQUIRE(r.kind == pipeline::ResultKind::Value);
}

TEST_CASE("Session agrees with run() on find and read", "[pipeline][session]") {
    const PipeImage p = make_pipe_image();
    const generate::Image img = view(p);
    const std::string once = "str " + q(kOnce) + " -> xref -> func";

    const std::vector<std::string> jobs{
        once + " -> find \"F7 80 58\"",
        once + " -> find \"F7 80 ' ? ? 00 00\" -> read 4",
        once + " -> find \"F7 80 ' ? ? 00 00\" -> read 8",
        once + " -> find \"0F 0B 0F 0B\"",
        once + " -> read 4 -> xref",
        "bytes \"C7 3D 9A 5E\" -> read 8",
    };
    pipeline::Session s(img);
    s.preload_string_targets();
    for (const std::string& j : jobs) {
        const auto a = pipeline::run(img, j);
        const auto b = s.run(j);
        INFO("job: " << j);
        REQUIRE(a.ok == b.ok);
        REQUIRE(a.addresses == b.addresses);
        REQUIRE(a.kind == b.kind);
        REQUIRE(a.failed_stage == b.failed_stage);
        REQUIRE(a.error == b.error);
    }
    REQUIRE(pipeline::run(img, jobs[1]).ok);
}

TEST_CASE("func:strict fails when it would replace a mid-function address",
          "[pipeline][func]") {
    // The property is the TRANSITION, not the address set. An `entry` filter
    // placed after `func` can never reject anything -- by then every address
    // is a function start by construction -- which is why this is a modifier
    // on `func` rather than a stage of its own.
    //
    // Strictness is per-use: for a target that IS a function entry,
    // `func:strict` asserts that assumption; for a mid-function target, moving
    // is correct and plain `func` is right. Both are exercised here.
    const PipeImage p = make_pipe_image();
    const generate::Image img = view(p);
    const std::string entry_pat =
        "bytes \"" + generate::hex_bytes(p.bytes.data() + p.fn_once, 8) + "\"";
    const std::string mid_pat =
        "bytes \"" + generate::hex_bytes(p.bytes.data() + p.ref_once, 8) + "\"";

    // Entry in: nothing moved, so strict and plain agree.
    const auto strict_ok = pipeline::run(img, entry_pat + " -> func:strict");
    const auto plain_ok = pipeline::run(img, entry_pat + " -> func");
    REQUIRE(strict_ok.ok);
    REQUIRE(strict_ok.addresses == plain_ok.addresses);
    REQUIRE(strict_ok.trace.back().stage == "func:strict"); // and it says which it was

    // Mid-function in: plain succeeds (correctly), strict refuses.
    const auto plain_mid = pipeline::run(img, mid_pat + " -> func");
    REQUIRE(plain_mid.ok);
    REQUIRE(plain_mid.addresses == std::vector<uint64_t>{ p.fn_once });

    const auto strict_mid = pipeline::run(img, mid_pat + " -> func:strict");
    REQUIRE_FALSE(strict_mid.ok);
    REQUIRE(strict_mid.failed_stage == 1);
    REQUIRE(strict_mid.error.find("func:strict") != std::string::npos);

    // The trace still records the stage that rejected, and by how much --
    // an error naming a stage the caller cannot see is not much of an error.
    REQUIRE(strict_mid.trace.size() == 2);
    REQUIRE(strict_mid.trace.back().stage == "func:strict");
    REQUIRE(strict_mid.trace.back().moved == 1);

    // The fixture is only meaningful if the two addresses really differ.
    REQUIRE(p.ref_once != p.fn_once);
}

TEST_CASE("modifiers attach with a colon, and only where they mean something",
          "[pipeline][func]") {
    // `func:strict` -- a QUALIFIER on the stage, read the way CSS reads
    // `a:hover`. The three rejected spellings each cost something this one
    // does not: `func | strict` borrows the pattern dialect's alternation bar
    // AND needs `|` to bind tighter than `->`, a precedence rule nothing on
    // the line states; `strict(func)` needs no such rule but reads inside-out
    // in a left-to-right pipeline and borrows the dialect's group parens just
    // as much; `func!` reads as negation, the opposite of what it asserts.
    // The colon needs no precedence rule because it takes no whitespace.
    const PipeImage p = make_pipe_image();
    const generate::Image img = view(p);
    const std::string mid =
        "bytes \"" + generate::hex_bytes(p.bytes.data() + p.ref_once, 8) + "\"";
    const std::string entry =
        "bytes \"" + generate::hex_bytes(p.bytes.data() + p.fn_once, 8) + "\"";

    // strict rejects a replacement; loose and bare func accept it.
    REQUIRE_FALSE(pipeline::run(img, mid + " -> func:strict").ok);
    REQUIRE(pipeline::run(img, mid + " -> func:loose").ok);
    REQUIRE(pipeline::run(img, mid + " -> func").ok);
    REQUIRE(pipeline::run(img, mid + " -> func:loose").addresses
            == pipeline::run(img, mid + " -> func").addresses);

    // strict is a no-op where nothing moved -- without this, a modifier that
    // always failed would satisfy the assertions above.
    REQUIRE(pipeline::run(img, entry + " -> func:strict").ok);

    // Applied to a stage with no located-vs-replaced distinction, it is a
    // parse error rather than silently doing nothing.
    const auto wrong = pipeline::run(img, mid + " -> xref:strict");
    REQUIRE_FALSE(wrong.ok);
    REQUIRE(wrong.error.find("apply to `func` only") != std::string::npos);

    // The unknown STAGE is reported ahead of the modifier: `bogus:strict` is
    // a misspelled stage, and saying "modifiers apply to func only" would
    // point at the wrong half of the expression.
    const auto bogus = pipeline::run(img, mid + " -> bogus:strict");
    REQUIRE_FALSE(bogus.ok);
    REQUIRE(bogus.error.find("unknown stage") != std::string::npos);

    // An unknown modifier is named as such, not silently ignored.
    const auto unk = pipeline::run(img, mid + " -> func:neg");
    REQUIRE_FALSE(unk.ok);
    REQUIRE(unk.error.find("unknown modifier") != std::string::npos);

    // The colon takes no whitespace -- that is what makes `func:strict ->
    // unique` scan as two stages rather than three. A spaced colon is
    // rejected with a message about the spacing, not a bare "expected '->'".
    const auto spaced = pipeline::run(img, mid + " -> func :strict");
    REQUIRE_FALSE(spaced.ok);
    REQUIRE(spaced.error.find("no spaces") != std::string::npos);
    REQUIRE_FALSE(pipeline::run(img, mid + " -> func : strict").ok);

    // The rejected spellings stay rejected.
    REQUIRE_FALSE(pipeline::run(img, mid + " -> strict(func)").ok);
    REQUIRE_FALSE(pipeline::run(img, mid + " -> func | strict").ok);
    REQUIRE_FALSE(pipeline::run(img, mid + " -> func!").ok);
    REQUIRE_FALSE(pipeline::run(img, mid + " -> func strict").ok);
    REQUIRE_FALSE(pipeline::run(img, mid + " -> func:").ok);

    // The trace names the modified form, so a reader of --trace or the batch
    // stage column sees which one ran.
    const auto t = pipeline::run(img, mid + " -> func:strict");
    REQUIRE(t.trace.back().stage == "func:strict");

    REQUIRE(p.ref_once != p.fn_once);
}
