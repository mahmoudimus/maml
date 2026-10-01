#include <array>
#include <catch.hpp>
#include <maml/v1_generate.hpp>
#include <maml/v1_pipeline.hpp>
#include <random>

TEST_CASE("v1 preserves reference values and continuation", "[v1]") {
    const std::array<uint8_t, 7> bytes{ 0xE8, 1, 0, 0, 0, 0x90, 0xCC };
    maml::v1::Image image{ bytes };
    const auto a = maml::v1::Pattern("E8 rel32(x) 90").find(image);
    REQUIRE(a);
    REQUIRE(a->offset == 0);
    REQUIRE(a->capture("x")->value == 6);
    REQUIRE(a->capture("x")->kind == "ResolvedRelativeTarget");
    REQUIRE(maml::v1::Pattern("E8 rel32(x):follow CC").match_at(image, 0));
    REQUIRE_THROWS_AS(a->capture("typo"), maml::v1::Error);
}

TEST_CASE("v1 capture rollback covers failed branches and gap retries", "[v1]") {
    const std::array<uint8_t, 4> bytes{ 0xAA, 0xBB, 0xCC, 0xDD };
    maml::v1::Image image{ bytes };
    auto match = maml::v1::Pattern("AA (BB @(bad) EE | BB @(good) CC)").find(image);
    REQUIRE(match);
    REQUIRE_FALSE(match->capture("bad"));
    REQUIRE(match->capture("good")->value == 2);
    auto gap = maml::v1::Pattern("AA [0..2] @(here) DD").find(image);
    REQUIRE(gap->capture("here")->value == 3);
}

TEST_CASE("v1 checked arithmetic and explicit pointer mapping", "[v1]") {
    const std::array<uint8_t, 9> bytes{ 8, 0, 0, 0, 0, 0, 0, 0, 0xCC };
    maml::v1::Image image{ bytes };
    auto pointer = maml::v1::Pattern("ptr64(p)").match_at(image, 0);
    REQUIRE(pointer->capture("p")->value == 8);
    REQUIRE_FALSE(maml::v1::Pattern("ptr64(p):follow CC").match_at(image, 0));
    image.pointer_map[8] = 8;
    REQUIRE(maml::v1::Pattern("ptr64(p):follow CC").match_at(image, 0));
    image.base = UINT64_MAX;
    REQUIRE_FALSE(maml::v1::Pattern("rel8(p)").match_at(image, 0));
    REQUIRE_THROWS_AS(maml::v1::Reference(maml::v1::Encoding::AbsolutePointer64LE, 1), maml::v1::Error);
    REQUIRE_THROWS_AS(maml::v1::Reference(static_cast<maml::v1::Encoding>(99)), maml::v1::Error);
}

TEST_CASE("v1 pipeline distinguishes matches from projected targets", "[v1]") {
    const std::array<uint8_t, 11> bytes{ 0xE8, 5, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xCC };
    maml::v1::Image image{ bytes };
    auto result = maml::v1::Pipeline("bytes(\"E8 rel32(x)\") -> capture(\"x\") -> unique").run(image);
    REQUIRE(result.values.size() == 1);
    REQUIRE(result.values[0].value == 10);
    REQUIRE_THROWS_AS(maml::v1::Pipeline("bytes(\"E8 rel32(x)\") -> unique").run(image), maml::v1::Error);
    REQUIRE_THROWS_AS(maml::v1::Pipeline("bytes(\"FF @(x)\") -> capture(\"typo\")"), maml::v1::Error);
}

TEST_CASE("v1 seeded execution agrees with exhaustive search", "[v1]") {
    std::mt19937 rng(42);
    for (auto text : { "AA ?? BB", "AA [0..3] @(x) CC", "AA rel8(x):follow CC", "AA rel8(x) BB", "(AA | BB) @(x)" }) {
        const maml::v1::Pattern pattern(text);
        for (size_t trial = 0; trial < 50; ++trial) {
            std::array<uint8_t, 64> bytes;
            for (auto& byte : bytes)
                byte = std::array<uint8_t, 6>{ 0xAA, 0xBB, 0xCC, 0, 1, 0xFF }[rng() % 6];
            const maml::v1::Image image{ bytes };
            REQUIRE(pattern.find_all(image) == pattern.find_all(image, 0, true));
        }
    }
}

TEST_CASE("v1 generator emits and verifies nibble masks", "[v1][generate]") {
    using namespace maml::v1;
    std::array<uint8_t, 128> a, b;
    a.fill(0xCC);
    b.fill(0xCC);
    const std::array<uint8_t, 9> calla{ 0xE8, 0xDB, 0xFF, 0xFF, 0xFF, 0x4C, 0x8B, 0xD1, 0x48 };
    const std::array<uint8_t, 9> callb{ 0xE8, 0xCB, 0xFF, 0xFF, 0xFF, 0x4C, 0x8B, 0xD7, 0x48 };
    std::copy(calla.begin(), calla.end(), a.begin() + 64);
    std::copy(callb.begin(), callb.end(), b.begin() + 96);
    const std::array<maml::generate::Range, 1> code{ { { 0, 128 } } };
    const std::array<maml::generate::Function, 1> fa{ { { 64, { { 64, 73 } } } } }, fb{ { { 96, { { 96, 105 } } } } };
    maml::v1::generate::Options options;
    options.prefer_short = false;
    const auto candidates = maml::v1::generate::verified({ a, code, {}, fa }, 32, { b, code, {}, fb }, 48, options);
    auto found = std::find_if(candidates.begin(), candidates.end(), [](const auto& c) {
        return c.pattern.find("D?") != std::string::npos;
    });
    REQUIRE(found != candidates.end());
    REQUIRE(found->target_capture == "target");
    REQUIRE(found->dialect == "maml-v1");
    REQUIRE(maml::v1::generate::resolve_consensus(a, { *found })[0].address == 32);
    REQUIRE(maml::v1::generate::resolve_consensus(b, { *found })[0].address == 48);
}

TEST_CASE("v1 strict function mapping checks each input", "[v1][pipeline]") {
    const std::array<uint8_t, 3> bytes{ 0xAA, 0xAA, 0xBB };
    const maml::v1::Image image{ bytes, 0x1000 };
    const std::array<maml::generate::Function, 1> functions{ { { 0, { { 0, 2 } } } } };
    auto loose = maml::v1::Pipeline("bytes(\"AA\") -> func:loose").run(image, {}, {}, functions);
    REQUIRE(loose.values.size() == 1);
    REQUIRE(loose.values[0].value == 0x1000);
    REQUIRE(loose.trace.back().stage == "func:loose");
    REQUIRE_THROWS_AS(maml::v1::Pipeline("bytes(\"AA\") -> func:strict").run(image, {}, {}, functions), maml::v1::Error);
    REQUIRE_THROWS_AS(maml::v1::Pipeline("bytes(\"BB\") -> func:strict").run(image, {}, {}, functions), maml::v1::Error);
    auto strict = maml::v1::Pipeline("bytes(\"AA AA\") -> func:strict").run(image, {}, {}, functions);
    REQUIRE(strict.values[0].value == 0x1000);
    REQUIRE(strict.trace.back().stage == "func:strict");
    REQUIRE_THROWS_AS(maml::v1::Pipeline("bytes(\"AA\") -> func:strict:loose"), maml::v1::Error);
}

TEST_CASE("v1 pipeline builder shares parsing and preserves prefixes", "[v1][pipeline]") {
    using namespace maml::v1;
    const std::array<uint8_t, 7> data{ 0xE8, 1, 0, 0, 0, 0x90, 0xCC };
    const Image image{ data };
    const std::array<maml::generate::Function, 2> functions{ { { 0, { { 0, 6 } } }, { 6, { { 6, 7 } } } } };
    const auto prefix = PipelineBuilder().bytes("E8 rel32(target):follow CC");
    const auto query = prefix.capture("target").func(FunctionMode::Strict).unique();
    REQUIRE(prefix.source() == "bytes(\"E8 rel32(target):follow CC\")");
    const auto result = query.build().run(image, {}, {}, functions);
    const auto text = Pipeline("bytes(\"E8 rel32(target):follow CC\")\n -> capture(\"target\")\n -> func:strict\n -> unique").run(image, {}, {}, functions);
    REQUIRE(result.values.size() == 1);
    REQUIRE(result.values[0].value == text.values[0].value);
    REQUIRE(result.values[0].value == 6);
    REQUIRE_THROWS_AS(prefix.capture("typo").build(), Error);
    REQUIRE_THROWS_AS(prefix.read(3).build(), Error);
    REQUIRE_THROWS_AS(PipelineBuilder().build(), Error);
    REQUIRE_THROWS_AS(prefix.func(static_cast<FunctionMode>(99)), Error);
}

TEST_CASE("v1 pipeline builder quotes strings as data", "[v1][pipeline]") {
    using namespace maml::v1;
    const std::string text = "say \"hello\" -> unique \\ end";
    const auto bytes = std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size() + 1);
    const std::array<maml::generate::Range, 1> rodata{ { { 0, text.size() + 1 } } };
    const auto result = PipelineBuilder().str(text).unique().build().run(Image{ bytes }, {}, rodata);
    REQUIRE(result.values.size() == 1);
    REQUIRE(result.values[0].value == 0);
    REQUIRE(result.trace.size() == 2);
    REQUIRE_NOTHROW(PipelineBuilder().str("\n\t\x01").build());
}

TEST_CASE("v1 directional pipeline windows and builders", "[v1][pipeline]") {
    using namespace maml::v1;
    const std::array<uint8_t, 5> data{ 0xAA, 0x90, 0xCC, 0x90, 0xCC };
    const Image image{ data };
    const std::array<maml::generate::Range, 1> instructions{ { { 0, 2 } } };
    auto before = PipelineBuilder().bytes("CC").before("AA [0..4]", 0).build().run(image);
    REQUIRE(before.matches.size() == 1);
    REQUIRE(before.matches[0].offset == 0);
    auto query = PipelineBuilder().bytes("AA").after("CC", 2).build();
    REQUIRE_THROWS_AS(query.run(image), Error);
    auto after = query.run(image, {}, {}, {}, instructions);
    REQUIRE(after.matches.size() == 2);
    REQUIRE(after.matches[0].offset == 2);
    REQUIRE(after.matches[1].offset == 4);
    REQUIRE_THROWS_AS(Pipeline("bytes(\"AA\") -> before(\"CC\", within=-1)"), Error);
}

TEST_CASE("v1 string contains returns indexed string starts", "[v1][pipeline]") {
    using namespace maml::v1;
    const std::string text = "PrefixNeedleNeedle";
    const Image image{ std::span(reinterpret_cast<const uint8_t*>(text.c_str()), text.size() + 1) };
    const std::array<maml::generate::Range, 1> rodata{ { { 0, text.size() + 1 } } };
    auto result = PipelineBuilder().str("Needle", StringMatch::Contains).build().run(image, {}, rodata);
    REQUIRE(result.values.size() == 1);
    REQUIRE(result.values[0].value == 0);
    REQUIRE_FALSE(PipelineBuilder().str("Needle").build().run(image, {}, rodata).ok());
    REQUIRE_THROWS_AS(PipelineBuilder().str("Needle", static_cast<StringMatch>(99)).build(), Error);
    REQUIRE_FALSE(PipelineBuilder().str("").build().run(image, {}, rodata).ok());
    REQUIRE_THROWS_AS(PipelineBuilder().str("", StringMatch::Contains).build(), Error);
}

TEST_CASE("function spans preserve entries and exclude gaps", "[v1][pipeline]") {
    using namespace maml;
    std::array<uint8_t, 32> bytes{};
    bytes[0] = 0xAA;
    bytes[12] = bytes[24] = 0xBB;
    const std::array<generate::Function, 2> functions{ { { 0, { { 0, 4 }, { 24, 28 } } }, { 8, { { 8, 16 } } } } };
    v1::Image image{ bytes };
    auto result = v1::Pipeline("bytes(\"BB\") -> func").run(image, {}, {}, functions);
    REQUIRE(result.values.size() == 2);
    REQUIRE(result.values[0].value == 0);
    REQUIRE(result.values[1].value == 8);
    result = v1::Pipeline("bytes(\"AA\") -> find(\"BB\")").run(image, {}, {}, functions);
    REQUIRE(result.matches.size() == 1);
    REQUIRE(result.matches[0].offset == 24);
    REQUIRE_THROWS_AS(v1::Pipeline("bytes(\"BB\") -> func:strict").run(image, {}, {}, functions), v1::Error);
    generate::Image indexed{ bytes, {}, {}, functions };
    REQUIRE(generate::clamp_to_func(indexed, 25, 64) == 3);
    REQUIRE(generate::enclosing_function(indexed, 25)->entry == 0);
    REQUIRE_FALSE(generate::enclosing_function(indexed, 20));
    const std::array<generate::Function, 2> invalid{ { { 0, { { 0, 4 } } }, { 2, { { 2, 8 } } } } };
    REQUIRE_THROWS_AS(v1::Pipeline("bytes(\"AA\") -> func").run(image, {}, {}, invalid), v1::Error);
}

TEST_CASE("absolute pointer table traversal uses explicit address mappings", "[v1][pipeline][pointers]") {
    using namespace maml;
    std::vector<uint8_t> bytes(128, 0);
    const std::string name = "PitchUpStart";
    std::copy(name.begin(), name.end(), bytes.begin() + 16);
    auto store = [&](size_t at, uint64_t value) {
        for (int k = 0; k < 8; ++k)
            bytes[at + k] = uint8_t(value >> (8 * k));
    };
    constexpr uint64_t base = 0x140000000;
    store(48, base + 16);
    store(56, base + 96);
    v1::Image image{ bytes, base, { { base + 16, base + 16 }, { base + 96, base + 96 } } };
    std::array<generate::Range, 1> rodata{ { { 16, 32 } } }, data{ { { 48, 64 } } };
    std::array<generate::Function, 1> functions{ { { 96, { { 96, 112 } } } } };
    auto query = v1::PipelineBuilder().str(name).ptrrefs().unique().offset(8).read_ptr().func(v1::FunctionMode::Strict).unique().build();
    auto result = query.run(image, {}, rodata, functions, {}, data);
    REQUIRE(result.values.size() == 1);
    REQUIRE(result.values[0].value == base + 96);
    REQUIRE(result.trace[1].candidates == 18);
    REQUIRE(result.trace[1].mapped == 2);
    REQUIRE(result.trace[1].out == 1);
    image.pointer_map.erase(base + 96);
    REQUIRE_THROWS_AS(query.run(image, {}, rodata, functions, {}, data), v1::Error);
    REQUIRE_THROWS_AS(v1::Pipeline("str(\"PitchUpStart\") -> offset(-17)").run(image, {}, rodata), v1::Error);
}

#if MAML_ENABLE_INSN
TEST_CASE("v1 insn stage matches by access size and captures displacement", "[v1][pipeline][insn]") {
    using namespace maml::v1;
    // movups xmm0,[rcx+0x228]  (16-byte read)
    // movss  xmm0,[rcx+0x111]  (4-byte read)
    // ret
    const std::vector<uint8_t> bytes{
        0x0F, 0x10, 0x81, 0x28, 0x02, 0x00, 0x00, // movups xmm0, [rcx+0x228]
        0xF3, 0x0F, 0x10, 0x81, 0x11, 0x01, 0x00, 0x00, // movss  xmm0, [rcx+0x111]
        0xC3 // ret   (offset 15)
    };
    const Image image{ bytes };
    const std::array<maml::generate::Function, 1> functions{ { { 0, { { 0, bytes.size() } } } } };

    const std::array<maml::generate::Range, 3> instructions{ { { 0, 7 }, { 7, 15 }, { 15, 16 } } };

    // A 16-byte memory read resolves to the movups displacement, not the movss.
    auto r16 = Pipeline("bytes(\"C3\") -> func -> insn(\"read size=16 disp(d)\") -> capture(\"d\") -> unique")
                   .run(image, {}, {}, functions, instructions);
    REQUIRE(r16.ok());
    REQUIRE(r16.values.size() == 1);
    REQUIRE(r16.values[0].value == 0x228);

    // A 4-byte memory read resolves to the movss displacement instead.
    auto r4 = Pipeline("bytes(\"C3\") -> func -> insn(\"read size=4 disp(d)\") -> capture(\"d\") -> unique")
                  .run(image, {}, {}, functions, instructions);
    REQUIRE(r4.ok());
    REQUIRE(r4.values[0].value == 0x111);

    // The size filter is strict: neither read is a 2-byte access.
    auto r2 = Pipeline("bytes(\"C3\") -> func -> insn(\"read size=2 disp(d)\")").run(image, {}, {}, functions, instructions);
    REQUIRE(!r2.ok());

    // Without a size constraint both reads match -- two distinct displacements.
    auto any = Pipeline("bytes(\"C3\") -> func -> insn(\"read disp(d)\") -> capture(\"d\")").run(image, {}, {}, functions, instructions);
    REQUIRE(any.values.size() == 2);

    // A capture is mandatory; a sizeless/captureless spec is a parse error.
    REQUIRE_THROWS_AS(Pipeline("bytes(\"C3\") -> func -> insn(\"read size=4\")"), maml::v1::Error);
}

TEST_CASE("v1 insn within=N searches an instruction window and disp_addr captures the encoded field", "[v1][pipeline][insn]") {
    using namespace maml::v1;
    const std::vector<uint8_t> bytes{
        0x8B, 0x81, 0x10, 0x00, 0x00, 0x00, // 0:  mov   eax, [rcx+0x10]
        0xE8, 0x00, 0x00, 0x00, 0x00, // 6:  call  +0           (anchor)
        0xF3, 0x0F, 0x10, 0x81, 0x68, 0x01, 0x00, 0x00, // 11: movss xmm0, [rcx+0x168]
        0x8B, 0x81, 0x64, 0x01, 0x00, 0x00, // 19: mov   eax, [rcx+0x164]
        0xC3 // 25: ret
    };
    const Image image{ bytes };
    const std::array<maml::generate::Function, 1> functions{ { { 0, { { 0, bytes.size() } } } } };

    const std::array<maml::generate::Range, 5> instructions{ { { 0, 6 }, { 6, 11 }, { 11, 19 }, { 19, 25 }, { 25, 26 } } };

    // Whole-function form sees all three 4-byte reads.
    auto whole = Pipeline("bytes(\"C3\") -> insn(\"read size=4 disp(d)\")").run(image, {}, {}, functions, instructions);
    REQUIRE(whole.matches.size() == 3);

    // Cursor form: only instructions starting 0..N bytes from the anchor. The mov
    // at 19 starts 13 bytes after the call, so within=12 stops at the movss.
    auto near = Pipeline("bytes(\"E8 ?? ?? ?? ??\") -> insn(\"read size=4 disp(d)\", within=12) -> capture(\"d\") -> unique")
                    .run(image, {}, {}, functions, instructions);
    REQUIRE(near.values.size() == 1);
    REQUIRE(near.values[0].value == 0x168);

    // within is inclusive: 13 admits the mov at 19, and results stay in address order.
    auto wide = Pipeline("bytes(\"E8 ?? ?? ?? ??\") -> insn(\"read size=4 disp(d)\", within=13)").run(image, {}, {}, functions, instructions);
    REQUIRE(wide.matches.size() == 2);
    REQUIRE(wide.matches[0].offset == 11);
    REQUIRE(wide.matches[1].offset == 19);

    // A window that ends mid-instruction still decodes that instruction whole:
    // within=5 admits only starts 6..11, and the movss at 11 is read in full.
    auto edge = Pipeline("bytes(\"E8 ?? ?? ?? ??\") -> insn(\"read size=4 disp(d)\", within=5) -> capture(\"d\") -> unique")
                    .run(image, {}, {}, functions, instructions);
    REQUIRE(edge.values[0].value == 0x168);

    // The window form needs no function metadata.
    auto bare = Pipeline("bytes(\"E8 ?? ?? ?? ??\") -> insn(\"read size=4 disp(d)\", within=12, decode=\"linear\") -> capture(\"d\")").run(image);
    REQUIRE(bare.values.size() == 1);
    REQUIRE_THROWS_AS(Pipeline("bytes(\"C3\") -> insn(\"read size=4 disp(d)\")").run(image), maml::v1::Error);

    // `cursor` captures where the displacement bytes live, so read(4) recovers
    // the literal: movss is F3 0F 10 81 <disp32>, disp at 11 + 4 = 15.
    auto at = Pipeline("bytes(\"E8 ?? ?? ?? ??\") -> insn(\"read size=4 disp_addr(d)\", within=12) -> capture(\"d\") -> unique")
                  .run(image, {}, {}, functions, instructions);
    REQUIRE(at.values[0].value == 15);
    REQUIRE(at.values[0].kind == "CursorAddress");
    auto literal = Pipeline("bytes(\"E8 ?? ?? ?? ??\") -> insn(\"read size=4 disp_addr(d)\", within=12) -> capture(\"d\") -> read(4)")
                       .run(image, {}, {}, functions, instructions);
    REQUIRE(literal.values[0].value == 0x168);

    // Builder spelling matches the parsed form.
    REQUIRE(PipelineBuilder().bytes("C3").insn("read size=4 disp(d)", 12).source() ==
            "bytes(\"C3\") -> insn(\"read size=4 disp(d)\", within=12)");

    REQUIRE_THROWS_AS(Pipeline("bytes(\"C3\") -> insn(\"read cursor disp_addr(d)\")"), maml::v1::Error);
    REQUIRE_THROWS_AS(Pipeline("bytes(\"C3\") -> insn(\"read disp(d)\", within=)"), maml::v1::Error);
    REQUIRE_THROWS_AS(Pipeline("bytes(\"C3\") -> insn(\"read disp(d)\", span=4)"), maml::v1::Error);
}

TEST_CASE("v1 instruction metadata prevents embedded-opcode matches", "[v1][insn]") {
    using namespace maml;
    const std::vector<uint8_t> bytes{ 0x48, 0xB8, 0x8B, 0x41, 0x20, 0, 0, 0, 0, 0, 0xC3 };
    const v1::Image image{ bytes };
    const std::array<generate::Function, 1> functions{ { { 0, { { 0, 11 } } } } };
    const std::array<generate::Range, 2> instructions{ { { 0, 10 }, { 10, 11 } } };
    REQUIRE(v1::Pipeline("bytes(\"C3\") -> insn(\"read disp(d)\")").run(image, {}, {}, functions, instructions).matches.empty());
    REQUIRE_THROWS_AS(v1::Pipeline("bytes(\"8B 41 20\") -> insn(\"read disp(d)\", within=0)").run(image, {}, {}, functions, instructions), v1::Error);
    REQUIRE_THROWS_AS(v1::Pipeline("bytes(\"C3\") -> insn(\"read disp(d)\")").run(image, {}, {}, functions), v1::Error);
    auto speculative = v1::PipelineBuilder().bytes("8B 41 20").insn("read disp(d)", 0, v1::InstructionDecode::Linear).build();
    REQUIRE(speculative.run(image).matches.size() == 1);
    const std::vector<uint8_t> bad{ 0x06, 0x8B, 0x41, 0x20, 0xC3 };
    REQUIRE(v1::PipelineBuilder().bytes("06").insn("read disp(d)", 100, v1::InstructionDecode::Linear).build().run(v1::Image{ bad }).matches.empty());
}

TEST_CASE("v1 displacement scalars are signed and zero is a field offset", "[v1][insn]") {
    using namespace maml;
    const std::vector<uint8_t> bytes{ 0x8B, 0x41, 0xF8, 0x8B, 0x01, 0xC3 };
    const std::array<generate::Function, 1> functions{ { { 0, { { 0, 6 } } } } };
    const std::array<generate::Range, 3> instructions{ { { 0, 3 }, { 3, 5 }, { 5, 6 } } };
    auto result = v1::Pipeline("bytes(\"C3\") -> insn(\"read disp(d)\")").run(v1::Image{ bytes }, {}, {}, functions, instructions);
    REQUIRE(result.matches.size() == 2);
    REQUIRE(result.matches[0].capture("d")->as_signed() == -8);
    REQUIRE(result.matches[1].capture("d")->as_signed() == 0);
    REQUIRE_THROWS_AS(v1::Value{}.as_signed(), v1::Error);
    auto address = v1::Pipeline("bytes(\"C3\") -> insn(\"read disp_addr(d)\") -> capture(\"d\")").run(v1::Image{ bytes, 0x140000000 }, {}, {}, functions, instructions);
    REQUIRE(address.values.size() == 1);
    REQUIRE(address.values[0].value == 0x140000002);
}

TEST_CASE("v1 instruction filters describe operands rather than object identity", "[v1][insn]") {
    using namespace maml;
    auto push = decode::decode_one(reinterpret_cast<const uint8_t*>("\x50"), 1);
    REQUIRE(push);
    REQUIRE_FALSE(v1::InsnSpec::parse("write disp(d)").matches(*push, push->memory[0]));
    REQUIRE(v1::InsnSpec::parse("write base=stack operand=any disp(d)").matches(*push, push->memory[0]));
    auto movsb = decode::decode_one(reinterpret_cast<const uint8_t*>("\xA4"), 1);
    REQUIRE(movsb->memory.size() == 2);
    auto cmpxchg = decode::decode_one(reinterpret_cast<const uint8_t*>("\x0F\xB1\x41\x20"), 4);
    REQUIRE(v1::InsnSpec::parse("write size=4 disp(d)").matches(*cmpxchg, cmpxchg->memory[0]));
    auto indexed = decode::decode_one(reinterpret_cast<const uint8_t*>("\x8B\x44\x88\x10"), 4);
    REQUIRE_FALSE(v1::InsnSpec::parse("read disp(d)").matches(*indexed, indexed->memory[0]));
    REQUIRE(v1::InsnSpec::parse("read index=rcx base=rax operand=1 mnemonic=mov disp(d)").matches(*indexed, indexed->memory[0]));
    REQUIRE(indexed->memory[0].scale == 4);
    REQUIRE_THROWS_AS(v1::InsnSpec::parse("lea size=4 disp(d)"), v1::Error);
    REQUIRE_THROWS_AS(v1::InsnSpec::parse("read size=4 size=16 disp(d)"), v1::Error);
    REQUIRE_THROWS_AS(v1::InsnSpec::parse("read @(d)"), v1::Error);
}

#else
TEST_CASE("v1 core rejects unavailable instruction stage", "[v1][insn]") {
    REQUIRE_THROWS_AS(maml::v1::Pipeline("bytes(\"C3\") -> insn(\"read disp(d)\")"), maml::v1::Error);
}
#endif
