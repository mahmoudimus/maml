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
    const std::array<maml::generate::Function, 1> fa{ { { 64, {{64, 73}} } } }, fb{ { { 96, {{96, 105}} } } };
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
    const std::array<maml::generate::Function, 1> functions{ { { 0, {{0, 2}} } } };
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
    const std::array<maml::generate::Function, 2> functions{ { { 0, {{0, 6}} }, { 6, {{6, 7}} } } };
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
    std::copy(name.begin(), name.end(), bytes.begin()+16);
    auto store = [&](size_t at, uint64_t value) {
        for (int k=0;k<8;++k) bytes[at+k] = uint8_t(value >> (8*k));
    };
    constexpr uint64_t base = 0x140000000;
    store(48,base+16); store(56,base+96);
    v1::Image image{bytes,base,{{base+16,base+16},{base+96,base+96}}};
    std::array<generate::Range,1> rodata{{{16,32}}}, data{{{48,64}}};
    std::array<generate::Function,1> functions{{{96,{{96,112}}}}};
    auto query = v1::PipelineBuilder().str(name).ptrrefs().unique().offset(8).read_ptr().func(v1::FunctionMode::Strict).unique().build();
    auto result = query.run(image,{},rodata,functions,{},data);
    REQUIRE(result.values.size()==1);
    REQUIRE(result.values[0].value==base+96);
    REQUIRE(result.trace[1].candidates==18);
    REQUIRE(result.trace[1].mapped==2);
    REQUIRE(result.trace[1].out==1);
    image.pointer_map.erase(base+96);
    REQUIRE_THROWS_AS(query.run(image,{},rodata,functions,{},data), v1::Error);
    REQUIRE_THROWS_AS(v1::Pipeline("str(\"PitchUpStart\") -> offset(-17)").run(image,{},rodata), v1::Error);
}
