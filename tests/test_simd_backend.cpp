// A vector backend must actually be compiled in.
//
// detail::scan_literal keeps a memchr path that runs when no vector path was
// selected, and it is CORRECT -- it just costs about 1.9x. So a build where
// the preprocessor block in mamlscan.hpp falls through stays green through every
// other test in this suite while silently shipping the slow scan. Nothing else
// here would notice, which is precisely why this file exists.
//
// The measurement the fallback would erase, over a 133MB image: 243.17 ms
// (Boyer-Moore) -> 9.40 ms (memchr) -> 4.99 ms (NEON).
#include "maml/mamlscan.hpp"
#include <catch.hpp>

TEST_CASE("a vector backend is compiled in on every 64-bit target", "[simd]") {
#if defined(MAML_SIMD_NEON)
    SUCCEED("NEON");
#elif defined(MAML_SIMD_SSE2)
    SUCCEED("SSE2");
#elif defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
    FAIL("64-bit target with no vector backend selected -- the scan fell back "
         "to scalar memchr and the SIMD prefilter is not in this build");
#else
    // 32-bit and other targets legitimately have no vector path here; the
    // SSE2 branch is guarded on __x86_64__/_M_X64 for exactly that reason.
    SUCCEED("no vector backend expected on this target");
#endif
}

// Names the backend in the test log. ctest --output-on-failure hides this on a
// green run, so CI greps the binary's own output instead -- but when a
// platform's result is surprising, the answer is already in the log.
TEST_CASE("report the compiled backend", "[simd]") {
#if defined(MAML_SIMD_NEON)
    WARN("maml SIMD backend: neon");
#elif defined(MAML_SIMD_SSE2)
    WARN("maml SIMD backend: sse2");
#else
    WARN("maml SIMD backend: scalar");
#endif
    SUCCEED();
}
