// Throughput of the literal scan, per platform.
//
// Every performance number this project quotes -- 243.17 -> 67.86 -> 9.40 ->
// 4.99 ms over a 133MB image -- was measured on arm64/NEON. The SSE2 path has
// only ever been proven to COMPILE and to be SELECTED; its throughput on real
// x86 hardware has never been measured, which makes any claim about what a
// wider vector would buy a guess rather than a measurement.
//
// Two cases, because they stress different things:
//
//   rare   -- a needle whose first byte is uncommon. The prefilter rejects
//             almost every window, so this measures the vector loop itself.
//   common -- a needle whose FIRST byte is everywhere but which almost never
//             matches in full. This is the case the header comment credits
//             the two-anchor prefilter for: memchr returns to scalar code on
//             every first-byte hit and collapses to ~1 GB/s, where staying in
//             the vector loop held ~26 GB/s.
//
// Reports the best of several reps: we want the achievable rate, not the
// average of a run that got descheduled.
#include "maml/mamlscan.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

using namespace maml;

static const char* backend() {
#if defined(MAML_SIMD_NEON)
    return "neon";
#elif defined(MAML_SIMD_SSE2)
    return "sse2";
#else
    return "scalar";
#endif
}

// A cheap deterministic PRNG: the same bytes on every platform, so the numbers
// are comparable across legs rather than merely internally consistent.
static uint64_t s_state = 0x9E3779B97F4A7C15ull;
static uint8_t next_byte() {
    s_state ^= s_state << 13;
    s_state ^= s_state >> 7;
    s_state ^= s_state << 17;
    return (uint8_t)(s_state >> 24);
}

static double gbps(const std::vector<uint8_t>& img, const uint8_t* needle,
                   size_t k, int reps, size_t* hits_out) {
    double best = 0.0;
    size_t hits = 0;
    for (int r = 0; r < reps; ++r) {
        hits = 0;
        const auto t0 = std::chrono::steady_clock::now();
        locate::detail::scan_literal(img.data(), img.data() + img.size(),
            needle, k, [&](const uint8_t*) { ++hits; return false; });
        const auto t1 = std::chrono::steady_clock::now();
        const double sec = std::chrono::duration<double>(t1 - t0).count();
        const double rate = (double)img.size() / sec / 1e9;
        if (rate > best)
            best = rate;
    }
    *hits_out = hits;
    return best;
}

// What the vector path replaced, on the same buffer, so the platform's number
// is a ratio rather than a bare figure. Also a correctness cross-check: the
// two must find the same matches, which is scan_literal's stated contract.
static double memchr_gbps(const std::vector<uint8_t>& img, const uint8_t* needle,
                          size_t k, int reps, size_t* hits_out) {
    double best = 0.0;
    size_t hits = 0;
    for (int r = 0; r < reps; ++r) {
        hits = 0;
        const auto t0 = std::chrono::steady_clock::now();
        const uint8_t* p = img.data();
        const uint8_t* last = img.data() + img.size();
        while ((size_t)(last - p) >= k) {
            const uint8_t* q = (const uint8_t*)memchr(p, needle[0],
                                                      (size_t)(last - p) - k + 1);
            if (!q)
                break;
            if (memcmp(q, needle, k) == 0)
                ++hits;
            p = q + 1;
        }
        const auto t1 = std::chrono::steady_clock::now();
        const double sec = std::chrono::duration<double>(t1 - t0).count();
        const double rate = (double)img.size() / sec / 1e9;
        if (rate > best)
            best = rate;
    }
    *hits_out = hits;
    return best;
}

int main(int argc, char** argv) {
    const size_t mb = argc > 1 ? (size_t)atoi(argv[1]) : 128;
    const int reps = argc > 2 ? atoi(argv[2]) : 5;
    const size_t n = mb << 20;

    std::vector<uint8_t> img(n);
    for (size_t i = 0; i < n; ++i)
        img[i] = next_byte();

    // Common first byte: 0x90 every 8th byte, so the prefilter's first anchor
    // hits constantly and only the second anchor rejects.
    for (size_t i = 0; i < n; i += 8)
        img[i] = 0x90;
    const uint8_t common[6] = { 0x90, 0x11, 0x22, 0x33, 0x44, 0x55 };

    // Rare: placed AFTER the 0x90 fill and at an offset the fill does not
    // touch. Written before, the fill overwrote its first byte and the scan
    // reported 0 hits -- a benchmark that silently measures "found nothing"
    // is measuring the wrong thing.
    const uint8_t rare[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    const size_t rare_at = (n / 2) | 3u;
    for (size_t i = 0; i < sizeof rare; ++i)
        img[rare_at + i] = rare[i];

    size_t h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    const double r1 = gbps(img, rare, sizeof rare, reps, &h1);
    const double r2 = gbps(img, common, sizeof common, reps, &h2);
    const double m1 = memchr_gbps(img, rare, sizeof rare, reps, &h3);
    const double m2 = memchr_gbps(img, common, sizeof common, reps, &h4);

    printf("mamlbench backend=%s image=%zuMB reps=%d\n", backend(), mb, reps);
    printf("  %-20s %10s %10s %8s\n", "case", "vector", "memchr", "speedup");
    printf("  %-20s %7.2f GB/s %7.2f GB/s %7.2fx   (%zu hits)\n",
           "rare-first-byte", r1, m1, m1 > 0 ? r1 / m1 : 0.0, h1);
    printf("  %-20s %7.2f GB/s %7.2f GB/s %7.2fx   (%zu hits)\n",
           "common-first-byte", r2, m2, m2 > 0 ? r2 / m2 : 0.0, h2);
    if (h1 != h3 || h2 != h4) {
        printf("::error::vector and memchr disagree: %zu/%zu and %zu/%zu\n",
               h1, h3, h2, h4);
        return 1;
    }
    if (h1 == 0) {
        printf("::error::the rare needle was never found; the benchmark is "
               "measuring an empty search\n");
        return 1;
    }
    return 0;
}
