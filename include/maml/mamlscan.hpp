// mamlscan -- locating a pattern in a large image, quickly.
//
// maml answers "does this pattern match at this cursor". Finding *where* it
// matches in a 133MB image is a separate problem, and doing it by handing
// next_match() the whole image costs about a second per pattern because the
// atom matcher runs at every byte offset.
//
// The strategy here is seed-then-refine, after ida-sigmaker's ALGORITHM.md:
//
//   1. Seed on the RAREST contiguous run of exact bytes, not the longest.
//      Length is a poor proxy for selectivity -- one real pattern's longest run
//      occurs 140,722 times in the image while a shorter run in the same
//      pattern is nearly unique. Ranking only needs a capped count, since a run
//      past the cap is simply "too common" either way.
//   2. Refine each candidate against every exact byte at a fixed offset. This
//      is a plain compare, no recursion: one pattern goes from 31,378
//      candidates to a single call into the matcher.
//   3. Verify with the matcher seeded at the candidate and bounded to that one
//      offset, so a rejection costs nothing. Unbounded, a rejected candidate
//      scans the whole remainder -- 950 of them took six minutes, versus 262ms
//      bounded.
//
// Fixed offsets stop at the first cursor-moving token: after `$` the cursor
// jumps to the callee, so nothing past it sits at a predictable offset. The
// scanner is deliberately conservative there rather than assuming contiguity.
//
// Selectivity can also be measured once, offline, and handed back through
// Seed -- then step 1 costs nothing at scan time, which is what an injected
// library wants.
#ifndef MAML_SCAN_HPP
#define MAML_SCAN_HPP

#include "version.hpp"
#include <algorithm>
#include <cstdint>
#include <bit>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#if defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64)
#  include <arm_neon.h>
#  define MAML_SIMD_NEON 1
#elif defined(__x86_64__) || defined(_M_X64)
#  include <emmintrin.h>
#  define MAML_SIMD_SSE2 1
#endif

namespace maml {
    namespace locate {

        // Exact bytes at fixed offsets within a pattern, up to the first cursor move.
        struct FixedBytes {
            std::vector<int> offsets;
            std::vector<uint8_t> bytes;
            size_t span = 0;
        };

        inline FixedBytes fixed_bytes(std::string_view pattern) {
            FixedBytes f;
            std::vector<std::string> t;
            {
                std::istringstream is{ std::string(pattern) };
                std::string w;
                while (is >> w)
                    t.push_back(w);
            }
            auto is_hex = [](const std::string& s) {
                return s.size() == 2 && std::isxdigit((unsigned char)s[0]) && std::isxdigit((unsigned char)s[1]);
            };
            size_t pos = 0;
            size_t i = 0;
            // Set when the token just consumed was a plain hex byte, so that a
            // following `&` knows there is a fixed byte to retract.
            bool prev_hex = false;
            while (i < t.size()) {
                // `E8 $ { ' }` first. `$` alone moves the cursor to the call target, but
                // the block form puts it back: `{` pushes, `'` saves the callee, `}`
                // pops. Measured against the image, the bytes after `}` sit at call site
                // + 5, contiguous with the opcode -- so the fixed region continues, and
                // treating `$` as its end discards everything a seed could key on.
                //
                // This has to be tested before the plain-hex case, because "E8" is
                // itself a valid hex pair and a generic check consumes it.
                const size_t amp = t[i].find('&');
                if (t[i] == "E8" && i + 4 < t.size() &&
                    t[i + 1] == "$" && t[i + 2] == "{" && t[i + 3] == "'" && t[i + 4] == "}") {
                    f.offsets.push_back((int)pos);
                    f.bytes.push_back(0xE8);
                    pos += 5; // opcode plus the rel32 the block steps over
                    i += 5;
                    prev_hex = false;
                } else if (is_hex(t[i])) {
                    f.offsets.push_back((int)pos);
                    f.bytes.push_back((uint8_t)std::strtoul(t[i].c_str(), nullptr, 16));
                    ++pos;
                    ++i;
                    prev_hex = true;
                } else if (amp != std::string::npos) {
                    // A mask. The lexer binds `&` to the hex run immediately
                    // before it, with or without whitespace, so this token is
                    // one of `XX&MM`, `XX&` (mask next), `&MM`, or `&` (mask
                    // next) -- and in the last two the run was the token just
                    // consumed as a plain byte, which must be RETRACTED: a
                    // masked byte is fixed-WIDTH, so it keeps its slot in
                    // `pos`, but it is not fixed-VALUE, so it must not be a
                    // seed byte. Left in, the seed demanded the unmasked
                    // literal and the scan silently missed every match whose
                    // masked bits differed -- measured as 1 hit where the
                    // unseeded matcher found 32.
                    const std::string lhs = t[i].substr(0, amp);
                    const std::string rhs = t[i].substr(amp + 1);
                    if (lhs.empty()) {
                        if (!prev_hex)
                            break; // `&` after something we did not push: give up here
                        f.offsets.pop_back();
                        f.bytes.pop_back();
                    } else if (is_hex(lhs)) {
                        ++pos;
                    } else {
                        break; // a multi-byte masked run: stop before it, conservatively
                    }
                    i += rhs.empty() ? 2 : 1; // a bare `&`/`XX&` takes its mask from the next token
                    prev_hex = false;
                } else if (t[i] == "?") {
                    ++pos;
                    ++i;
                    prev_hex = false;
                } else if (t[i].size() > 2 && t[i].front() == '[' && t[i].back() == ']' &&
                           t[i].find('-') == std::string::npos) {
                    pos += (size_t)std::strtoul(t[i].c_str() + 1, nullptr, 10); // fixed skip
                    ++i;
                    prev_hex = false;
                } else {
                    break; // a range skip or any other cursor move: offsets end here
                }
            }
            f.span = pos;
            return f;
        }

        // Contiguous runs among the fixed bytes, as (offset, bytes).
        inline std::vector<std::pair<size_t, std::vector<uint8_t>>> runs(const FixedBytes& f) {
            std::vector<std::pair<size_t, std::vector<uint8_t>>> out;
            for (size_t i = 0; i < f.offsets.size();) {
                size_t j = i;
                std::vector<uint8_t> cur{ f.bytes[i] };
                while (j + 1 < f.offsets.size() && f.offsets[j + 1] == f.offsets[j] + 1) {
                    cur.push_back(f.bytes[j + 1]);
                    ++j;
                }
                out.push_back({ (size_t)f.offsets[i], cur });
                i = j + 1;
            }
            return out;
        }

        namespace detail {
            // Two-anchor vector prefilter. Compares needle[0] and needle[k-1] at
            // 16 positions at once, ANDs the results, and only examines survivors.
            // Adapted from ida-sigmaker's simd_support.hpp (MIT, same author) and
            // narrowed: maml's needle is always a literal run, so the per-byte
            // masks that header carries are unnecessary.
            //
            // The win is not the compare, it is never leaving the vector loop.
            // memchr returns to scalar code on every first-byte hit; measured on a
            // 133MB image with a common first byte, 1.0 GB/s against 26 GB/s.
            //
            // Dispatch is compile-time against the baseline ISA on purpose.
            // SSE2 and NEON are guaranteed on every 64-bit target here, so the
            // choice is always safe; AVX2 is not baseline, and a wheel built
            // with -mavx2 would SIGILL on any pre-2013 x86. Runtime dispatch is
            // not the escape hatch it looks like either: C++17 inline variables
            // could hold a CPUID resolver in a header, but per-function
            // target attributes are GCC/Clang-only -- MSVC needs /arch as a
            // whole-TU flag, which a header cannot ask for.
            //
            // AVX2 was measured and rejected, not assumed. tools/mamlbench runs
            // on every Release CI leg; across five machines the busy case
            // (first anchor hitting one byte in eight) runs at 0.78-0.94x the
            // rare case -- 6% slower on three of them. If the COMPARE were the
            // bottleneck, that gap would be large, so the loop is waiting on
            // loads and wider vectors buy nothing. Corroborating: glibc's
            // memchr dispatches to AVX2 at runtime and managed 13.75 GB/s
            // searching one byte on the same machine where this SSE2 loop did
            // 21.60 checking two. Re-open the question if mamlbench's
            // common/rare ratio ever drops on a new platform.
            //
            // Calls on_candidate(p) for each p in [first, last-k] where the k bytes
            // at p equal `needle`, in increasing p, including overlapping matches.
            // Returns as soon as on_candidate returns true. Same match set and
            // order as a memchr+memcmp scan -- that equivalence is the contract.
            template <typename F>
            inline void scan_literal(const uint8_t* first, const uint8_t* last,
                                     const uint8_t* needle, size_t k, F&& on_candidate) {
                if (k == 0 || static_cast<size_t>(last - first) < k)
                    return;
                const uint8_t* p = first;
#if defined(MAML_SIMD_NEON)
                const uint8x16_t v0 = vdupq_n_u8(needle[0]);
                const uint8x16_t vk = vdupq_n_u8(needle[k - 1]);
                while (static_cast<size_t>(last - p) >= k + 15) {
                    const uint8x16_t eq =
                        vandq_u8(vceqq_u8(vld1q_u8(p), v0),
                                 vceqq_u8(vld1q_u8(p + k - 1), vk));
                    // 4 bits per lane -- NEON has no movemask.
                    uint64_t m = vget_lane_u64(
                        vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(eq), 4)), 0);
                    while (m) {
                        const unsigned i = static_cast<unsigned>(std::countr_zero(m)) >> 2;
                        if (std::memcmp(p + i, needle, k) == 0 && on_candidate(p + i))
                            return;
                        m &= ~(0xFULL << (i * 4));
                    }
                    p += 16;
                }
#elif defined(MAML_SIMD_SSE2)
                const __m128i v0 = _mm_set1_epi8(static_cast<char>(needle[0]));
                const __m128i vk = _mm_set1_epi8(static_cast<char>(needle[k - 1]));
                while (static_cast<size_t>(last - p) >= k + 15) {
                    const __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
                    const __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + k - 1));
                    unsigned m = static_cast<unsigned>(_mm_movemask_epi8(
                        _mm_and_si128(_mm_cmpeq_epi8(a, v0), _mm_cmpeq_epi8(b, vk))));
                    while (m) {
                        const unsigned i = static_cast<unsigned>(std::countr_zero(m));
                        if (std::memcmp(p + i, needle, k) == 0 && on_candidate(p + i))
                            return;
                        m &= m - 1;
                    }
                    p += 16;
                }
#endif
                // Tail, and the whole scan where no vector path is compiled in.
                while (static_cast<size_t>(last - p) >= k) {
                    const uint8_t* q = static_cast<const uint8_t*>(
                        std::memchr(p, needle[0], static_cast<size_t>(last - p) - k + 1));
                    if (!q)
                        return;
                    if (std::memcmp(q, needle, k) == 0 && on_candidate(q))
                        return;
                    p = q + 1;
                }
            }
        } // namespace detail

        // Occurrences of `needle`, counting no further than `cap`. Overlapping
        // occurrences count separately (`it = q + 1`, not `it = q + k`).
        //
        // memchr, not std::boyer_moore_searcher: measured over a 133MB image, BM
        // costs 64-259 ms against 9 ms here for the short needles a seed actually
        // is. libc's memchr is already vectorized, and BM's skip table cannot pay
        // for its per-call overhead at these lengths.
        inline size_t count_up_to(std::span<const uint8_t> hay,
            const std::vector<uint8_t>& needle, size_t cap) {
            if (needle.empty() || needle.size() > hay.size())
                return SIZE_MAX;
            size_t c = 0;
            detail::scan_literal(hay.data(), hay.data() + hay.size(),
                                 needle.data(), needle.size(),
                                 [&](const uint8_t*) { return ++c >= cap; });
            return c;
        }

        // The run a scan should key on: offset into the pattern, and its bytes.
        struct Seed {
            size_t offset = 0;
            std::vector<uint8_t> bytes;
            bool ok() const {
                return !bytes.empty();
            }
        };

        // Counting seeds exactly costs about 5ms per pattern per 133MB image (it
        // was 243ms before run ordering, memchr and the SIMD prefilter landed).
        // Cheap offline; still not something to pay per pattern inside DllMain,
        // where the offline generator has already measured the seed. Callers
        // pick. Exact is the default so the trade is opted into, not inherited:
        // measured over a 330-pattern corpus, the capped mode picks a worse seed
        // for 4.55% of patterns, by up to 9.82x.
        inline constexpr size_t kSeedCapExact    = SIZE_MAX;
        inline constexpr size_t kSeedCapLoadTime = 4096;

        // Pick the rarest run. `cap` bounds the counting; under a truncating cap a
        // run at or past it is only used when nothing more selective exists, in
        // which case the longest wins. Under kSeedCapExact that fallback is
        // reachable only when there are no runs.
        inline Seed select_seed(std::span<const uint8_t> image, const FixedBytes& f,
                                size_t cap = kSeedCapExact) {
            Seed best;
            size_t best_count = SIZE_MAX;
            auto rs = runs(f);
            // Longest-first, not offset order. `best_count` starts at SIZE_MAX, so
            // whichever run is counted first is counted in full -- and in offset
            // order that is usually the lone leading opcode byte, the commonest
            // thing in the pattern. Longer runs are usually rarer, so visiting
            // them first drops `best_count` immediately and `count_up_to`'s
            // `min(best_count, cap)` short-circuits every later run. Measured on a
            // 133MB image: 677ms in offset order, 44ms here. NOT a no-op on
            // choice, though a single-pattern fixture suggested it was: over a
            // real 330-pattern corpus it moved 23 of 330 seed choices on one image and 21 on the other:
            // 12 pure ties, 9 to a RARER run, 2 to a commoner one. Seed choice
            // cannot change a match -- find() re-verifies every fixed byte at
            // each hit -- so this costs candidates and time, never answers.
            //
            // Reordering doesn't only change which of several tied (equal-count)
            // runs wins. `best_count <= 4` below is a satisficer, not an argmin --
            // it stops at the first run counted at or under 4, not the smallest,
            // so two runs with different, non-tied counts can each trigger it, and
            // whichever is visited first wins. Ties are only a subset of that.
            //
            // `stable_sort`, not `sort`: among equal-length runs this preserves
            // offset order, which keeps the longest-run fallback below picking
            // exactly the run it picked before.
            std::stable_sort(rs.begin(), rs.end(),
                [](const auto& a, const auto& b) { return a.second.size() > b.second.size(); });
            for (const auto& [off, r] : rs) {
                const size_t c = count_up_to(image, r, (std::min)(best_count, cap));
                if (c < best_count) {
                    best_count = c;
                    best.bytes = r;
                    best.offset = off;
                }
                if (best_count <= 4)
                    break;
            }
            if (!best.ok() || best_count >= cap)
                for (const auto& [off, r] : rs)
                    if (r.size() > best.bytes.size()) {
                        best.bytes = r;
                        best.offset = off;
                    }
            return best;
        }


    } // namespace locate
} // namespace maml
#endif
