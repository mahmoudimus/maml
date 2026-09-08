// maml::generate -- the inverse of matching.
//
// `maml` answers "where does this pattern match?". This answers "give me a
// durable pattern for this address", where durable means: unique in TWO
// independent compilations and resolving to its own target in each.
//
// It derives its own substrate from image bytes -- call graph, string table,
// rip-relative references -- so the API takes an image and section bounds, not
// a disassembler's output. It does not parse PE/ELF/Mach-O and does not
// disassemble; everything here is byte scanning and rel32/disp32 arithmetic.
#ifndef MAML_GENERATE_HPP
#define MAML_GENERATE_HPP

#include "maml/mamlscan.hpp"
#include "maml/v1.hpp"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace maml {
    namespace generate {

        // RVAs, half-open.
        struct Range {
            uint64_t begin = 0;
            uint64_t end = 0;
        };

        // A flat, RVA-indexed image plus what the caller knows that the bytes
        // do not say. `funcs` is optional: absent, a byte window is used and
        // the results are merely worse, not wrong. If supplied it must already
        // be chain-resolved -- UNW_FLAG_CHAININFO fragments are not function
        // starts, a trap this project walked into four separate times.
        struct Image {
            std::span<const uint8_t> bytes;
            std::span<const Range> code;
            std::span<const Range> rodata;
            std::span<const Range> funcs = {};
        };

        enum class Strategy { Body,
            Xref,
            StringAnchor,
            RipRef };

        struct Options {
            // Pattern bytes. Every strategy budgets it; see each emitter for
            // whether it spends it on the tail alone (Xref) or on the whole
            // pattern (Body, StringAnchor, RipRef).
            size_t max_len = 64;

            // Independent anchors per target. candidates() treats this as a
            // ROUND-ROBIN budget across the four strategies, not as a
            // sequential fill -- see the long note there.
            int want = 4;

            // TAIL LENGTH ONLY. With it on, a trailing literal run that no
            // later atom depends on is shortened to the shortest that is
            // still unique in THIS image (never below
            // detail::kMinLiteralRun); with it off, the full budgeted window
            // is emitted. It says nothing about WHERE a pattern anchors --
            // that is `deep_anchor` below. Those two were one flag until a
            // review found that turning `prefer_short` off silently
            // downgraded Body to delta 0 only, which nothing documented and
            // no caller could have wanted from an option about length.
            bool prefer_short = true;

            // Body's distinctiveness walk. With it on, Body tries deeper
            // offsets past the entry (0, 4, 8, 16, 32, 64) until one is
            // unique within this image, and anchors there with a matching
            // anchor_delta; with it off, Body anchors at delta 0 and emits
            // that whether or not it is distinctive. On by default because
            // the entry bytes of a function are the LEAST distinctive part
            // of it -- prologues repeat across a whole image -- and because
            // the deeper anchor is the only reason a Body candidate ever
            // survives verification for such a function.
            //
            // The cost is one full-image scan per offset tried, so a caller
            // generating for thousands of targets against a 137MB image may
            // want it off; the anchors it then gets are worse, not wrong.
            bool deep_anchor = true;
            std::string dialect = "maml-current";
            bool nibble_wildcards = false;
        };

        struct Candidate {
            std::string pattern;

            // 0 = the match, 1 = the first `'` capture.
            //
            // INVARIANT, relied on by detail::resolves_uniquely: save_index != 0
            // IFF the pattern captures. That function decides whether to read
            // the capture slot or to subtract anchor_delta, and it asks this
            // field rather than the strategy enum -- it used to ask the enum,
            // which silently discarded every capturing StringAnchor the moment
            // Xref stopped being the only capturing strategy. A new strategy
            // that captures at save_index 0, or sets a nonzero save_index
            // without capturing, breaks resolution while every existing test
            // still passes.
            size_t save_index = 0;

            // SUBTRACT FROM THE MATCH TO GET THE TARGET:
            //
            //     target = (int64_t)match_offset - anchor_delta
            //
            // IT IS SIGNED, AND NEGATIVE VALUES ARE NORMAL, not a defect and
            // not a marker. It is `anchor - target`, so it is negative
            // whenever the anchor sits BEFORE the target -- which is the
            // ordinary case for StringAnchor's depth-0 form, where the `lea`
            // that loads the string may well precede the function whose
            // address is wanted (a delta of -48 is a real observed value).
            // Body's walk only ever moves forward, so its deltas are >= 0;
            // that is Body's property, not this field's.
            //
            // Do the subtraction in int64_t. A caller computing
            // `match - anchor_delta` in uint64_t happens to get the right
            // answer for a negative delta by two's-complement wraparound, but
            // it gets there by luck: the same expression with any range check
            // or any narrowing in it stops being right. Sign the arithmetic.
            //
            // Only meaningful when save_index == 0. A capturing candidate
            // reads its target out of the save slot and leaves this at 0
            // (see the save_index invariant above).
            int64_t anchor_delta = 0;

            // WHERE THIS ANCHOR SITS in the image it was generated from: the
            // call site for Xref, the `lea` for StringAnchor, the referencing
            // instruction for RipRef, the anchored bytes for Body.
            //
            // It is not an input to resolution -- resolve_consensus reads the
            // pattern, save_index and anchor_delta and never this -- and it
            // means nothing in a LATER image, where the anchor will be
            // somewhere else. It exists so a caller can ask whether the
            // anchors it holds are INDEPENDENT.
            //
            // That question is load-bearing and was previously unanswerable
            // from this struct. METHOD.md measures 31.2% correct resolution
            // for one anchor against 84.4% for two or more, and that figure
            // assumes anchors that can fail separately. Two patterns cut from
            // the same instruction at different tail lengths are one anchor
            // reported twice: they agree in every build because they are the
            // same bytes, and they die together. A consumer counting
            // candidates rather than sites read exactly that as a two-witness
            // consensus and had to walk it back by hand.
            //
            // `emit()` cannot dedup on it -- two genuinely different anchors
            // may legitimately share a site, most obviously a Body and an
            // Xref pattern over the same address -- so it is reported rather
            // than enforced, and the caller decides what independence means.
            uint64_t anchor_site = 0;
            Strategy strategy = Strategy::Body;
            size_t literals = 0;
            locate::Seed seed;        // rarest run, already chosen
            std::string dialect = "maml-current";
            std::string target_capture;
        };

        // Every RVA in an executable range holding an `E8` whose rel32 lands on
        // `target`, in increasing order.
        //
        // This is not an approximation. Measured against IDA's own cross-
        // references on the same build: 6914 sites across nine targets, delta
        // zero. A stray E8 whose rel32 happens to land on the target would add
        // one, and that anchor would still be CORRECT -- the rel32 does point
        // there -- merely anchored on bytes that are not an instruction. Dual-
        // build verification strips it anyway, since a byte coincidence does not
        // reproduce in a second compilation.
        inline std::vector<uint64_t> callers_of(const Image& img, uint64_t target) {
            std::vector<uint64_t> out;
            const uint8_t* base = img.bytes.data();
            const size_t n = img.bytes.size();
            for (const Range& r : img.code) {
                const uint64_t lo = r.begin;
                const uint64_t hi = (std::min)(r.end, (uint64_t)n);
                if (lo >= hi || hi - lo < 5)
                    continue;
                for (uint64_t i = lo; i + 5 <= hi; ++i) {
                    if (base[i] != 0xE8)
                        continue;
                    const uint32_t raw = (uint32_t)base[i + 1] |
                        ((uint32_t)base[i + 2] << 8) |
                        ((uint32_t)base[i + 3] << 16) |
                        ((uint32_t)base[i + 4] << 24);
                    const int64_t rel = (int64_t)(int32_t)raw;
                    if ((int64_t)i + 5 + rel == (int64_t)target)
                        out.push_back(i);
                }
            }
            return out;
        }

        // A printable run in `rodata`: `rva` is where it starts, `len` counts
        // the printable bytes only -- the terminating NUL is not part of it.
        struct Str {
            uint64_t rva = 0;
            uint32_t len = 0;
        };

        inline bool is_printable_byte(uint8_t b) {
            return b >= 0x20 && b <= 0x7E;
        }

        // Every MAXIMAL printable run of at least 6 bytes, terminated by a
        // NUL, within `img.rodata`. `code` is not consulted -- a run outside
        // every `rodata` range is not a string here even if it sits in `code`;
        // that is StringAnchor's (Task 8) business, not this function's.
        //
        // "Maximal" means one entry per run, never per suffix: "HELLO_WORLD\0"
        // is one Str at the run's start, not eleven overlapping ones.
        //
        // A run that reaches a range's `end` without a NUL appearing INSIDE
        // that range is dropped, not truncated -- and the byte at `r.end`
        // itself, NUL or not, is never read to decide that. The scan below
        // only ever indexes `i < hi`, where `hi` is already clamped to both
        // `r.end` and `bytes.size()`, so that holds by construction.
        //
        // Ranges are scanned independently, so overlapping `rodata` ranges
        // (not expected, per the design) could otherwise yield the same `rva`
        // twice; the final sort+dedup absorbs that rather than requiring
        // callers to pre-merge their ranges.
        //
        // Sorted by ascending `rva` unconditionally -- Task 8 leans on that
        // guarantee rather than on the caller having passed sorted `rodata`.
        inline std::vector<Str> strings(const Image& img) {
            std::vector<Str> out;
            const size_t n = img.bytes.size();

            for (const Range& r : img.rodata) {
                const uint64_t hi = (std::min)(r.end, (uint64_t)n);
                if (r.begin >= hi)
                    continue;

                uint64_t i = r.begin;
                while (i < hi) {
                    if (!is_printable_byte(img.bytes[i])) {
                        ++i;
                        continue;
                    }
                    const uint64_t start = i;
                    while (i < hi && is_printable_byte(img.bytes[i]))
                        ++i;
                    // `i` is now `hi`, or the first byte after the run that is
                    // not printable -- either way, never read yet.
                    if (i < hi && img.bytes[i] == 0x00) {
                        const uint64_t len = i - start;
                        if (len >= 6)
                            out.push_back({ start, (uint32_t)len });
                    }
                    // Ran off the range's end with no NUL seen, or the run's
                    // terminator was some other non-printable byte: neither
                    // case is a string. `i` already sits past the run, so the
                    // outer loop resumes correctly without re-reading it.
                }
            }

            std::sort(out.begin(), out.end(),
                [](const Str& a, const Str& b) { return a.rva < b.rva; });
            out.erase(std::unique(out.begin(), out.end(),
                          [](const Str& a, const Str& b) { return a.rva == b.rva; }),
                out.end());
            return out;
        }

        // Every RVA in an executable range holding a RIP-relative `lea`
        // (`48 8D <modrm> <disp32>`, modrm mod=00 rm=101) whose computed
        // target is `target`, in increasing order. `site` is the address of
        // the leading `48`, not the modrm or the displacement.
        //
        // Any REX.W prefix, not just `0x48`. REX is 0100WRXB, so a `lea`
        // whose DESTINATION is r8-r15 sets REX.R and encodes as `4C 8D`, and
        // matching `0x48` alone skipped every one of them.
        //
        // This was deliberately narrow once, on the reasoning that widening
        // without re-measuring risked changing the substrate, and that the
        // cost was "a coverage limit, not a correctness bug". The first half
        // held; the second did not. Measured on a retail binary, 29.1% of all
        // rip-relative LEAs were missed -- 112,180 of 385,184 -- and 30.5% of
        // those targeting .rdata. And a MISSING reference manufactures FALSE
        // UNIQUENESS: `rip_refs_to(...).size() == 1` cannot tell "one
        // reference exists" from "one was indexed and the rest skipped", which
        // is the same ambiguity as a single unique hit,
        // reached from the other side. In the Win64 ABI r8/r9 are the third
        // and fourth integer arguments, so `lea r8, [rip+string]` is one of
        // the commonest ways a string reaches a call -- precisely the
        // StringAnchor substrate.
        //
        // The mask, not a special case for `0x4C`: 0x4A, 0x4B, 0x4E and 0x4F
        // all occur in the same binary. REX.X and REX.B are meaningless for a
        // RIP-relative operand (there is no base or index register), so every
        // encoding in 0x48-0x4F is the same instruction here.
        //
        // The `reg` field of modrm (bits 3-5) is the destination register
        // and is intentionally unconstrained -- only mod and rm gate the
        // match, hence `(modrm & 0xC7) == 0x05`.
        //
        // RIP-relative addressing is relative to the END of the instruction:
        // target = site + 7 + disp32, the same `site + length` arithmetic `$`
        // performs, and the same place the trailing-immediate trap comes
        // from. Getting the +7 wrong (e.g. +6 or +8) offsets every reference
        // by a constant -- see tests/test_generate.cpp for a case pinned to
        // this exact convention.
        inline std::vector<uint64_t> rip_refs_to(const Image& img, uint64_t target) {
            std::vector<uint64_t> out;
            const uint8_t* base = img.bytes.data();
            const size_t n = img.bytes.size();
            for (const Range& r : img.code) {
                const uint64_t lo = r.begin;
                const uint64_t hi = (std::min)(r.end, (uint64_t)n);
                if (lo >= hi || hi - lo < 7)
                    continue;
                for (uint64_t i = lo; i + 7 <= hi; ++i) {
                    if ((base[i] & 0xF8) != 0x48 || base[i + 1] != 0x8D)
                        continue;
                    const uint8_t modrm = base[i + 2];
                    if ((modrm & 0xC7) != 0x05)
                        continue;
                    const uint32_t raw = (uint32_t)base[i + 3] |
                        ((uint32_t)base[i + 4] << 8) |
                        ((uint32_t)base[i + 5] << 16) |
                        ((uint32_t)base[i + 6] << 24);
                    const int64_t disp = (int64_t)(int32_t)raw;
                    if ((int64_t)i + 7 + disp == (int64_t)target)
                        out.push_back(i);
                }
            }
            std::sort(out.begin(), out.end());
            out.erase(std::unique(out.begin(), out.end()), out.end());
            return out;
        }

        // Every RIP-relative `lea` whose target is in `wanted`, indexed by that
        // target, built in ONE pass over `code`.
        //
        // rip_refs_to() answers for a single target and scans the whole image
        // to do it. StringAnchor needs the answer for every string in the
        // table, and calling it once per string is quadratic in a way that no
        // fixture here can show: measured on a 4MB image the cost is 0.52 ms
        // per string and dead linear -- 250 strings 131 ms, 2,000 strings
        // 1,071 ms. On the 133MB image this library exists for, the table has
        // 85,232 content-unique strings and one target took 71 MINUTES, with a
        // 132-target corpus extrapolating to about 156 hours. StringAnchor was
        // effectively unusable on any real input.
        //
        // `wanted` keeps this bounded: a 133MB image holds ~385,000 `lea`s, and
        // indexing only the targets that are actually strings avoids carrying
        // the rest.
        //
        // The decode below MUST stay identical to rip_refs_to's -- same
        // `48 8D` gate, same `(modrm & 0xC7) == 0x05`, same `site + 7 + disp32`
        // -- and a test pins the two against each other for exactly that
        // reason.
        inline std::unordered_map<uint64_t, std::vector<uint64_t>>
        rip_lea_index(const Image& img, const std::unordered_set<uint64_t>& wanted) {
            std::unordered_map<uint64_t, std::vector<uint64_t>> out;
            const uint8_t* base = img.bytes.data();
            const size_t n = img.bytes.size();
            for (const Range& r : img.code) {
                const uint64_t lo = r.begin;
                const uint64_t hi = (std::min)(r.end, (uint64_t)n);
                if (lo >= hi || hi - lo < 7)
                    continue;
                for (uint64_t i = lo; i + 7 <= hi; ++i) {
                    if ((base[i] & 0xF8) != 0x48 || base[i + 1] != 0x8D)
                        continue;
                    const uint8_t modrm = base[i + 2];
                    if ((modrm & 0xC7) != 0x05)
                        continue;
                    const uint32_t raw = (uint32_t)base[i + 3] |
                        ((uint32_t)base[i + 4] << 8) |
                        ((uint32_t)base[i + 5] << 16) |
                        ((uint32_t)base[i + 6] << 24);
                    const int64_t disp = (int64_t)(int32_t)raw;
                    const int64_t t = (int64_t)i + 7 + disp;
                    if (t < 0 || !wanted.count((uint64_t)t))
                        continue;
                    out[(uint64_t)t].push_back(i);
                }
            }
            // Ascending and deduplicated, matching rip_refs_to: `code` ranges
            // are not required to be sorted, so insertion order is not enough.
            for (auto& kv : out) {
                std::sort(kv.second.begin(), kv.second.end());
                kv.second.erase(std::unique(kv.second.begin(), kv.second.end()),
                    kv.second.end());
            }
            return out;
        }

        // One instruction form that carries a RIP-relative disp32, as a TABLE
        // ROW. This header does not disassemble and must not start: a general
        // x86 length decoder is a large, wrong-in-the-corners thing, and the
        // only fact RipRef needs from an instruction is where its disp32 sits
        // and how many bytes follow it. Adding a form is one row here.
        //
        // `imm_width` is the field the whole strategy exists for. RIP-relative
        // addressing resolves against the END of the instruction, while `$`
        // computes (cursor + 4) + disp32 -- so `$` is correct only while the
        // disp32 is the instruction's LAST field, and lands short by exactly
        // `imm_width` when an immediate follows it. See README.md and
        // tests/test_patterns.cpp, which pin both halves for the matcher.
        struct RipForm {
            uint8_t opcode[3] = { 0, 0, 0 }; // literal prefix/opcode bytes BEFORE the modrm
            // Per-byte mask, 0xFF for an exact match. 0xF8 on a REX byte
            // accepts the whole 0x48-0x4F range, so a form whose destination
            // is r8-r15 (REX.R, e.g. `4C 8B 0D`) is matched -- the same
            // blindness that lost 29.1% of rip-relative LEAs.
            uint8_t opcode_mask[3] = { 0xFF, 0xFF, 0xFF };
            uint8_t opcode_len = 0;
            int8_t modrm_reg = -1;   // 0-7 when the opcode's own /digit selects it, -1 when free
            uint8_t disp_off = 0;    // where the disp32 starts, from the instruction's first byte
            uint8_t total_len = 0;   // FULL length, the trailing immediate INCLUDED
            uint8_t imm_width = 0;   // 0, 1 or 4
        };

        // The supported forms. Deliberately small; an unrecognised encoding is
        // SKIPPED, never guessed at (see rip_operand_refs_to).
        //
        // `modrm_reg` is -1 wherever the reg field names a register and is
        // therefore free -- the same rule rip_refs_to states for `lea`. It is
        // pinned only where the opcode's /digit lives in that field and selects
        // the operation rather than a register: `83 /7` is cmp (its siblings
        // add/or/adc/... share the length and want their own rows if wanted),
        // and `C7 /0` is the only defined mov form of that opcode.
        inline constexpr RipForm kRipForms[] = {
            // 4x 8B /r      mov r64, [rip+disp]                  disp32 is last
            { { 0x48, 0x8B }, { 0xF8, 0xFF, 0xFF }, 2, -1, 3, 7, 0 },
            // 4x 8D /r      lea r64, [rip+disp]                  disp32 is last
            //
            // Every other row here DEREFERENCES the global; this one takes its
            // ADDRESS, which is how a global is most often named in the first
            // place. Its absence was not a partial gap, it was total: on the
            // twelve globals a consumer reported as unanchorable, `candidates`
            // returned nothing for nine of them, and two-build `verified`
            // went from 2/9 to 5/9 with this row alone -- including both the
            // targets that consumer graded "solid".
            { { 0x48, 0x8D }, { 0xF8, 0xFF, 0xFF }, 2, -1, 3, 7, 0 },
            // 4x 69 /r id   imul r64, [rip+disp], imm32          `$` is 4 short
            { { 0x48, 0x69 }, { 0xF8, 0xFF, 0xFF }, 2, -1, 3, 11, 4 },
            // 4x C7 /0 id   mov qword [rip+disp], imm32          `$` is 4 short
            { { 0x48, 0xC7 }, { 0xF8, 0xFF, 0xFF }, 2, 0, 3, 11, 4 },
            // 83 /7 ib      cmp dword [rip+disp], imm8           `$` is 1 short
            { { 0x83 }, { 0xFF, 0xFF, 0xFF }, 1, 7, 2, 7, 1 },
            // 0F 11 /r      movups [rip+disp], xmm               disp32 is last
            //
            // A STORE, and the reg field is the source xmm register, so it is
            // free. An SSE-width global written back is a shape none of the
            // GPR rows above can see; a consumer hand-wrote this form as
            // `0F 11 05 $ { ' }` and it verified on two builds before any of
            // this table could emit it.
            { { 0x0F, 0x11 }, { 0xFF, 0xFF, 0xFF }, 2, -1, 3, 7, 0 },
            // 0F B6 /r      movzx r32, byte [rip+disp]           disp32 is last
            { { 0x0F, 0xB6 }, { 0xFF, 0xFF, 0xFF }, 2, -1, 3, 7, 0 },
            // 4x 0F B6 /r   movzx r64/r8-r15, byte [rip+disp]    disp32 is last
            //
            // Its own row rather than a mask on the one above: the REX prefix
            // is a fourth byte at the FRONT, which moves modrm, disp_off and
            // total_len by one. 0xF0 rather than 0xF8 because both REX.W
            // (`48 0F B6`) and REX.R (`44 0F B6`) are this instruction.
            { { 0x40, 0x0F, 0xB6 }, { 0xF0, 0xFF, 0xFF }, 3, -1, 4, 8, 0 },
            // 8B /r         mov r32, [rip+disp]      NO REX       disp32 is last
            //
            // The 32-bit load. Every other row here is REX-prefixed or
            // two-byte, and this one is neither, which is what makes it the
            // row that ALIASES: its bytes are the tail of the `4x 8B` row's,
            // so it matches again one byte into every 64-bit mov. See the
            // end-dedup at the bottom of rip_operand_refs_to, which is what
            // makes this row safe to have.
            { { 0x8B }, { 0xFF, 0xFF, 0xFF }, 1, -1, 2, 6, 0 },
        };

        // An instruction that RIP-relatively references some global, and the
        // table row that says how to read it.
        struct RipOperandRef {
            uint64_t site = 0;             // the instruction's first byte
            const RipForm* form = nullptr; // never null in a returned ref
        };

        // Every site in an executable range whose RIP-relative operand computes
        // `target`, in increasing order, together with the form matched.
        //
        // A site whose bytes match NO row is skipped and reported nowhere.
        // There is deliberately no "assume the disp32 is last" fallback: that
        // assumption is right for the mov form and wrong by the immediate's
        // width for every form that carries one, and the resulting candidate
        // resolves a few bytes BELOW a real global while still matching, still
        // reporting exactly one hit. Nothing downstream can tell that apart
        // from a correct answer, so the only safe treatment of an unknown
        // encoding is to emit nothing for it.
        //
        // Target arithmetic is site + TOTAL length + disp32 -- the full length,
        // immediate included, which is the same fact the trap comes from. The
        // `(int64_t)(int32_t)raw` cast chain is rip_refs_to's, for the same
        // reason: skipping the narrowing loses every negative displacement.
        inline std::vector<RipOperandRef> rip_operand_refs_to(const Image& img,
            uint64_t target) {
            std::vector<RipOperandRef> out;
            const uint8_t* base = img.bytes.data();
            const size_t n = img.bytes.size();
            for (const Range& r : img.code) {
                const uint64_t lo = r.begin;
                const uint64_t hi = (std::min)(r.end, (uint64_t)n);
                if (lo >= hi)
                    continue;
                for (uint64_t i = lo; i < hi; ++i) {
                    for (const RipForm& f : kRipForms) {
                        // The full instruction has to be in bounds, not just
                        // the displacement: a row's length is what the target
                        // arithmetic below is about to trust.
                        if (i + f.total_len > hi)
                            continue;
                        bool opcode_ok = true;
                        for (uint8_t k = 0; k < f.opcode_len; ++k)
                            if ((base[i + k] & f.opcode_mask[k]) != f.opcode[k]) {
                                opcode_ok = false;
                                break;
                            }
                        if (!opcode_ok)
                            continue;
                        const uint8_t modrm = base[i + f.opcode_len];
                        if ((modrm & 0xC7) != 0x05) // mod=00, rm=101: RIP-relative
                            continue;
                        if (f.modrm_reg >= 0 && (int8_t)((modrm >> 3) & 7) != f.modrm_reg)
                            continue;
                        const uint32_t raw = (uint32_t)base[i + f.disp_off] |
                            ((uint32_t)base[i + f.disp_off + 1] << 8) |
                            ((uint32_t)base[i + f.disp_off + 2] << 16) |
                            ((uint32_t)base[i + f.disp_off + 3] << 24);
                        const int64_t disp = (int64_t)(int32_t)raw;
                        if ((int64_t)i + f.total_len + disp == (int64_t)target)
                            out.push_back({ i, &f });
                        break; // rows are opcode-disjoint: one match per site
                    }
                }
            }
            std::sort(out.begin(), out.end(),
                [](const RipOperandRef& a, const RipOperandRef& b) { return a.site < b.site; });
            out.erase(std::unique(out.begin(), out.end(),
                          [](const RipOperandRef& a, const RipOperandRef& b) { return a.site == b.site; }),
                out.end());

            // Then dedup by where the instruction ENDS, keeping the lowest
            // site -- which is the longest instruction, which is the real one.
            //
            // Rows are opcode-disjoint at a site, but not across sites: a row
            // whose opcode is the tail of a longer row's matches again one
            // byte in, and the target arithmetic comes out RIGHT there, since
            // both readings end at the same address. `48 8B 05 <disp>` is
            // therefore reported at its own site AND at site+1 as a bare
            // `8B 05 <disp>`; `44 0F B6 05 <disp>` likewise at site+1 as
            // `0F B6 05 <disp>`.
            //
            // Nothing downstream can reject those: they are not wrong
            // addresses, they resolve correctly, and they are unique. What
            // they are is the SAME instruction counted twice, and a target
            // credited with two anchors that are one byte apart has one --
            // they die together in the next build. That is the false-
            // corroboration shape METHOD.md's "two or more anchors" figure
            // assumes away, and a consumer hit it in the field with
            // hand-written variants before this table could produce it.
            //
            // Keying on the end rather than guarding on a preceding REX byte
            // is exact, not a heuristic: two DISTINCT instructions cannot end
            // at the same address unless one is a byte-suffix of the other,
            // which is precisely this case. The "is the previous byte
            // 0x40-0x4F" guard was tried first and drops genuine sites
            // whenever a preceding displacement or immediate byte lands in
            // that range -- roughly one site in sixteen, for nothing.
            std::unordered_set<uint64_t> ends;
            std::vector<RipOperandRef> kept;
            kept.reserve(out.size());
            for (const RipOperandRef& r : out)
                if (ends.insert(r.site + r.form->total_len).second)
                    kept.push_back(r);
            return kept;
        }

        // Bytes rendered as maml literals: "4C 8B D0".
        inline std::string hex_bytes(const uint8_t* p, size_t n) {
            static const char* D = "0123456789ABCDEF";
            std::string s;
            s.reserve(n * 3);
            for (size_t i = 0; i < n; ++i) {
                if (i)
                    s += ' ';
                s += D[p[i] >> 4];
                s += D[p[i] & 0xF];
            }
            return s;
        }

        // The `funcs` range containing `at`, or nullptr when `funcs` is empty
        // or nothing covers it. StringAnchor's depth 0 and depth 1 differ ONLY
        // by which function holds the load site, so "not contained" has to be
        // distinguishable from "contained by a range that happens to begin at
        // 0" -- hence a pointer rather than an index or a Range by value.
        //
        // ORDER-INDEPENDENT BY CONSTRUCTION. `funcs` is caller-supplied and
        // this header states no sortedness or disjointness precondition on it;
        // returning the first range that happens to cover `at` would make the
        // answer -- and with it StringAnchor's depth-0-vs-depth-1 choice and
        // every clamped tail length -- depend on the order the caller listed
        // its functions in. So the TIGHTEST covering range wins: smallest
        // width, ties broken by the lowest `begin`, then by the lowest `end`.
        // That is a total order on the covering set, so the same `funcs`
        // content always yields the same answer however it is permuted.
        //
        // Tightest rather than first is also the right answer on the merits:
        // where ranges nest (a chain-resolved function inside a region, say),
        // the innermost is the one whose end a tail must not run past.
        inline const Range* enclosing_func(const Image& img, uint64_t at) {
            const Range* best = nullptr;
            for (const Range& r : img.funcs) {
                if (at < r.begin || at >= r.end)
                    continue;
                if (!best) {
                    best = &r;
                    continue;
                }
                const uint64_t rw = r.end - r.begin, bw = best->end - best->begin;
                if (rw < bw || (rw == bw && (r.begin < best->begin || (r.begin == best->begin && r.end < best->end))))
                    best = &r;
            }
            return best;
        }

        // When `img.funcs` is non-empty and one of its ranges contains
        // `anchor`, clamp `take` to what remains of THAT range so a tail never
        // runs into the next function's prologue, alignment padding, or data.
        // With `funcs` empty (the Task 1-4 default), or with no range
        // containing `anchor`, this is a no-op -- behaviour stays byte-
        // identical to before this existed, which is what let the milestone
        // ship with a byte window and merely worse (not wrong) results.
        //
        // Shares enclosing_func's tightest-covering rule rather than repeating
        // a scan of its own: the two used to answer independently, so an
        // overlapping or reordered `funcs` could clamp against one range while
        // the depth decision was made against another.
        inline size_t clamp_to_func(const Image& img, uint64_t anchor, size_t take) {
            if (const Range* r = enclosing_func(img, anchor))
                return (std::min)(take, (size_t)(r->end - anchor));
            return take;
        }

        namespace detail {

            // One bucket per strategy: the interleave order candidates()
            // spends `want` in, and the order dedup resolves ties in. It lives
            // here rather than inside candidates() because verified() must
            // size its oversample by the same number -- the budget is SHARED
            // across these buckets, so asking for N yields only ~N/buckets
            // attempts per strategy.
            enum Bucket { kXref = 0,
                kBody,
                kStringAnchor,
                kRipRef,
                kBucketCount };

            // THE FLOOR ON A TRAILING LITERAL RUN. Uniqueness alone will
            // happily stop at ONE byte: on a fixture whose filler is 0xCC, a
            // single 0x4C is already unique, and the bisection below has no
            // reason of its own to keep looking.
            //
            // A one- or two-byte run is the worst case twice over.
            //
            //   * It is the worst case for DURABILITY. Uniqueness in one
            //     image is exactly the property that does not survive a
            //     recompile; a run that is unique only
            //     because the image is small carries no evidence at all about
            //     the code around it, so verified() is being asked to confirm
            //     a coincidence rather than a shape.
            //   * It is the worst case for locate::select_seed, which picks
            //     the rarest fixed run to scan on. A one-byte seed makes the
            //     seed step a byte histogram -- it hits everywhere and the
            //     refine step runs at every hit -- which is precisely the
            //     140,722-candidate failure CLAUDE.md records.
            //
            // Four bytes, because that is the width at which a run stops
            // being a byte value and starts being an instruction or an
            // operand. It is a FLOOR, not a target: where uniqueness needs
            // more, more is emitted, and where the whole available window is
            // shorter than this the window is emitted as-is (a two-byte
            // window cannot be padded into a four-byte one).
            inline constexpr size_t kMinLiteralRun = 4;

            // The shortest trailing literal run, in bytes, for which
            // `head` + that run still matches exactly once in `img` --
            // or `full` when even the full run does not, since then no
            // shorter one can either. `head` carries its own trailing
            // separator (or is empty); the run's bytes start at `tail`.
            //
            // BISECTION IS VALID BECAUSE UNIQUENESS IS MONOTONE IN THE RUN'S
            // LENGTH, and that is a precondition, not an optimisation.
            // Extending a trailing literal run only ADDS constraints, so it
            // can only remove matches, never add one; and the site the bytes
            // were copied from always matches, so the count never reaches
            // zero. The hit count is therefore non-increasing in L and never
            // below 1: unique at length L implies unique at every length
            // greater than L. Without that, a binary search would be a guess
            // -- it never examines most of the lengths it skips.
            //
            // A 64-byte run costs ~7 full-image scans rather than 64. Seven
            // scans of a 137MB image is still not free; that cost is what
            // `prefer_short` buys, which is why it is an option rather than
            // the only behaviour.
            //
            // Never returns 0, and never less than kMinLiteralRun unless
            // `full` is itself below it. An empty run would leave Body with
            // no pattern at all, and one floor across every strategy is
            // easier to reason about than one per shape.
            inline size_t shortest_unique_tail(std::span<const uint8_t> img,
                const std::string& head, const uint8_t* tail, size_t full,
                size_t save_index, bool semantic = false) {
                auto unique_at = [&](size_t len) {
                    if (semantic)
                        return v1::Pattern(head + hex_bytes(tail, len)).find_all(v1::Image{ img }, 2).size() == 1;
                    locate::Compiled comp;
                    // compile() throws only on a malformed pattern; the
                    // heads here are the emitters' own, so this is the same
                    // unreachable guard resolves_uniquely carries.
                    try {
                        comp = locate::compile(head + hex_bytes(tail, len));
                    } catch (...) {
                        return false;
                    }
                    locate::prime(comp, img);
                    // save_index matters to the COUNT, not just to what is
                    // reported: find_all drops a match whose save slot does
                    // not exist. Asking with the candidate's own index is
                    // what makes this test agree with resolves_uniquely.
                    return locate::find_all(img, comp, save_index, 2).size() == 1;
                };
                if (full <= kMinLiteralRun || !unique_at(full))
                    return full;
                // hi is known unique; lo is the floor, and the floor is
                // kMinLiteralRun rather than 1 -- see the note on it. The
                // bisection therefore never examines a length below the
                // floor, so it also never pays for one.
                size_t lo = kMinLiteralRun, hi = full;
                while (lo < hi) {
                    const size_t mid = lo + (hi - lo) / 2;
                    if (unique_at(mid))
                        hi = mid;
                    else
                        lo = mid + 1;
                }
                return hi;
            }

        } // namespace detail

        // Every anchor the image affords for `target`, already seeded.
        // Reproduces the state of the art, and its durability: 33% against a
        // build one minor version away.
        //
        // Single-image by definition -- the literals come from `img`. A
        // candidate whose tail differs in another build is emitted here and
        // DISCARDED by verified(), not repaired. The range-tolerant form
        // (`E8 $ { ' } [3-5] ...`) is not synthesised; producing it would need a
        // diff-based mode comparing both images before emitting, which
        // DESIGN_generate.md does not specify.
        //
        // `prefer_short` inherits exactly that limitation, and it is worth
        // naming separately because it does not merely pass a weak candidate
        // through -- it CHOOSES a shorter one. The trailing literal run is
        // shortened to the least that is unique in THIS image, and a run that
        // long may not be unique in another build. verified() rejects such a
        // candidate; it does not lengthen it back. The trade is deliberate:
        // shorter runs cross fewer instructions and so cross fewer of the
        // things a recompile moves.
        //
        // The set-level rules, which are this function's and not any single
        // strategy's:
        //   * DEDUP KEYS ON THE RESOLVING TRIPLE (pattern, save_index,
        //     anchor_delta), never on the pattern text alone. Two candidates
        //     with identical bytes but a different save_index or anchor_delta
        //     resolve to DIFFERENT addresses -- collapsing them would discard
        //     a distinct anchor, or keep one that resolves elsewhere. Where
        //     the whole triple matches, the FIRST emitted wins, so the block
        //     order below (Xref, Body, StringAnchor, RipRef) is what a caller
        //     sees, and the same image always yields the same set.
        //   * `want` BOUNDS THE TOTAL, not any per-strategy count, and it
        //     counts what survives dedup. A duplicate spends no budget: two
        //     identical patterns are one anchor, and the 72% -> 90% figure
        //     rests on anchors that fail INDEPENDENTLY, which identical ones
        //     do not.
        //   * THE BUDGET IS SPENT ROUND-ROBIN, NOT IN STRATEGY ORDER. Each
        //     strategy fills its OWN bucket (itself capped at `want`, so a
        //     target with 768 callers does not build 768 candidates), and the
        //     buckets are then interleaved: one from Xref, one from Body, one
        //     from StringAnchor, one from RipRef, and around again until
        //     `want` is reached or every bucket is empty.
        //
        //     A sequential fill -- run Xref until the budget is gone, then
        //     Body, then the rest -- is what this used to do, and it is wrong
        //     for the one case that is also the common one. The measured
        //     figure is ~768 call sites per target, so Xref alone always
        //     exhausted `want` and Body, StringAnchor and RipRef never ran at
        //     all; `want=4` against 30 callers returned four Xrefs. That is
        //     not merely a missing feature. The 72% -> 90% claim rests on
        //     anchors that fail INDEPENDENTLY, and N tails harvested from one
        //     build's call sites fail TOGETHER: a recompile that changes the
        //     calling convention, inlines the callee, or moves the code
        //     around every site invalidates all N at once. Four anchors of
        //     four different SHAPES are the independence the figure is
        //     about; four Xrefs are close to one anchor counted four times.
        //
        //     verified()'s oversample does not paper over it: widening `want`
        //     widens the SAME ordered budget, so with more call sites than
        //     `want * kVerifyOversample` the later strategies still never run.
        //
        //     Determinism is unchanged: the strategy order within a round is
        //     fixed (Xref, Body, StringAnchor, RipRef), the order within a
        //     bucket is the order that strategy emitted in, and dedup still
        //     keeps the FIRST of a colliding triple in that same strategy
        //     order -- it runs as candidates enter their buckets, so a
        //     duplicate never occupies a bucket slot either.
        //
        // This does NOT filter by uniqueness in `img` -- verified() is the
        // filter. Xref emits every caller unconditionally; Body uses
        // uniqueness only to SELECT which delta to anchor on (see below), and
        // falls back to delta 0 rather than emitting nothing when no offset
        // is distinctive. Enforcing uniqueness here would also mean a full-
        // image scan per emitted candidate -- 2229 of them for one target in
        // this file's own measured table -- against a 2.5s substrate budget.
        // The rule for every strategy after this one: uniqueness SELECTS, it
        // never SUPPRESSES. StringAnchor choosing which literal and RipRef
        // choosing which `lea` are the same shape as Body choosing its delta;
        // set-level policy (dedup, ranking, discarding weak anchors) is
        // Task 10's, not candidates()'s.
        inline std::vector<Candidate> candidates(const Image& img, uint64_t target,
            const Options& opt = {}) {
            if (opt.dialect != "maml-current" && opt.dialect != "maml-v1")
                throw v1::Error("InvalidArgument", "Unknown generator dialect");
            const bool semantic = opt.dialect == "maml-v1";
            if (opt.nibble_wildcards && !semantic)
                throw v1::Error("InvalidArgument", "Nibble generation requires maml-v1");
            std::vector<Candidate> out;
            const size_t n = img.bytes.size();
            auto seed_for = [&](const std::string& pattern) {
                if (semantic)
                    return v1::Pattern(pattern).select_seed(img.bytes);
                return locate::select_seed(img.bytes, locate::fixed_bytes(pattern));
            };

            // `want` <= 0 asks for nothing, and every loop below would
            // otherwise have to say so itself.
            if (opt.want <= 0)
                return out;
            const size_t cap = (size_t)opt.want;

            using detail::Bucket;
            using detail::kXref, detail::kBody, detail::kStringAnchor,
                detail::kRipRef, detail::kBucketCount;
            std::vector<Candidate> bucket[kBucketCount];

            // The resolving triples already emitted. A vector rather than a
            // set because the buckets are bounded by `want` each (four by
            // default, and verified()'s oversample keeps it in the tens), so
            // the linear scan is cheaper than hashing a pattern string.
            struct Key {
                std::string pattern;
                size_t save_index;
                int64_t anchor_delta;
            };
            std::vector<Key> seen;
            auto emit = [&](Bucket b, Candidate&& c) {
                c.dialect = opt.dialect;
                if (semantic && c.save_index) {
                    c.target_capture = "target";
                    c.save_index = 0;
                }
                for (const Key& k : seen)
                    if (k.save_index == c.save_index && k.anchor_delta == c.anchor_delta && k.pattern == c.pattern)
                        return;
                seen.push_back({ c.pattern, c.save_index, c.anchor_delta });
                bucket[b].push_back(std::move(c));
            };

            for (uint64_t site : callers_of(img, target)) {
                // The PER-STRATEGY cap, which is also what bounds the work:
                // shortening a tail costs ~7 full-image scans, so this loop
                // must not run once per caller on a target with 768 of them.
                if (bucket[kXref].size() >= cap)
                    break;
                const uint64_t after = site + 5;           // past the E8 rel32
                if (after >= n)
                    continue;
                size_t take = (std::min)(opt.max_len, (size_t)(n - after));
                take = clamp_to_func(img, after, take);
                if (take == 0)
                    continue;

                // The tail is a trailing literal run with nothing behind it,
                // so shortening it cannot starve a later atom -- the `'` is
                // filled by the `E8 $ { ' }` in front.
                const std::string kXrefHead = semantic ? "E8 rel32(target) " : "E8 $ { ' } ";
                if (opt.prefer_short)
                    take = detail::shortest_unique_tail(img.bytes, kXrefHead,
                        img.bytes.data() + after, take, 1, semantic);

                Candidate c;
                c.strategy = Strategy::Xref;
                c.anchor_site = site;  // the call site this pattern anchors on
                c.save_index = 1;      // the `'` capture holds the callee
                c.anchor_delta = 0;    // target comes from the slot, not the match
                c.literals = take + 1; // the E8 plus the tail
                c.pattern = kXrefHead + hex_bytes(img.bytes.data() + after, take);

                c.seed = seed_for(c.pattern);
                emit(kXref, std::move(c));
            }

            // Body: anchor directly on the target's own bytes rather than on a
            // caller. There is no capture -- save_index is 0, the whole match
            // -- and anchor_delta records however far past the entry the
            // pattern actually starts. Comparing a Body match straight against
            // the target without subtracting anchor_delta is the trap
            // CLAUDE.md records twice.
            //
            // All four strategies can appear for one target (DESIGN_generate.md);
            // `want` is a per-target anchor BUDGET, not a per-strategy fallback
            // chain -- so Body runs whatever Xref already contributed. It has
            // its own bucket and its own cap, and gating it on the TOTAL is
            // what starved it out entirely on any well-called target.
            //
            // Body anchors only within an executable range: DESIGN_generate.md
            // says section bounds exist so the generator does not anchor on
            // data.
            //
            // Walks a small set of offsets past the entry (`deep_anchor`, on
            // by default), 0 first, moving deeper only when the shallower
            // offset is NOT DISTINCTIVE -- not
            // unique within THIS image at save_index 0. That is the checkable
            // meaning of CLAUDE.md's "the entry bytes are not distinctive, but
            // bytes further in are"; room alone is not a substitute; a window
            // can have plenty of room and still be nothing but repeated filler.
            // If nothing in the set turns out distinctive, the delta-0
            // candidate is still emitted as a fallback -- candidates() reports
            // regardless of quality, same as Xref; verified() is the actual
            // filter. Only one Body candidate is ever produced per target --
            // unlike Xref, Body has exactly one entry point to work from, not
            // one per call site.
            //
            // THE WALK IS GOVERNED BY `deep_anchor`, NOT BY `prefer_short`.
            // Those were the same flag until a review measured what that
            // cost: with the entry bytes repeated elsewhere and distinctive
            // bytes at +4, prefer_short=true emitted a delta-4 candidate that
            // resolved uniquely while prefer_short=false emitted delta 0,
            // which resolves_uniquely then rejected. Nothing said that an
            // option documented as "shortest sufficient context, not longest"
            // also decided WHERE Body anchored. `prefer_short` now means tail
            // length and nothing else.
            {
                bool target_in_code = false;
                for (const Range& r : img.code)
                    if (target >= r.begin && target < r.end) {
                        target_in_code = true;
                        break;
                    }

                if (target_in_code) {
                    static constexpr uint64_t kDeltas[] = { 0, 4, 8, 16, 32, 64 };
                    std::optional<Candidate> fallback; // delta 0's candidate, if none is distinctive

                    for (uint64_t delta : kDeltas) {
                        const uint64_t anchor = target + delta;
                        if (anchor >= n)
                            break;      // deeper offsets only move further past the end

                        // The walk can move the anchor past the target's own
                        // function -- or out of executable code entirely --
                        // once delta > 0. That was unreachable before the
                        // walk could ever advance past delta 0; apply the
                        // same "don't anchor on data" rule to the anchor
                        // that already applies to the target.
                        bool anchor_in_code = false;
                        for (const Range& r : img.code)
                            if (anchor >= r.begin && anchor < r.end) {
                                anchor_in_code = true;
                                break;
                            }
                        if (!anchor_in_code) {
                            if (!opt.deep_anchor)
                                break;  // not willing to search further for one
                            continue;   // try the next, deeper offset
                        }

                        size_t take = (std::min)(opt.max_len, (size_t)(n - anchor));
                        take = clamp_to_func(img, anchor, take);
                        if (take == 0)
                            break;      // no room here; a deeper offset has even less

                        Candidate c;
                        c.strategy = Strategy::Body;
                        c.anchor_site = anchor;       // target + delta, where the run starts
                        c.save_index = 0;             // no capture -- the match itself
                        c.anchor_delta = (int64_t)delta;
                        c.literals = take;
                        c.pattern = hex_bytes(img.bytes.data() + anchor, take);

                        bool distinctive = false;
                        try {
                            if (semantic)
                                distinctive = v1::Pattern(c.pattern).find_all(v1::Image{ img.bytes }, 2).size() == 1;
                            else {
                                auto comp = locate::compile(c.pattern);
                                locate::prime(comp, img.bytes);
                                distinctive = locate::find_all(img.bytes, comp, 0, 2).size() == 1;
                            }
                        } catch (...) {
                            distinctive = false;
                        }

                        if (distinctive) {
                            // Body's whole pattern IS the trailing literal
                            // run, and nothing follows it, so prefer_short
                            // shortens it to the least that stays unique.
                            // Only reachable when the full window is already
                            // unique, which is the bisection's precondition.
                            if (opt.prefer_short) {
                                const size_t keep = detail::shortest_unique_tail(
                                    img.bytes, "", img.bytes.data() + anchor, take, 0, semantic);
                                c.literals = keep;
                                c.pattern = hex_bytes(img.bytes.data() + anchor, keep);
                            }
                            c.seed = seed_for(c.pattern);
                            emit(kBody, std::move(c));
                            fallback.reset();
                            break;      // found a distinctive anchor -- stop here
                        }

                        if (!fallback) {
                            c.seed = seed_for(c.pattern);
                            fallback = std::move(c); // remember delta 0's candidate
                        }
                        if (!opt.deep_anchor)
                            break;      // not willing to search further for one
                        // else: try the next, deeper offset
                    }

                    // Not shortened: the fallback is the candidate no offset
                    // made unique, and a run that is not unique at its full
                    // length is unique at no shorter one either.
                    if (fallback)
                        emit(kBody, std::move(*fallback));
                }
            }

            // StringAnchor: anchor on the instruction that LOADS a distinctive
            // string constant. DESIGN_generate.md calls this the most durable
            // shape, and the reason is that a string literal is source-level
            // text: it survives the compiler decisions that move, reorder and
            // reallocate every instruction around it. Release builds strip
            // diagnostic strings but keep UI text, so the filter is on what the
            // string IS, not on whether one exists.
            //
            // Two conditions SELECT the string to anchor on -- they never
            // suppress a candidate from another strategy, which is why this
            // runs as its own block rather than gating anything above it:
            //   (a) content-unique in the string table. strings() dedupes by
            //       RVA, not by content, so the same text emitted into two
            //       rodata slots is two entries. BOTH are disqualified, not
            //       just the second: anchoring on either would be anchoring on
            //       whichever slot the next build's linker happened to keep.
            //   (b) loaded from exactly one site. A string loaded from two
            //       functions does not name a function, and the pattern built
            //       from either lea would be one of two equally good matches.
            //
            // DEPTH BOUND -- STRUCTURAL, NOT A TUNING KNOB. Exactly two cases
            // are emitted: the load site is in the target's own function
            // (depth 0), or it is in a function that calls the target directly
            // (depth 1). Callers-of-callers are deliberately NOT chased, and
            // the reason is the dialect rather than cost: `E8 $ { ' }` resolves
            // exactly ONE call edge, so from two edges away the `'` capture
            // names the INTERMEDIATE function, not the target. A two-hop
            // pattern would therefore have to match the intermediate function's
            // own entry bytes -- precisely the fragile thing Body already
            // covers, dressed up as a string anchor. Raising the bound does not
            // buy reach; it buys a worse Body candidate.
            //
            // COST: this used to call rip_refs_to() -- a full-image scan --
            // once per content-unique string, which is quadratic in a way no
            // fixture here can show. On the 133MB image the table holds 85,232
            // content-unique strings and ONE target took 71 minutes; the whole
            // 132-target corpus extrapolated to ~156 hours. It now builds
            // rip_lea_index() once, in a single pass, and looks each string up.
            // The strategy's rules are unchanged -- only where the answer
            // comes from.
            {
                static constexpr int kMaxStringAnchorDepth = 1;

                const std::vector<Str> strs = strings(img);
                const uint8_t* base = img.bytes.data();

                auto content_of = [&](const Str& s) {
                    return std::string_view((const char*)base + s.rva, s.len);
                };

                // Computed once over the table, not once per candidate: this is
                // a string-table comparison, not the full-image scan the header
                // note above rules out for uniqueness checks.
                std::unordered_map<std::string_view, size_t> occurrences;
                for (const Str& s : strs)
                    if (s.rva + s.len <= n)
                        ++occurrences[content_of(s)];

                // One pass instead of one scan per string. Only the strings
                // that can still qualify are indexed, so the map does not
                // carry all ~385,000 `lea` targets a real image holds.
                std::unordered_set<uint64_t> wanted;
                for (const Str& s : strs)
                    if (s.rva + s.len <= n && occurrences[content_of(s)] == 1)
                        wanted.insert(s.rva);
                const auto lea_index = rip_lea_index(img, wanted);

                const std::vector<uint64_t> to_target = callers_of(img, target);
                const Range* target_fn = enclosing_func(img, target);

                // Ascending RVA, because strings() guarantees that order and a
                // generator that emits a different anchor set on the same image
                // is not reproducible.
                for (const Str& s : strs) {
                    if (bucket[kStringAnchor].size() >= cap)
                        break;
                    if (s.rva + s.len > n)
                        continue;
                    if (occurrences[content_of(s)] != 1)
                        continue;

                    const auto it = lea_index.find(s.rva);
                    if (it == lea_index.end() || it->second.size() != 1)
                        continue;
                    const uint64_t site = it->second[0];
                    const uint64_t after = site + 7; // past 48 8D modrm disp32
                    if (after > n)
                        continue;

                    // THE DISPLACEMENT IS WILDCARDED, AND THAT IS THE WHOLE
                    // POINT. The string's address moves between builds; the
                    // lea's presence and position do not. Four separate `?`
                    // atoms, because `?` is ONE byte in this dialect -- `??` is
                    // two bytes, not "a wildcard run". Rendering the disp32 as
                    // literals would produce a pattern that matches only the
                    // image it was generated from: unique in one build, absent
                    // from the second, which is the entire premise of the
                    // library failing quietly.
                    const std::string lea =
                        hex_bytes(base + site, 3) + (semantic ? " ?? ?? ?? ??" : " ? ? ? ?");

                    const bool at_target = target_fn && site >= target_fn->begin && site < target_fn->end;
                    const int depth = at_target ? 0 : 1;
                    if (depth > kMaxStringAnchorDepth)
                        continue;

                    if (depth == 0) {
                        // The lea itself is the anchor, and it sits
                        // anchor_delta bytes into the target's own function --
                        // exactly Body's convention, SUBTRACT FROM THE MATCH TO
                        // GET THE TARGET.
                        //
                        // max_len is a budget on the whole pattern, so the tail
                        // gets what the seven lea bytes leave. Depth 1 below
                        // measures its span the same way; the two forms of one
                        // strategy agreeing matters more here than matching
                        // Xref, which budgets its tail alone.
                        if (opt.max_len <= 7)
                            continue;
                        size_t take = (std::min)(opt.max_len - 7, (size_t)(n - after));
                        take = clamp_to_func(img, after, take);
                        if (take == 0)
                            continue;

                        // Depth 0 ends in a trailing literal run with nothing
                        // behind it -- unlike depth 1 below -- so prefer_short
                        // may shorten it.
                        if (opt.prefer_short)
                            take = detail::shortest_unique_tail(img.bytes, lea + " ",
                                base + after, take, 0, semantic);

                        Candidate c;
                        c.strategy = Strategy::StringAnchor;
                        c.anchor_site = site; // the lea that loads the string
                        c.save_index = 0; // no capture -- the match itself
                        c.anchor_delta = (int64_t)site - (int64_t)target;
                        c.literals = 3 + take; // the four `?` are not literals
                        c.pattern = lea + " " + hex_bytes(base + after, take);

                        c.seed = seed_for(c.pattern);
                        emit(kStringAnchor, std::move(c));
                        continue;
                    }

                    // Depth 1: the pattern spans lea -> call, and the target
                    // comes out of the `'` capture rather than out of the match
                    // position, exactly as Xref's does.
                    if (opt.max_len < 12)
                        continue; // 7 lea bytes plus a 5-byte call, minimum
                    const uint64_t call_hi = site + opt.max_len - 5; // inclusive

                    // The FIRST call to the target at or after the lea. Bounded
                    // by the enclosing function when funcs says what that is --
                    // and when it does not, bounded only by the budget: R8's
                    // rule is that an unknown function bound is not guessed at.
                    const Range* site_fn = enclosing_func(img, site);
                    uint64_t call = 0;
                    bool found = false;
                    for (uint64_t cs : to_target) { // ascending
                        if (cs < after)
                            continue;
                        if (cs > call_hi)
                            break; // past the budget, and to_target only grows
                        if (site_fn && cs + 5 > site_fn->end)
                            continue;
                        call = cs;
                        found = true;
                        break;
                    }
                    // Nothing rather than a truncated pattern: a tail cut short
                    // of the call would not reach the `E8`, so the `'` slot
                    // would never be filled and the candidate could not resolve
                    // to anything at all.
                    if (!found)
                        continue;

                    const size_t gap = (size_t)(call - after);

                    // PREFER_SHORT DELIBERATELY DOES NOT TOUCH THIS GAP. It
                    // is not a trailing run: the `E8 $ { ' }` behind it is
                    // what fills the save slot, and a gap cut short of the
                    // call reaches no `E8`, so the pattern captures nothing
                    // and resolves to nothing. Shortening is only ever
                    // applied to a run no later atom depends on.
                    Candidate c;
                    c.strategy = Strategy::StringAnchor;
                    c.anchor_site = site; // the lea, again -- not the call it reaches
                    c.save_index = 1;   // the `'` capture holds the callee
                    c.anchor_delta = 0; // target comes from the slot, not the match
                    c.literals = 3 + gap + 1; // lea opcode, gap, and the E8
                    c.pattern = lea;
                    if (gap)
                        c.pattern += " " + hex_bytes(base + after, gap);
                    c.pattern += semantic ? " E8 rel32(target)" : " E8 $ { ' }";

                    c.seed = seed_for(c.pattern);
                    emit(kStringAnchor, std::move(c));
                }
            }

            // RipRef: anchor on an instruction that RIP-relatively references
            // the target and let the disp32 name it. Exactly Xref's shape --
            // literal opcode bytes, then `$ { ... ' }`, save_index 1 and
            // anchor_delta 0 -- over a disp32 instead of a rel32, which is why
            // it reaches globals at all: a global has no call site for Xref to
            // work from and no entry bytes for Body.
            //
            // THE CORRECTIVE SKIP IS THE POINT. `$` computes (cursor + 4) +
            // disp32; RIP-relative addressing resolves against the END of the
            // instruction. Those agree only while the disp32 is the last field,
            // so a form carrying a trailing immediate needs `[4]` or `[1]`
            // inside the block to walk the cursor the rest of the way before
            // `'` saves. Omitting it does not fail loudly: the pattern still
            // matches, still reports one hit, and captures an address a few
            // bytes below a real global. The immediate width comes from the
            // table row, never from an assumption -- rip_operand_refs_to
            // reports nothing for an encoding the table does not know.
            //
            // The displacement is NOT rendered as literals: it is what the
            // pattern is reading, and it moves between builds.
            //
            // A LITERAL TAIL FOLLOWS THE BLOCK, exactly as Xref's does, and it
            // is not optional decoration. Two or three opcode bytes plus a
            // capture is not a pattern, it is an INSTRUCTION SELECTOR:
            // `48 8B 0D $ { ' }` says "some `mov rcx, [rip+X]`", and a real
            // image has hundreds of those. Such a candidate reports many hits,
            // resolves_uniquely rejects it, and verified() returns nothing --
            // which mattered more than it sounds, because Xref, Body and
            // StringAnchor all anchor on CODE and none of them can name a
            // global at all. Without the tail, a global had no working
            // strategy. It went unnoticed through nine reviews because every
            // fixture here fills with 0xCC, where the opcode occurs exactly
            // once and the context-free form is unique by accident of the
            // fixture.
            //
            // WHERE THE TAIL STARTS. The `{`/`}` pair pushes the cursor at the
            // disp32 and pops it back with a +4 advance, so after `}` the
            // cursor sits at site + disp_off + 4 -- just past the
            // displacement, regardless of what the `$` inside the block
            // jumped to. That is BEFORE any trailing immediate, so a form
            // carrying one gets its immediate as the first literal bytes of
            // the tail. That is a feature: `48 C7 05 <disp32> 01 00 00 00`
            // stores a specific constant, and "the site that writes 1 to this
            // global" is far more distinctive than "a site that writes to it".
            // (The `[N]` skip inside the block is a separate thing entirely --
            // it walks the CAPTURE's cursor so `'` names the right address,
            // and it does not move the outer cursor at all.)
            //
            // max_len now binds here -- it used to be documented as inert --
            // and it budgets the WHOLE pattern the way StringAnchor's does:
            // the opcode bytes come out of it first and the tail gets what is
            // left. `prefer_short` also applies, on the same terms as Xref's
            // tail: nothing follows the run, so shortening it cannot starve a
            // later atom, and the `'` is filled from inside the block in
            // front of it.
            {
                const uint8_t* base = img.bytes.data();
                for (const RipOperandRef& ref : rip_operand_refs_to(img, target)) {
                    if (bucket[kRipRef].size() >= cap)
                        break;
                    const RipForm& f = *ref.form;
                    const size_t head_len = f.opcode_len + 1u; // opcode bytes plus the modrm

                    std::string head = hex_bytes(base + ref.site, head_len);
                    if (semantic) {
                        head += " rel32(target";
                        if (f.imm_width)
                            head += ", target_add=" + std::to_string(f.imm_width);
                        head += ")";
                    } else {
                        head += " $ { ";
                        if (f.imm_width)
                            head += "[" + std::to_string(f.imm_width) + "] ";
                        head += "' }";
                    }

                    // Past the disp32, which is where `}` leaves the cursor.
                    const uint64_t after = ref.site + f.disp_off + 4u;
                    size_t take = 0;
                    if (after < n && opt.max_len > head_len) {
                        take = (std::min)(opt.max_len - head_len, (size_t)(n - after));
                        take = clamp_to_func(img, after, take);
                        if (take && opt.prefer_short)
                            take = detail::shortest_unique_tail(img.bytes, head + " ",
                                base + after, take, 1, semantic);
                    }

                    // No room for context leaves the bare `48 8B 0D $ { ' }`
                    // selector -- three literal bytes and a capture, exactly
                    // the shape that cannot be unique on a real image and that
                    // the tail exists to prevent. Skip the site rather than
                    // emit something verified() must discard.
                    if (take == 0)
                        continue;

                    Candidate c;
                    c.strategy = Strategy::RipRef;
                    c.anchor_site = ref.site; // the referencing instruction
                    c.save_index = 1;   // the `'` capture holds the global
                    c.anchor_delta = 0; // target comes from the slot, not the match
                    c.literals = head_len + take;
                    c.pattern = head + " " + hex_bytes(base + after, take);

                    c.seed = seed_for(c.pattern);
                    emit(kRipRef, std::move(c));
                }
            }

            // THE INTERLEAVE. One from each bucket per round, in the fixed
            // strategy order, until `want` is reached or nothing is left --
            // see the round-robin note in this function's header comment for
            // why the budget is spent this way rather than in strategy order.
            for (size_t round = 0; out.size() < cap; ++round) {
                bool any = false;
                for (size_t b = 0; b < kBucketCount; ++b) {
                    if (round >= bucket[b].size())
                        continue;
                    any = true;
                    if (out.size() >= cap)
                        break;
                    out.push_back(std::move(bucket[b][round]));
                }
                if (!any)
                    break; // every bucket exhausted
            }
            return out;
        }

        // Not part of the proposed public surface (DESIGN_generate.md) --
        // an implementation helper that verified() uses internally. Keeping
        // it out of the generate:: namespace means its signature is not a
        // breaking change for callers of this header.
        namespace detail {

            // True when `c.pattern` matches exactly once in `img` and that
            // match resolves to `want`. Uniqueness uses find_all with limit
            // 2: it stops at the second hit rather than enumerating every
            // match in a 137MB image.
            inline std::optional<uint64_t> resolve_semantic(std::span<const uint8_t> image, const Candidate& c) {
                if (c.dialect != "maml-v1" || c.save_index != 0)
                    throw v1::Error("InvalidArgument", "Invalid semantic candidate metadata");
                const v1::Pattern pattern(c.pattern);
                if (!c.target_capture.empty()) {
                    if (c.anchor_delta)
                        throw v1::Error("InvalidArgument", "A captured target cannot also use anchor_delta");
                    (void)v1::Match{ 0, pattern.schema(), {} }.capture(c.target_capture);
                }
                const auto hits = pattern.find_all(v1::Image{ image }, 2);
                if (hits.size() != 1)
                    return std::nullopt;
                if (!c.target_capture.empty()) {
                    auto value = hits[0].capture(c.target_capture);
                    if (!value || value->space != "image")
                        return std::nullopt;
                    return value->value;
                }
                uint64_t target;
                if (c.anchor_delta >= 0) {
                    if (hits[0].offset < uint64_t(c.anchor_delta))
                        return std::nullopt;
                    return hits[0].offset - uint64_t(c.anchor_delta);
                }
                const uint64_t magnitude = uint64_t(-(c.anchor_delta + 1)) + 1;
                if (!v1::add(hits[0].offset, magnitude, target))
                    return std::nullopt;
                return target;
            }

            inline bool resolves_uniquely(std::span<const uint8_t> img,
                const Candidate& c, uint64_t want) {
                if (c.dialect == "maml-v1")
                    return resolve_semantic(img, c) == want;
                if (c.dialect != "maml-current")
                    throw v1::Error("InvalidArgument", "Unknown candidate dialect");
                locate::Compiled comp;
                // compile() can throw on a malformed pattern; the patterns
                // candidates() builds always parse, so this is unreachable
                // today and exists for a caller that constructs a Candidate
                // by hand. prime() and find_all() are deliberately left
                // outside the try: the matcher's scan path cannot throw
                // anything but bad_alloc -- every throw site is in the
                // parser (established in Phase 1).
                try {
                    comp = locate::compile(c.pattern);
                } catch (...) {
                    return false;
                }
                locate::prime(comp, img);
                const auto hits = locate::find_all(img, comp, c.save_index, 2);
                if (hits.size() != 1)
                    return false;
                // A capture-bearing candidate reads its target from the SAVE
                // SLOT; one without a capture recovers it from the match
                // position, minus the delta. Comparing a Body match directly
                // against the target is the failure CLAUDE.md records twice.
                //
                // The test is on save_index, not on the strategy enum. Xref is
                // no longer the only capturing strategy -- StringAnchor's
                // depth-1 form ends in the same `E8 $ { ' }` and carries
                // save_index 1 -- and keying on the enum silently rejected
                // every one of those as resolving to its own match offset.
                // save_index 0 IS the match offset (slot 0 is where the pattern
                // matched), so the two branches stay exactly as they were for
                // Xref and Body.
                const uint64_t got = c.save_index != 0
                    ? hits[0].value
                    : (uint64_t)((int64_t)hits[0].offset - c.anchor_delta);
                return got == want;
            }

        } // namespace detail

        // Unique in BOTH, resolving to its own target in each. This is the one
        // to use: 72% survival against a build one minor version away, and 90%
        // once each target carries several anchors on distinct call sites.
        //
        // Requiring a match in two compilations is not a validation step bolted
        // on at the end -- it is the mechanism that forces the pattern onto code
        // both compilers agreed on, which is the code least likely to move.
        //
        // Returns a SET, not one answer: four anchors on four call sites fail
        // independently, and that independence is the whole of the 72% -> 90%
        // difference.
        //
        // RETURNING FEWER THAN `want` IS NORMAL. RETURNING ZERO IS NORMAL.
        // This is a filter, not a generator with a quota: most targets in a
        // real image do not afford four anchors that are unique in both
        // builds, and plenty afford none. An empty result means "this image
        // pair offers no durable pattern for this address", which is a
        // correct and useful answer -- it is the answer a signature tool that
        // reports one-build uniqueness gets WRONG 67% of the time. A caller
        // must not read a short result as a failure of this function, retry
        // with a bigger `want` (the oversample below already does that
        // internally), or fall back to an unverified candidates() result.
        //
        // The returned Candidate::seed was chosen against image A. It stays a
        // valid starting point, but a consumer scanning image B should
        // re-prime: seed choice is a property of the (pattern, image) pair, not
        // of the pattern alone.
        //
        // `want` here means anchors that WORK, so this asks candidates() for
        // more than it needs and stops at the first `want` that survive both
        // images. Without the oversample a caller gets `want` ATTEMPTS:
        // candidates() caps at `want` and every rejection below is then a
        // permanent shortfall, which puts the 90%-at-want-4 figure out of
        // reach by construction -- it needs four anchors that survive, not
        // four that were tried. candidates()'s own contract is unchanged; a
        // caller of candidates() still gets exactly `want`.
        // What a set of anchors resolves to in a NEW image, grouped by the
        // address they agree on and ordered by how many agreed.
        //
        // This exists because a single clean hit is not proof. Measured across
        // four real builds with a BinDiff function mapping as ground truth,
        // 5-13% of dual-build-verified patterns that matched EXACTLY ONCE in a
        // later build resolved to the WRONG function -- more often than they
        // matched ambiguously, and just as silently.
        //
        // Two or more anchors agreeing on one address were correct 25 times out
        // of 25 in that measurement (>= 88% at 95% confidence by the rule of
        // three). Agreement needs no symbols and no ground truth, so unlike
        // uniqueness it is a check a caller can apply in the field.
        //
        // The intended read is groups.front(): take it when it holds two or
        // more anchors, take nothing when the leader is alone or the top two
        // are tied. The count travels with the address for that reason -- a
        // caller that wants to ignore the evidence has to do so deliberately.
        struct Resolution {
            uint64_t address = 0;              // what these anchors resolved to
            std::vector<size_t> anchors;       // indices into the input vector
        };

        inline std::vector<Resolution> resolve_consensus(
            std::span<const uint8_t> image, const std::vector<Candidate>& cands) {
            std::vector<Resolution> out;
            for (size_t i = 0; i < cands.size(); ++i) {
                const Candidate& c = cands[i];
                uint64_t got;
                if (c.dialect == "maml-v1") {
                    auto resolved = detail::resolve_semantic(image, c);
                    if (!resolved)
                        continue;
                    got = *resolved;
                } else {
                    if (c.dialect != "maml-current")
                        throw v1::Error("InvalidArgument", "Unknown candidate dialect");
                    auto comp = locate::compile(c.pattern);
                    locate::prime(comp, image);
                    // limit 2: an anchor matching more than once has told us
                    // nothing, and enumerating the rest of a 133MB image to learn
                    // that is pure cost. Such an anchor does not get to vote --
                    // otherwise ambiguity would inflate a consensus instead of
                    // being excluded from it.
                    const auto hits = locate::find_all(image, comp, c.save_index, 2);
                    if (hits.size() != 1)
                        continue;
                    got = c.save_index != 0
                              ? hits[0].value
                              : (uint64_t)((int64_t)hits[0].offset - c.anchor_delta);
                }
                auto it = std::find_if(out.begin(), out.end(),
                    [&](const Resolution& r) { return r.address == got; });
                if (it == out.end())
                    out.push_back({ got, { i } });
                else
                    it->anchors.push_back(i);
            }
            // Most-agreed first; address order breaks ties so the result is
            // reproducible rather than dependent on candidate order.
            std::stable_sort(out.begin(), out.end(),
                [](const Resolution& x, const Resolution& y) {
                    if (x.anchors.size() != y.anchors.size())
                        return x.anchors.size() > y.anchors.size();
                    return x.address < y.address;
                });
            return out;
        }

        inline std::vector<Candidate> verified(const Image& a, uint64_t target_a,
            const Image& b, uint64_t target_b,
            const Options& opt = {}) {
            // TWO BUILDS MEANS TWO BUILDS. Handed the same image twice, this
            // would verify every single-image candidate against itself and
            // return a full set of patterns with NO evidence of durability
            // behind them -- a tail carrying an absolute `mov rax, imm64`
            // sails through, and that immediate is exactly the kind of thing
            // a recompile moves. That is not a weak result, it is a WRONG
            // one: it reproduces the 33% state of the art while reporting the
            // 72% figure. The whole premise of this header is that the second
            // compilation is independent evidence, so refuse rather than
            // pretend.
            //
            // Pointer-and-size identity, deliberately: it catches the mistake
            // that actually happens (`verified(img, t, img, t)`, which this
            // project's own test suite did in four places) without scanning
            // two 137MB buffers for equality. Two distinct buffers holding
            // identical bytes are not caught, and are not meant to be -- a
            // caller who copies an image to get past this is no longer making
            // an honest mistake.
            if (a.bytes.data() == b.bytes.data() && a.bytes.size() == b.bytes.size())
                return {};

            // Oversample by a factor of four to leave room for candidates
            // rejected during verification and strategies with no output.
            constexpr int kVerifyOversample = 4;

            // Multiplied by the bucket count, not the oversample factor alone.
            // candidates() spends its budget round-robin, so a request for N
            // is shared across the live strategies: ask for N*4 with two live
            // buckets and each gets ~N*2 attempts, not the N*4 the factor
            // above reasons about. Measured at want=1 -- four callers where
            // only the fourth tail survives into B, plus a Body eligible in A
            // and not in B -- the widened set was `Xref Body Xref Xref`, the
            // surviving fourth Xref was never built, and this returned 0.
            Options wide = opt;
            constexpr int kWiden = kVerifyOversample * (int)detail::kBucketCount;
            if (opt.want > 0 && opt.want <= (std::numeric_limits<int>::max)() / kWiden)
                wide.want = opt.want * kWiden;

            std::vector<Candidate> out;
            auto accept = [&](Candidate c) {
                if (!detail::resolves_uniquely(a.bytes, c, target_a) || !detail::resolves_uniquely(b.bytes, c, target_b))
                    return;
                for (const auto& old : out) {
                    if (old.pattern == c.pattern && old.anchor_delta == c.anchor_delta && old.target_capture == c.target_capture && old.save_index == c.save_index && old.dialect == c.dialect)
                        return;
                    if (c.dialect == "maml-v1" && old.strategy == c.strategy && old.anchor_site == c.anchor_site)
                        return;
                }
                out.push_back(std::move(c));
            };
            auto source = candidates(a, target_a, wide);
            for (const auto& c : source) {
                if ((int)out.size() >= opt.want)
                    break;
                accept(c);
            }
            if (opt.nibble_wildcards && (int)out.size() < opt.want) {
                // Pair linear programs only. Full tails align by structure,
                // not by guessed instruction boundaries or string edits.
                wide.prefer_short = false;
                source = candidates(a, target_a, wide);
                const auto peers = candidates(b, target_b, wide);
                for (const auto& ca : source) {
                    if ((int)out.size() >= opt.want)
                        break;
                    for (const auto& cb : peers) {
                        if ((int)out.size() >= opt.want)
                            break;
                        if (ca.strategy != cb.strategy || ca.anchor_delta != cb.anchor_delta || ca.target_capture != cb.target_capture)
                            continue;
                        const v1::Pattern pa(ca.pattern), pb(cb.pattern);
                        auto merged = pa.generalize(pb);
                        if (!merged || *merged == ca.pattern)
                            continue;
                        Candidate c = ca;
                        c.pattern = *merged;
                        const v1::Pattern compiled(c.pattern);
                        c.literals = compiled.fixed_literal_count();
                        c.seed = compiled.select_seed(a.bytes);
                        accept(std::move(c));
                    }
                }
            }
            return out;
        }

    } // namespace generate
} // namespace maml

#endif // MAML_GENERATE_HPP
