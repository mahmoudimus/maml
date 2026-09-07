// maml::pipeline -- a small language for FINDING an address.
//
// Composed entirely from substrate generate.hpp already derives: the string
// table, the rip-relative lea index, the call graph, and function bounds. See
// the stage definitions below for the model; every
// stage maps a SET of addresses to a set of addresses, and a pipeline is
// stages composed left to right:
//
//     str "GetActivePlayerObj" -> xref -> func
//     bytes "48 89 5C 24 08 57" -> func -> callers -> unique
//
// It is a discovery aid: run it, get an address, hand that address to
// generate::verified() to obtain byte patterns. It is not a signature, and
// nothing here claims anything about how a pipeline survives a rebuild --
// that is unmeasured, and the durability harness measures it before any such
// claim is made.
//
// NOT in the include/maml.hpp umbrella, deliberately, for the same reason
// generate.hpp is not: a downstream project vendors maml.hpp and
// mamlscan.hpp by copying exactly those two files.
#ifndef MAML_PIPELINE_HPP
#define MAML_PIPELINE_HPP

#include "maml/generate.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace maml {
    namespace pipeline {

        enum class Op {
            Str, // seed: rodata addresses whose NUL-terminated run == text
            Bytes, // seed: match offsets of a maml pattern, save_index 0
            Find, // filter: match a pattern INSIDE each input's function
            Xref, // sites referencing each input
            Callers, // call sites targeting each input
            Func, // the enclosing function of each input
            Unique, // identity, but FAILS unless the set holds exactly one
            Nth, // the K-th in ascending order
            Limit, // the first N in ascending order
            Read // terminal: N little-endian bytes at each input, as VALUES
        };

        // A seed stage ignores its input and produces a set from the image.
        //
        // `find` is deliberately NOT one, and that is the whole difference
        // between it and `bytes`. `bytes` scans img.bytes and discards its
        // input, so a chain like `str -> xref -> func -> bytes "..."` throws
        // away the narrowing the first three stages did and the pattern has
        // to be unique image-wide. Measured over 71 downstream targets, the
        // minimal unique byte prefix is a median of 14 bytes image-wide
        // against 3 bytes within the target's own function.
        inline bool is_seed(Op op) {
            return op == Op::Str || op == Op::Bytes;
        }

        // A terminal stage produces something other than addresses, so
        // nothing can follow it. Enforced in parse(), not at run time: a
        // pipeline that would feed field offsets to `xref` is a mistake in
        // the TEXT, and catching it at parse means a jobfile is rejected
        // before any image is touched.
        inline bool is_terminal(Op op) {
            return op == Op::Read;
        }

        struct Stage {
            Op op = Op::Str;
            std::string text; // Str/Bytes/Find payload, already unescaped
            uint64_t n = 0; // Nth's K, Limit's N, Read's width

            // `func:strict` rather than `func`: fail if this stage REPLACED
            // any address rather than merely locating it.
            //
            // The property belongs to the TRANSITION, not to the address set,
            // which is why it could never be a filter -- an `entry` stage
            // placed after `func` can never reject anything, because by then
            // every address is a function start by construction. Strictness is
            // also per-use: for a target that is a function entry,
            // `func:strict` asserts that assumption; for a target that is
            // a mid-function displacement, moving is CORRECT and plain `func`
            // is right.
            bool strict = false;

            std::string repr; // canonical rendering; what the trace names
        };

        // Cardinality in and out of one stage. Recorded for EVERY stage that
        // ran, because a caller that silently takes the first of three
        // addresses is making the mistake this project measured: 5-13% of
        // patterns resolving to exactly one address in a later build resolve
        // to the WRONG one, with nothing marking the answer suspect. The
        // trace is how a caller sees that its "one" address was one of three.
        struct StageResult {
            std::string stage;
            size_t in = 0;
            size_t out = 0;

            // Outputs that were NOT in this stage's input. For `xref` and
            // `callers` that is nearly everything and says little; for `func`
            // it is the signal that matters, because `func` REPLACES an
            // address with the entry of the function containing it.
            //
            // A pipeline ending in `func` can only ever answer with a function
            // ENTRY. Given a target that sits mid-function it returns the
            // enclosing entry and reports OK -- a category error, not a miss,
            // and silent. Downstream this showed up as three targets
            // (entry+0xc0, +0xaf, +0xe0) all resolving "successfully" to one
            // address, none of them a function start. `moved > 0` on a `func`
            // stage is how a caller sees that its address was REPLACED rather
            // than located.
            size_t moved = 0;
        };

        // What the numbers in `PipelineResult::addresses` MEAN. Every stage
        // but `read` yields addresses; `read` yields the values it loaded,
        // and the two are not interchangeable -- a consumer that treats a
        // structure field displacement as an address dereferences garbage,
        // and nothing else in the result would say otherwise.
        enum class ResultKind { Address,
            Value };

        struct PipelineResult {
            bool ok = false; // ended with >= 1 address, and nothing failed
            // Addresses, or -- when `kind` is Value -- the values `read`
            // loaded. One vector rather than two, because every stage but
            // the terminal one produces addresses and a second vector would
            // be empty in every pipeline that exists today.
            std::vector<uint64_t> addresses;
            ResultKind kind = ResultKind::Address;
            std::vector<StageResult> trace; // one entry per stage that COMPLETED
            // The stage to look at, or SIZE_MAX. For a parse error or missing
            // substrate that is the stage that failed. For `unique` it is the
            // stage that INTRODUCED the ambiguity, which is earlier than the
            // `unique` itself -- see the Op::Unique case in run(). So
            // `failed_stage` is not in general `trace.size()`.
            size_t failed_stage = SIZE_MAX;
            std::string error; // parse or execution detail
        };

        // An empty result is NOT a failure. `ok` means "ended with at least
        // one address"; a pipeline that legitimately finds nothing returns
        // ok=false with an empty `error` and failed_stage == SIZE_MAX. A
        // failing `unique`, a parse error, or missing substrate sets `error`.
        // Keeping those distinct is the point: "not found" and "not
        // configured" are different answers, and R4 below exists because
        // returning empty for both makes them indistinguishable.
        inline bool failed(const PipelineResult& r) {
            return !r.error.empty();
        }

        namespace detail {

            inline bool in_ranges(std::span<const generate::Range> rs, uint64_t at) {
                for (const generate::Range& r : rs)
                    if (at >= r.begin && at < r.end)
                        return true;
                return false;
            }

            inline void sort_unique(std::vector<uint64_t>& v) {
                std::sort(v.begin(), v.end());
                v.erase(std::unique(v.begin(), v.end()), v.end());
            }

            inline std::string quote(std::string_view s) {
                std::string out = "\"";
                for (unsigned char c : s) {
                    if (c == '"')
                        out += "\\\"";
                    else if (c == '\\')
                        out += "\\\\";
                    else if (c == '\n')
                        out += "\\n";
                    else if (c == '\t')
                        out += "\\t";
                    else if (c < 0x20 || c == 0x7F) {
                        static const char* kHex = "0123456789ABCDEF";
                        out += "\\x";
                        out += kHex[c >> 4];
                        out += kHex[c & 0xF];
                    } else
                        out += (char)c;
                }
                out += "\"";
                return out;
            }

            inline int hex_digit(char c) {
                if (c >= '0' && c <= '9')
                    return c - '0';
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;
                return -1;
            }

            inline bool word_char(char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_';
            }

        } // namespace detail

        // The canonical rendering of a stage, which is what its trace entry is
        // named by. Round-trips through parse().
        inline std::string to_string(const Stage& s) {
            switch (s.op) {
            case Op::Str:
                return "str " + detail::quote(s.text);
            case Op::Bytes:
                return "bytes " + detail::quote(s.text);
            case Op::Find:
                return "find " + detail::quote(s.text);
            case Op::Xref:
                return "xref";
            case Op::Callers:
                return "callers";
            case Op::Func:
                return s.strict ? "func:strict" : "func";
            case Op::Unique:
                return "unique";
            case Op::Nth:
                return "nth " + std::to_string(s.n);
            case Op::Limit:
                return "limit " + std::to_string(s.n);
            case Op::Read:
                return "read " + std::to_string(s.n);
            }
            return "?";
        }

        struct Program {
            bool ok = true;
            std::vector<Stage> stages;
            size_t failed_stage = SIZE_MAX;
            std::string error;
        };

        // pipeline := stage ( "->" stage )*
        // stage    := op ( ":" MODIFIER )?
        // op       := "str" STRING | "bytes" STRING | "find" STRING
        //            | "xref" | "callers" | "func" | "unique"
        //            | "nth" INT | "limit" INT | "read" (1|2|4|8)
        // MODIFIER := "strict" | "loose"       -- `func` only, no whitespace
        // STRING   := '"' ... '"'      escapes: \" \\ \n \t \xHH
        //
        // `->` rather than `|`, because the pattern dialect already uses `|`
        // for alternation inside `( ... )` and a `bytes` stage embeds that
        // dialect whole.
        //
        // Never throws and never crashes: a malformed pipeline out of a
        // jobfile comes back as ok=false with `failed_stage` at the offending
        // stage. `failed_stage` counts arrows consumed, so it indexes the
        // stage the reader is looking at even when that stage is incomplete.
        //
        // RULING, not in the grammar: the first stage must be a seed and no
        // later stage may be. The grammar cannot say it, but `str` in the
        // middle would silently discard everything to its left, and a
        // pipeline starting with `xref` has nothing to reference. Both are
        // caller mistakes that would otherwise surface as a quietly empty or
        // quietly wrong answer.
        //
        // The same shape of ruling for `read`, from the other end: it is
        // TERMINAL, so nothing may follow it. Its output is values, not
        // addresses, and a following `xref` or `func` would interpret a
        // structure field displacement as an RVA and answer confidently from
        // an unrelated part of the image.
        inline Program parse(std::string_view src) {
            Program p;
            size_t i = 0;
            const size_t n = src.size();
            size_t index = 0; // index of the stage being read

            auto fail = [&](const std::string& msg) {
                p.ok = false;
                p.failed_stage = index;
                p.error = msg;
                p.stages.clear();
                return p;
            };
            auto skip_ws = [&] {
                while (i < n && (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' ||
                                    src[i] == '\n'))
                    ++i;
            };
            auto at_arrow = [&] {
                return i + 1 < n && src[i] == '-' && src[i + 1] == '>';
            };

            skip_ws();
            if (i >= n)
                return fail("empty pipeline");

            for (;;) {
                skip_ws();
                if (i >= n)
                    return fail("expected a stage");
                if (at_arrow())
                    return fail("expected a stage, found '->'");
                if (!detail::word_char(src[i])) {
                    std::string c(1, src[i]);
                    return fail("expected a stage name, found '" + c + "'");
                }
                const size_t ws = i;
                while (i < n && detail::word_char(src[i]))
                    ++i;
                std::string word(src.substr(ws, i - ws));

                Stage st;

                // MODIFIERS ATTACH TO THEIR STAGE WITH `:`, as in
                // `func:strict`.
                //
                // The colon is a QUALIFIER, not a separator -- read it the way
                // CSS reads `a:hover`: the same `a`, in a particular state.
                // That is the relationship here, and it is why a modifier is
                // not spelled with either operator the language already has.
                // `func | strict` borrows the pattern dialect's alternation
                // character and needs `|` to bind tighter than `->`, a
                // precedence rule nothing on the line states -- a reader
                // coming from a shell sees one flat chain with two spellings
                // of the same pipe. `strict(func)` needs no such rule, but
                // reads inside-out in a pipeline that otherwise reads left to
                // right, and borrows the dialect's group parentheses just as
                // much as `|` borrows its bar.
                //
                // A sigil was the other candidate and is worse than all three:
                // `func!` reads as negation, which is the exact opposite of
                // the assertion it makes.
                //
                // NO WHITESPACE is permitted around the colon. Its absence is
                // what makes `func:strict -> unique` scan as two stages rather
                // than three, with nothing for a reader to be told.
                std::string modifier;
                if (i < n && src[i] == ':') {
                    ++i;
                    if (i >= n || !detail::word_char(src[i]))
                        return fail(word + ": expected a modifier name after ':'");
                    const size_t ms = i;
                    while (i < n && detail::word_char(src[i]))
                        ++i;
                    modifier = src.substr(ms, i - ms);
                    if (modifier != "strict" && modifier != "loose")
                        return fail("unknown modifier '" + modifier + "' on " +
                                    word + "; the modifiers are `strict` and "
                                    "`loose`");
                } else {
                    // `func :strict` and `func : strict`. Caught here because
                    // falling through leaves the top of the loop reporting
                    // "expected '->'" at the colon, which says nothing about
                    // why the colon is wrong.
                    const size_t save = i;
                    skip_ws();
                    if (i < n && src[i] == ':')
                        return fail("a modifier attaches to its stage with no "
                                    "spaces: write `" + word + ":<modifier>`");
                    i = save;
                }
                auto read_string = [&](std::string& out) -> bool {
                    skip_ws();
                    if (i >= n || src[i] != '"')
                        return false;
                    ++i;
                    while (i < n && src[i] != '"') {
                        if (src[i] != '\\') {
                            out += src[i++];
                            continue;
                        }
                        ++i;
                        if (i >= n)
                            return false;
                        const char e = src[i++];
                        if (e == '"')
                            out += '"';
                        else if (e == '\\')
                            out += '\\';
                        else if (e == 'n')
                            out += '\n';
                        else if (e == 't')
                            out += '\t';
                        else if (e == 'x') {
                            if (i + 1 >= n)
                                return false;
                            const int hi = detail::hex_digit(src[i]);
                            const int lo = detail::hex_digit(src[i + 1]);
                            if (hi < 0 || lo < 0)
                                return false;
                            out += (char)(uint8_t)((hi << 4) | lo);
                            i += 2;
                        } else
                            return false;
                    }
                    if (i >= n)
                        return false; // no closing quote
                    ++i;
                    return true;
                };
                auto read_int = [&](uint64_t& out) -> bool {
                    skip_ws();
                    const size_t ds = i;
                    while (i < n && src[i] >= '0' && src[i] <= '9')
                        ++i;
                    if (i == ds || i - ds > 19)
                        return false;
                    out = 0;
                    for (size_t k = ds; k < i; ++k)
                        out = out * 10 + (uint64_t)(src[k] - '0');
                    return true;
                };

                // A stage after a terminal one, checked BEFORE the stage
                // itself is read so that `read 4 -> nth 0` reports the
                // `nth`, not a complaint about `nth`'s argument.
                if (index != 0 && !p.stages.empty() &&
                    is_terminal(p.stages.back().op))
                    return fail(word + ": nothing may follow '" +
                                p.stages.back().repr +
                                "', which yields values rather than addresses");

                if (word == "str" || word == "bytes" || word == "find") {
                    st.op = (word == "str") ? Op::Str
                        : (word == "bytes") ? Op::Bytes
                                            : Op::Find;
                    if (!read_string(st.text))
                        return fail(word + ": expected a double-quoted string "
                                           "(escapes: \\\" \\\\ \\n \\t \\xHH)");
                    if (index != 0 && is_seed(st.op))
                        return fail(word + ": a seed stage is only valid as the "
                                           "first stage");
                } else if (word == "read") {
                    st.op = Op::Read;
                    // 1, 2, 4 or 8 only. A `read 3` has no little-endian
                    // meaning that a caller and this code would agree on, and
                    // silently rounding it to 4 would read a byte the pattern
                    // never claimed.
                    if (!read_int(st.n) || (st.n != 1 && st.n != 2 && st.n != 4 &&
                                               st.n != 8))
                        return fail("read: expected a width of 1, 2, 4 or 8 bytes");
                } else if (word == "xref") {
                    st.op = Op::Xref;
                } else if (word == "callers") {
                    st.op = Op::Callers;
                } else if (word == "func") {
                    st.op = Op::Func;
                } else if (word == "unique") {
                    st.op = Op::Unique;
                } else if (word == "nth" || word == "limit") {
                    st.op = (word == "nth") ? Op::Nth : Op::Limit;
                    if (!read_int(st.n))
                        return fail(word + ": expected a non-negative integer");
                } else {
                    return fail("unknown stage '" + word + "'");
                }

                if (!modifier.empty()) {
                    // `loose` is the default spelled out. It exists so a
                    // caller can say "moving is expected here" rather than
                    // leaving a reader to wonder whether strictness was
                    // forgotten.
                    if (modifier == "strict")
                        st.strict = true;
                    // Deliberately checked AFTER the stage name resolves, so
                    // `bogus:strict` reports the unknown stage rather than
                    // the modifier.
                    if (st.op != Op::Func)
                        return fail(word + ":" + modifier +
                                    " -- modifiers apply to `func` only; " +
                                    word + " has no located-vs-replaced "
                                    "distinction to assert");
                }

                if (index == 0 && !is_seed(st.op))
                    return fail(word + ": the first stage must seed the set "
                                       "(str or bytes)");

                st.repr = to_string(st);
                p.stages.push_back(st);

                skip_ws();
                if (i >= n)
                    break;
                if (!at_arrow()) {
                    std::string c(1, src[i]);
                    return fail("expected '->' between stages, found '" + c + "'");
                }
                i += 2;
                ++index;
            }
            return p;
        }

        namespace detail {

            // Substrate built ONCE per run, never once per stage. Scanning per
            // string is the shape of a defect this codebase already paid for:
            // one target took 71 MINUTES on the 133MB image it exists for,
            // because rip_refs_to() was being called per string.
            struct Substrate {
                const generate::Image& img;
                bool have_strings = false;
                std::vector<generate::Str> strs;

                // The lea index is keyed by target, and rip_lea_index() wants
                // the target set up front. `wanted` records what the current
                // index covers; a query for targets already covered costs
                // nothing, and one asking for new targets rebuilds over the
                // union. A pipeline has at most one data-`xref` stage in
                // practice, so that is one pass.
                std::unordered_set<uint64_t> wanted;
                std::unordered_map<uint64_t, std::vector<uint64_t>> lea;
                bool have_lea = false;

                explicit Substrate(const generate::Image& i) : img(i) {}

                const std::vector<generate::Str>& string_table() {
                    if (!have_strings) {
                        strs = generate::strings(img);
                        have_strings = true;
                    }
                    return strs;
                }

                const std::unordered_map<uint64_t, std::vector<uint64_t>>&
                lea_index(const std::vector<uint64_t>& targets) {
                    bool need = !have_lea;
                    for (uint64_t t : targets)
                        if (!wanted.count(t)) {
                            wanted.insert(t);
                            need = true;
                        }
                    if (need) {
                        lea = generate::rip_lea_index(img, wanted);
                        have_lea = true;
                    }
                    return lea;
                }
            };

        } // namespace detail

        // Run an already-parsed program. Never throws: a bad `bytes` pattern
        // is reported the same way a parse error is.
        namespace detail {
        inline PipelineResult run_with(Substrate& sub, const generate::Image& img,
            const std::vector<Stage>& stages) {
            PipelineResult r;
            std::vector<uint64_t> set;

            for (size_t idx = 0; idx < stages.size(); ++idx) {
                const Stage& st = stages[idx];
                const size_t in = set.size();
                std::vector<uint64_t> out;

                auto fail = [&](const std::string& msg) {
                    r.ok = false;
                    r.failed_stage = idx;
                    r.error = msg;
                    r.addresses.clear();
                    return r;
                };

                switch (st.op) {
                case Op::Str: {
                    // R4: no rodata means every `str` answers empty, which is
                    // indistinguishable from "the string is not there".
                    if (img.rodata.empty())
                        return fail("str: image has no rodata ranges, so no string "
                                    "table can be built");
                    const auto& table = sub.string_table();
                    for (const generate::Str& s : table) {
                        if (s.len != st.text.size())
                            continue;
                        if (s.rva + s.len > img.bytes.size())
                            continue;
                        if (std::equal(st.text.begin(), st.text.end(),
                                img.bytes.begin() + (ptrdiff_t)s.rva))
                            out.push_back(s.rva);
                    }
                    break;
                }
                case Op::Bytes: {
                    try {
                        locate::Compiled c = locate::compile(st.text);
                        locate::prime(c, img.bytes);
                        for (const locate::Hit& h : locate::find_all(img.bytes, c, 0))
                            out.push_back((uint64_t)h.value);
                    } catch (const std::exception& e) {
                        return fail(std::string("bytes: ") + e.what());
                    }
                    break;
                }
                case Op::Find: {
                    // A FILTER, not a seed: the pattern is matched inside the
                    // function enclosing each input address, so it only has
                    // to be unique THERE. That is the entire point -- 3 bytes
                    // at the median within a function against 14 image-wide
                    // -- and it is why the search itself is scoped rather
                    // than the results being filtered afterwards. Scanning
                    // img.bytes and keeping the hits that land in range would
                    // give the same answers for a long pattern and thousands
                    // of candidates for a short one, which is exactly the
                    // pattern this stage exists to make usable.
                    //
                    // R4: without `funcs` there is no scope, and answering
                    // empty would be indistinguishable from "the pattern is
                    // not in the function".
                    if (img.funcs.empty())
                        return fail("find: image has no funcs ranges, so there is "
                                    "no scope to search");

                    // Which slot to emit: the capture if the pattern has one,
                    // otherwise the match offset. Detected by scanning the
                    // TEXT for `'`, which is sufficient because `'` has
                    // exactly one role in this dialect -- it marks a save
                    // point, it is not a quote, an escape, or part of any
                    // literal, and a pattern is hex digits, `?`, `$`, `'`,
                    // and the grouping punctuation. Compiling the pattern to
                    // count its save slots would be the same answer at more
                    // cost, and would need a second compile to ask.
                    const size_t save_index =
                        st.text.find('\'') == std::string::npos ? 0u : 1u;

                    locate::Compiled c;
                    try {
                        c = locate::compile(st.text);
                    } catch (const std::exception& e) {
                        return fail(std::string("find: ") + e.what());
                    }

                    // Each function searched ONCE, however many input
                    // addresses land in it: two call sites in one function
                    // would otherwise scan it twice and produce the same
                    // hits twice.
                    std::vector<const generate::Range*> scopes;
                    for (uint64_t a : set) {
                        const generate::Range* f = generate::enclosing_func(img, a);
                        // R3: an address in no function is skipped, exactly
                        // as `func` skips it -- `funcs` IS configured, so
                        // "no enclosing function" is a real answer.
                        if (!f)
                            continue;
                        bool seen = false;
                        for (const generate::Range* s : scopes)
                            if (s->begin == f->begin && s->end == f->end)
                                seen = true;
                        if (!seen)
                            scopes.push_back(f);
                    }

                    for (const generate::Range* f : scopes) {
                        if (f->begin >= img.bytes.size() || f->end <= f->begin)
                            continue;
                        const size_t end =
                            (size_t)(std::min)((uint64_t)img.bytes.size(), f->end);
                        std::span<const uint8_t> body = img.bytes.subspan(
                            (size_t)f->begin, end - (size_t)f->begin);
                        // Primed per scope: seed choice is a property of the
                        // (pattern, image) pair, and here the "image" is this
                        // one function's bytes.
                        locate::prime(c, body);
                        for (const locate::Hit& h : locate::find_all(body, c, save_index))
                            out.push_back(f->begin + (uint64_t)h.value);
                    }
                    break;
                }
                case Op::Xref: {
                    // RULING, not a law: an address inside a `code` range is
                    // referenced by CALLS, so xref uses the call graph; an
                    // address outside it is data, referenced by RIP-relative
                    // operands, so xref uses the lea index. It means xref on a
                    // code address will not find a `lea` that takes the
                    // function's address -- `callers` and a future `datarefs`
                    // stage stay available where the caller knows better.
                    if (img.code.empty())
                        return fail("xref: image has no code ranges, so no "
                                    "reference can be found");
                    std::vector<uint64_t> data_targets;
                    for (uint64_t a : set) {
                        if (detail::in_ranges(img.code, a)) {
                            for (uint64_t s : generate::callers_of(img, a))
                                out.push_back(s);
                        } else if (detail::in_ranges(img.rodata, a)) {
                            data_targets.push_back(a);
                        } else {
                            // R4 again: without a range covering it, "which
                            // index" has no answer, and returning empty would
                            // read as "nothing references it".
                            char buf[32];
                            snprintf(buf, sizeof buf, "%llx", (unsigned long long)a);
                            return fail(std::string("xref: address 0x") + buf +
                                        " is in neither a code nor a rodata range, "
                                        "so no index applies");
                        }
                    }
                    if (!data_targets.empty()) {
                        const auto& index = sub.lea_index(data_targets);
                        for (uint64_t a : data_targets) {
                            auto it = index.find(a);
                            if (it == index.end())
                                continue;
                            for (uint64_t s : it->second)
                                out.push_back(s);
                        }
                    }
                    break;
                }
                case Op::Callers: {
                    if (img.code.empty())
                        return fail("callers: image has no code ranges, so no call "
                                    "site can be found");
                    for (uint64_t a : set)
                        for (uint64_t s : generate::callers_of(img, a))
                            out.push_back(s);
                    break;
                }
                case Op::Func: {
                    if (img.funcs.empty())
                        return fail("func: image has no funcs ranges, so no "
                                    "enclosing function is known");
                    for (uint64_t a : set)
                        if (const generate::Range* f = generate::enclosing_func(img, a))
                            out.push_back(f->begin);
                    // Addresses with no enclosing function are dropped, which
                    // is not a failure: `funcs` IS configured here, so an
                    // address outside every one of them genuinely has no
                    // answer.
                    break;
                }
                case Op::Unique: {
                    if (set.size() != 1) {
                        // `unique` names the stage that INTRODUCED the
                        // ambiguity, not its own index. That is the whole
                        // diagnostic value of it: for
                        // `str -> xref -> func -> unique` over a string with
                        // two referents (cardinalities 1, 2, 2) this reports
                        // stage 1, which says the STRING was referenced from
                        // several places -- a different problem from
                        // `str -> xref -> func -> callers -> unique` reporting
                        // stage 3, which says the FUNCTION has several callers.
                        // Blaming `unique` itself would name the same index
                        // every time and say nothing.
                        //
                        // The rule: walk back over the contiguous run of
                        // stages that did not end at exactly one, and blame
                        // the first of them. A stage that widened the set and
                        // a later stage that narrowed it back to one cannot be
                        // reached, because the run stops at the narrowing.
                        // The loop always takes at least one step, since the
                        // preceding stage's `out` IS this set's size.
                        size_t blame = idx;
                        while (blame > 0 && r.trace[blame - 1].out != 1)
                            --blame;
                        r.ok = false;
                        r.failed_stage = blame;
                        r.error = "unique: expected exactly 1 address, got " +
                                  std::to_string(set.size()) + " (from stage " +
                                  std::to_string(blame) + ": " +
                                  (blame < stages.size() ? stages[blame].repr : st.repr) +
                                  ")";
                        r.addresses.clear();
                        return r;
                    }
                    out = set;
                    break;
                }
                case Op::Nth: {
                    // R3: past the end is the empty set, cleanly.
                    if (st.n < set.size())
                        out.push_back(set[(size_t)st.n]);
                    break;
                }
                case Op::Limit: {
                    const size_t take = (size_t)(std::min)((uint64_t)set.size(), st.n);
                    out.assign(set.begin(), set.begin() + (ptrdiff_t)take);
                    break;
                }
                case Op::Read: {
                    // TERMINAL, and the parser has already refused anything
                    // after it. What comes out is what the bytes SAY, not
                    // where they are, which is what `kind` records.
                    const size_t width = (size_t)st.n;
                    for (uint64_t a : set) {
                        // R10: a read that would run past the end is DROPPED,
                        // never truncated. Half a displacement is not a
                        // smaller displacement, it is a different number, and
                        // a zero-padded one would be indistinguishable from a
                        // field at offset 0.
                        if (a >= img.bytes.size() || width > img.bytes.size() - a)
                            continue;
                        uint64_t v = 0;
                        for (size_t k = 0; k < width; ++k)
                            v |= (uint64_t)img.bytes[(size_t)a + k] << (8 * k);
                        out.push_back(v);
                    }
                    r.kind = ResultKind::Value;
                    break;
                }
                }

                // Sorted and deduplicated after every stage, so the answer
                // never depends on the order stages happened to discover
                // things -- and so `nth` and `limit` mean "in ascending
                // order" rather than "in discovery order".
                //
                // `read`'s VALUES go through the same treatment, deliberately
                // and not as an oversight: they come back ascending and
                // deduplicated, so N addresses can yield fewer than N values
                // when several of them hold the same number -- which is the
                // common case for a field offset read at two call sites, and
                // the answer a caller wants. The alternative, values parallel
                // to the addresses that produced them, needs a second vector
                // and a positional correspondence that `unique` and `limit`
                // would then have to preserve.
                detail::sort_unique(out);
                // Counted BEFORE the swap, while `set` is still the input:
                // results this stage produced that were not already in its
                // input. On `func` that is exactly the count of addresses
                // replaced by an enclosing entry.
                //
                // Not computed for `read`, where `out` holds values and
                // `set` holds addresses: comparing the two is a category
                // error, and a field offset that happened to equal an input
                // RVA would report a "move" that never occurred.
                size_t moved = 0;
                if (st.op != Op::Read)
                    for (uint64_t a : out)
                        if (!std::binary_search(set.begin(), set.end(), a))
                            ++moved;
                set.swap(out);
                r.trace.push_back({ st.repr, in, set.size(), moved });

                // Recorded first, then failed: the trace has to show the stage
                // that rejected and by how much, or the error names a stage
                // the caller cannot see.
                if (st.op == Op::Func && st.strict && moved > 0) {
                    r.ok = false;
                    r.failed_stage = idx;
                    r.error = "func:strict: " + std::to_string(moved) +
                        " address(es) were not function entries and were "
                        "replaced by the enclosing function; use `func` if "
                        "that is intended";
                    // AFTER `xref` OR `callers` THIS CAN ESSENTIALLY NEVER
                    // PASS, and the plain message above reads like a finding
                    // when it is really a category error. Both stages yield
                    // the SITE of a reference, and a site is mid-function by
                    // definition unless the reference happens to be a
                    // function's first instruction -- so the replacement
                    // `func:strict` refuses is the stage's normal work.
                    //
                    // Measured: over 60 targets in a real 42 MB image where
                    // `str -> xref -> func -> unique` succeeded, adding
                    // :strict rejected 60 of 60 -- the correct answers along
                    // with the wrong ones. A guard that rejects everything is
                    // not discriminating, it is off.
                    //
                    // It is not made a PARSE error because the exception is
                    // real: a function whose first instruction carries the
                    // reference does resolve to its own entry. Rare, not
                    // impossible. So this says so here, where the confusion
                    // actually happens, rather than refusing to run.
                    if (idx > 0 && (stages[idx - 1].op == Op::Xref
                                    || stages[idx - 1].op == Op::Callers)) {
                        r.error += ". NOTE: this follows `"
                            + stages[idx - 1].repr
                            + "`, which yields the SITE of a reference -- "
                              "mid-function by definition -- so `func:strict` "
                              "will reject nearly every input here. It is "
                              "meant for a set you already believe holds "
                              "entries, such as after `bytes \"<prologue>\"`. "
                              "Use plain `func`";
                    }
                    return r;
                }
            }

            r.addresses = set;
            r.ok = !set.empty();
            return r;
        }

        // Parse and run. A parse error comes back as ok=false with `error`
        // set and `failed_stage` at the offending stage -- not an exception.
        } // namespace detail

        inline PipelineResult run(const generate::Image& img,
            const std::vector<Stage>& stages) {
            detail::Substrate sub(img);
            return detail::run_with(sub, img, stages);
        }

        // One image, many pipelines, one substrate.
        //
        // run() builds its substrate per call, which is right for a one-shot:
        // about 19 ms on a 42MB image, of which 16.5 ms is the single rip-lea
        // pass. Put a thousand pipelines through it and that is a thousand
        // full-image scans -- the shape of the defect that cost StringAnchor
        // 71 minutes per target, one level up. Measured: 200 jobs took 3,478 ms
        // through run() against 17.8 ms through a Session, 196x.
        //
        // preload_string_targets() indexes every string in ONE pass. Without
        // it the index still rebuilds whenever a job introduces a target the
        // union has not seen, which for a jobfile of distinct strings is every
        // single job.
        class Session {
        public:
            explicit Session(const generate::Image& img)
                : img_(img), sub_(img_) {}

            void preload_string_targets() {
                std::vector<uint64_t> all;
                for (const generate::Str& st : sub_.string_table())
                    all.push_back(st.rva);
                sub_.lea_index(all);
            }

            PipelineResult run(std::string_view src) {
                Program p = parse(src);
                if (!p.ok) {
                    PipelineResult r;
                    r.ok = false;
                    r.failed_stage = p.failed_stage;
                    r.error = p.error;
                    return r;
                }
                return detail::run_with(sub_, img_, p.stages);
            }

        private:
            // BY VALUE, deliberately. `Image` is four spans over storage the
            // caller owns, so copying is free -- and holding a reference made
            // the natural call site, `Session s(img.view())`, bind to a
            // temporary that died on the next line.
            //
            // A test pins the temporary case but cannot ENFORCE it on its own:
            // reading freed stack memory is undefined behaviour that happens
            // to work here, so the test passes either way. The sanitizer CI
            // leg is what enforces it -- reverting this to a reference gives
            // "AddressSanitizer: stack-use-after-scope" there.
            //
            // The spans still alias the caller's buffers -- the Image is cheap
            // to copy precisely because it owns none of them -- so the bytes
            // and ranges must outlive the Session.
            generate::Image img_;
            detail::Substrate sub_;
        };

        inline PipelineResult run(const generate::Image& img, std::string_view src) {
            Program p = parse(src);
            if (!p.ok) {
                PipelineResult r;
                r.ok = false;
                r.failed_stage = p.failed_stage;
                r.error = p.error;
                return r;
            }
            return run(img, p.stages);
        }

    } // namespace pipeline
} // namespace maml

#endif // MAML_PIPELINE_HPP
