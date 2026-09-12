// SPDX-License-Identifier: BSL-1.0 OR MIT
#pragma once
#include "generate.hpp"
#include "v1.hpp"

namespace maml::v1 {
    struct Trace {
        std::string stage;
        size_t into = 0;
        size_t out = 0;
    };
    struct PipelineResult {
        bool is_matches = false;
        std::vector<std::string> schema;
        std::vector<Match> matches;
        std::vector<Value> values;
        std::vector<Trace> trace;
        bool ok() const {
            return is_matches ? !matches.empty() : !values.empty();
        }
    };
    class Pipeline {
        struct Stage {
            std::string name, argument, modifier;
            uint64_t number = 0;
            std::optional<Pattern> pattern;
        };
        std::vector<Stage> stages_;
        static bool in(std::span<const maml::generate::Range> ranges, uint64_t a) {
            for (auto r : ranges)
                if (r.begin <= a && a < r.end)
                    return true;
            return false;
        }

    public:
        explicit Pipeline(std::string_view source) {
            if (source.size() > 65536)
                throw Error("ResourceLimit", "Pipeline exceeds 65536 characters");
            size_t p = 0;
            auto ws = [&] {
                while (p < source.size() && std::isspace(static_cast<unsigned char>(source[p])))
                    ++p;
            };
            auto need = [&](char c) {
                ws();
                if (p == source.size() || source[p++] != c)
                    throw Error("InvalidSyntax", std::string("Expected '") + c + "'", p);
            };
            bool matches = false;
            std::vector<std::string> schema;
            while (true) {
                ws();
                size_t begin = p;
                while (p < source.size() && (std::isalpha(static_cast<unsigned char>(source[p])) || source[p] == '_'))
                    ++p;
                Stage s;
                s.name = std::string(source.substr(begin, p - begin));
                const bool directional = s.name == "before" || s.name == "after";
                const bool text = directional || s.name == "str" || s.name == "bytes" || s.name == "find" || s.name == "capture";
                const bool numeric = s.name == "nth" || s.name == "limit" || s.name == "read";
                if (text || numeric) {
                    need('(');
                    if (text) {
                        need('"');
                        bool closed = false;
                        while (p < source.size()) {
                            char c = source[p++];
                            if (c == '"') {
                                closed = true;
                                break;
                            }
                            if (c == '\\') {
                                if (p == source.size())
                                    throw Error("InvalidSyntax", "Unterminated escape", p);
                                c = source[p++];
                                if (c == 'n')
                                    c = '\n';
                                else if (c == 't')
                                    c = '\t';
                                else if (c == 'x') {
                                    if (source.size() - p < 2)
                                        throw Error("InvalidSyntax", "Truncated hex escape", p);
                                    unsigned byte = 0;
                                    auto r = std::from_chars(source.data() + p, source.data() + p + 2, byte, 16);
                                    if (r.ec != std::errc{} || r.ptr != source.data() + p + 2)
                                        throw Error("InvalidSyntax", "Invalid hex escape", p);
                                    p += 2;
                                    c = char(byte);
                                } else if (c != '"' && c != '\\')
                                    throw Error("InvalidSyntax", "Unknown escape", p);
                            }
                            s.argument += c;
                        }
                        if (!closed)
                            throw Error("InvalidSyntax", "Unterminated string", p);
                    } else {
                        ws();
                        size_t start = p;
                        while (p < source.size() && std::isdigit(static_cast<unsigned char>(source[p])))
                            ++p;
                        auto r = std::from_chars(source.data() + start, source.data() + p, s.number);
                        if (r.ec != std::errc{} || r.ptr != source.data() + p)
                            throw Error("InvalidArgument", "Expected unsigned decimal integer", p);
                        if (s.name == "read" && s.number != 1 && s.number != 2 && s.number != 4 && s.number != 8)
                            throw Error("InvalidArgument", "read width must be 1, 2, 4, or 8", p);
                    }
                    if (directional) {
                        need(',');
                        ws();
                        if (source.substr(p, 6) != "within")
                            throw Error("InvalidArgument", "Expected within=N", p);
                        p += 6;
                        need('=');
                        ws();
                        size_t start = p;
                        while (p < source.size() && std::isdigit(static_cast<unsigned char>(source[p])))
                            ++p;
                        auto parsed = std::from_chars(source.data() + start, source.data() + p, s.number);
                        if (start == p || parsed.ec != std::errc{})
                            throw Error("InvalidArgument", "within must be an unsigned 64-bit integer", start);
                    }
                    need(')');
                } else if (s.name != "xrefs" && s.name != "func" && s.name != "callers" && s.name != "unique")
                    throw Error("InvalidSyntax", "Unknown pipeline stage: " + s.name, p);
                const size_t modifier_begin = p;
                ws();
                if (p < source.size() && source[p] == ':') {
                    if (s.name != "func" || p != modifier_begin)
                        throw Error("InvalidModifier", "Only func accepts an attached :strict or :loose", p);
                    const size_t colon = p++;
                    const size_t start = p;
                    while (p < source.size() && (std::isalnum(static_cast<unsigned char>(source[p])) || source[p] == '_'))
                        ++p;
                    s.modifier = std::string(source.substr(start, p - start));
                    if (s.modifier != "strict" && s.modifier != "loose")
                        throw Error("InvalidModifier", "Expected func:strict or func:loose", colon);
                    ws();
                    if (p < source.size() && source[p] == ':')
                        throw Error("InvalidModifier", "Repeated func modifier", p);
                }
                const bool seed = s.name == "str" || s.name == "bytes";
                if (seed != stages_.empty())
                    throw Error("InvalidSyntax", "A pipeline must start with exactly one source", begin);
                if (s.name == "bytes" || s.name == "find" || directional) {
                    s.pattern.emplace(s.argument);
                    schema = s.pattern->schema();
                    matches = true;
                } else if (s.name == "capture") {
                    if (!matches)
                        throw Error("InvalidType", "capture requires match records", begin);
                    if (std::find(schema.begin(), schema.end(), s.argument) == schema.end())
                        throw Error("UnknownCapture", "Unknown capture: " + s.argument, begin);
                    matches = false;
                    schema.clear();
                } else if (s.name != "unique" && s.name != "nth" && s.name != "limit") {
                    matches = false;
                    schema.clear();
                }
                stages_.push_back(std::move(s));
                ws();
                if (p == source.size())
                    break;
                need('-');
                need('>');
            }
        }
        PipelineResult run(const Image& image, std::span<const maml::generate::Range> code = {},
            std::span<const maml::generate::Range> rodata = {}, std::span<const maml::generate::Range> funcs = {},
            std::span<const maml::generate::Range> instructions = {}) const {
            std::map<uint64_t, uint64_t> instruction_ends;
            for (auto ins : instructions) {
                if (ins.begin >= ins.end || ins.end > image.bytes.size())
                    throw Error("InvalidArgument", "Invalid instruction range");
                auto [it, inserted] = instruction_ends.emplace(ins.begin, ins.end);
                if (!inserted && it->second != ins.end)
                    throw Error("InvalidArgument", "Conflicting instruction lengths");
            }
            maml::generate::Image indexed{ image.bytes, code, rodata, funcs };
            PipelineResult r;
            auto count = [&] {
                return r.is_matches ? r.matches.size() : r.values.size();
            };
            auto offset = [&](const Value& v) {
                if (v.space != "image" || v.kind == "AbsolutePointerValue" || v.kind == "ReadValue")
                    throw Error("InvalidType", "Address stage requires an image address; pointers are not implicitly mapped");
                if (v.value < image.base)
                    throw Error("InvalidArgument", "Address precedes image base");
                return v.value - image.base;
            };
            auto address = [&](uint64_t at) {
                uint64_t a;
                if (!add(image.base, at, a))
                    throw Error("InvalidArgument", "Address overflow");
                return Value{ a, "CursorAddress", "image" };
            };
            for (const auto& s : stages_) {
                const size_t before = count();
                if (s.name == "unique") {
                    if (count() != 1)
                        throw Error("Cardinality", "unique requires exactly one element");
                } else if (s.name == "nth" || s.name == "limit") {
                    auto select = [&](auto& items) {
                        if (s.name == "limit") {
                            if (s.number < items.size())
                                items.resize(size_t(s.number));
                        } else if (s.number >= items.size())
                            items.clear();
                        else {
                            auto item = std::move(items[size_t(s.number)]);
                            items.clear();
                            items.push_back(std::move(item));
                        }
                    };
                    if (r.is_matches)
                        select(r.matches);
                    else
                        select(r.values);
                } else if (s.name == "capture") {
                    r.values = project(r.schema, r.matches, s.argument);
                    r.matches.clear();
                    r.schema.clear();
                    r.is_matches = false;
                } else if (s.name == "bytes") {
                    r.matches = s.pattern->find_all(image);
                    r.schema = s.pattern->schema();
                    r.is_matches = true;
                } else {
                    std::vector<uint64_t> inputs;
                    if (r.is_matches) {
                        for (const auto& m : r.matches)
                            inputs.push_back(m.offset);
                    } else {
                        for (const auto& v : r.values)
                            inputs.push_back(offset(v));
                    }
                    r.matches.clear();
                    r.values.clear();
                    r.schema.clear();
                    r.is_matches = false;
                    if (s.name == "str") {
                        if (rodata.empty())
                            throw Error("MissingMetadata", "str requires rodata ranges");
                        for (const auto& str : maml::generate::strings(indexed))
                            if (str.len == s.argument.size() && std::equal(s.argument.begin(), s.argument.end(), image.bytes.begin() + ptrdiff_t(str.rva)))
                                r.values.push_back(address(str.rva));
                    } else if (s.name == "before" || s.name == "after") {
                        std::set<uint64_t> emitted;
                        size_t attempts = 0;
                        std::sort(inputs.begin(), inputs.end());
                        inputs.erase(std::unique(inputs.begin(), inputs.end()), inputs.end());
                        for (auto anchor : inputs) {
                            if (anchor > image.bytes.size())
                                throw Error("InvalidArgument", "Anchor outside image");
                            uint64_t lo = 0, hi = anchor, end_min = 0, end_max = image.bytes.size();
                            if (s.name == "before") {
                                end_min = anchor > s.number ? anchor - s.number : 0;
                                end_max = anchor;
                                const auto extent = s.pattern->sequential_extent_bound();
                                lo = end_min > extent ? end_min - extent : 0;
                            } else {
                                auto ins = instruction_ends.find(anchor);
                                if (ins == instruction_ends.end())
                                    throw Error("MissingMetadata", "after requires an instruction range at every anchor");
                                lo = ins->second;
                                hi = lo + std::min<uint64_t>(s.number, image.bytes.size() - lo);
                            }
                            for (uint64_t at = lo; at <= hi; ++at) {
                                if (emitted.contains(at))
                                    continue;
                                if (++attempts > 1000000)
                                    throw Error("ResourceLimit", "Directional search exceeds 1000000 start attempts");
                                if (auto m = s.pattern->match_at(image, at, 1000000, end_min, end_max)) {
                                    emitted.insert(at);
                                    r.matches.push_back(std::move(*m));
                                }
                            }
                        }
                        std::sort(r.matches.begin(), r.matches.end(), [](const Match& a, const Match& b) {
                            return a.offset < b.offset;
                        });
                        r.is_matches = true;
                        r.schema = s.pattern->schema();
                    } else if (s.name == "find") {
                        if (funcs.empty())
                            throw Error("MissingMetadata", "find requires function ranges");
                        std::set<std::pair<uint64_t, uint64_t>> scopes;
                        for (auto at : inputs)
                            if (auto f = maml::generate::enclosing_func(indexed, at))
                                scopes.insert({ f->begin, f->end });
                        std::set<uint64_t> visited;
                        for (auto [lo, hi] : scopes)
                            for (uint64_t at = lo; at < std::min<uint64_t>(hi, image.bytes.size()); ++at)
                                if (visited.insert(at).second)
                                    if (auto m = s.pattern->match_at(image, at))
                                        r.matches.push_back(std::move(*m));
                        std::sort(r.matches.begin(), r.matches.end(), [](const Match& a, const Match& b) {
                            return a.offset < b.offset;
                        });
                        r.is_matches = true;
                        r.schema = s.pattern->schema();
                    } else if (s.name == "func") {
                        if (funcs.empty())
                            throw Error("MissingMetadata", "func requires function ranges");
                        for (auto at : inputs) {
                            if (s.modifier == "strict") {
                                const bool entry = std::any_of(funcs.begin(), funcs.end(), [&](const auto& f) {
                                    return f.begin == at && f.end > at;
                                });
                                if (!entry)
                                    throw Error("NotFunctionEntry",
                                        "func:strict requires every input to be a known function entry; rejected offset " + std::to_string(at));
                                r.values.push_back(address(at));
                            } else if (auto f = maml::generate::enclosing_func(indexed, at)) {
                                r.values.push_back(address(f->begin));
                            }
                        }
                    } else if (s.name == "callers" || s.name == "xrefs") {
                        if (code.empty())
                            throw Error("MissingMetadata", s.name + " requires code ranges");
                        std::unordered_set<uint64_t> targets;
                        for (auto at : inputs) {
                            if (s.name == "callers" || in(code, at)) {
                                for (auto site : maml::generate::callers_of(indexed, at))
                                    r.values.push_back(address(site));
                            } else if (in(rodata, at))
                                targets.insert(at);
                            else
                                throw Error("MissingMetadata", "xrefs target is in neither code nor rodata");
                        }
                        if (!targets.empty())
                            for (const auto& [target, sites] : maml::generate::rip_lea_index(indexed, targets))
                                for (auto site : sites)
                                    r.values.push_back(address(site));
                    } else if (s.name == "read") {
                        for (auto at : inputs) {
                            if (at > image.bytes.size() || s.number > image.bytes.size() - at)
                                continue;
                            uint64_t last;
                            if (!add(image.base, at, last) || !add(last, s.number, last))
                                continue;
                            uint64_t value = 0;
                            for (size_t k = 0; k < s.number; ++k)
                                value |= uint64_t(image.bytes[size_t(at) + k]) << (8 * k);
                            r.values.push_back(Value{ value, "ReadValue", "scalar" });
                        }
                    }
                    std::sort(r.values.begin(), r.values.end());
                    r.values.erase(std::unique(r.values.begin(), r.values.end()), r.values.end());
                }
                r.trace.push_back({ s.name + (s.modifier.empty() ? "" : ":" + s.modifier), before, count() });
            }
            return r;
        }
    };

    enum class FunctionMode { Default,
        Loose,
        Strict };

    // Value semantics let independent pipelines share a builder prefix. The
    // rendered source enters the existing compiler, including schema checking.
    class PipelineBuilder {
        std::string source_;
        explicit PipelineBuilder(std::string source) : source_(std::move(source)) {}
        PipelineBuilder append(std::string stage) const {
            return PipelineBuilder(source_.empty() ? std::move(stage) : source_ + " -> " + stage);
        }
        static std::string quote(std::string_view text) {
            constexpr char hex[] = "0123456789ABCDEF";
            std::string out = "\"";
            for (unsigned char c : text) {
                if (c == '"' || c == '\\') {
                    out += '\\';
                    out += char(c);
                } else if (c == '\n')
                    out += "\\n";
                else if (c == '\t')
                    out += "\\t";
                else if (c < 32 || c == 127) {
                    out += "\\x";
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else
                    out += char(c);
            }
            return out + '"';
        }

    public:
        PipelineBuilder() = default;
        const std::string& source() const {
            return source_;
        }
        PipelineBuilder str(std::string_view text) const {
            return append("str(" + quote(text) + ")");
        }
        PipelineBuilder bytes(std::string_view text) const {
            return append("bytes(" + quote(text) + ")");
        }
        PipelineBuilder find(std::string_view text) const {
            return append("find(" + quote(text) + ")");
        }
        PipelineBuilder before(std::string_view pattern, uint64_t within) const {
            return append("before(" + quote(pattern) + ", within=" + std::to_string(within) + ")");
        }
        PipelineBuilder after(std::string_view pattern, uint64_t within) const {
            return append("after(" + quote(pattern) + ", within=" + std::to_string(within) + ")");
        }
        PipelineBuilder capture(std::string_view name) const {
            return append("capture(" + quote(name) + ")");
        }
        PipelineBuilder xrefs() const {
            return append("xrefs");
        }
        PipelineBuilder callers() const {
            return append("callers");
        }
        PipelineBuilder func(FunctionMode mode = FunctionMode::Default) const {
            switch (mode) {
            case FunctionMode::Default: return append("func");
            case FunctionMode::Loose: return append("func:loose");
            case FunctionMode::Strict: return append("func:strict");
            }
            throw Error("InvalidModifier", "Unknown function mode");
        }
        PipelineBuilder unique() const {
            return append("unique");
        }
        PipelineBuilder nth(uint64_t n) const {
            return append("nth(" + std::to_string(n) + ")");
        }
        PipelineBuilder limit(uint64_t n) const {
            return append("limit(" + std::to_string(n) + ")");
        }
        PipelineBuilder read(uint64_t n) const {
            return append("read(" + std::to_string(n) + ")");
        }
        Pipeline build() const {
            return Pipeline(source_);
        }
    };
} // namespace maml::v1
