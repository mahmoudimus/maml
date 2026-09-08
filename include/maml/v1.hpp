// SPDX-License-Identifier: BSL-1.0 OR MIT
#pragma once
#include "mamlscan.hpp"
#include <charconv>
#include <map>
#include <set>
#include <tuple>

namespace maml::v1 {
    inline constexpr std::string_view dialect = "maml-v1";
    struct Error : std::runtime_error {
        std::string code;
        size_t position;
        Error(std::string c, std::string message, size_t p = 0)
            : std::runtime_error(std::move(message)), code(std::move(c)), position(p) {}
    };
    struct Value {
        uint64_t value = 0;
        std::string kind = "CursorAddress", space = "image";
        auto operator<=>(const Value&) const = default;
    };
    struct NamedCapture {
        std::string name;
        Value data;
        bool operator==(const NamedCapture&) const = default;
    };
    struct Match {
        uint64_t offset = 0;
        std::vector<std::string> schema;
        std::vector<NamedCapture> captures;
        std::optional<Value> capture(std::string_view name) const {
            if (std::find(schema.begin(), schema.end(), name) == schema.end())
                throw Error("UnknownCapture", "Unknown capture: " + std::string(name));
            for (const auto& c : captures)
                if (c.name == name)
                    return c.data;
            return std::nullopt;
        }
        bool operator==(const Match&) const = default;
    };
    struct Image {
        std::span<const uint8_t> bytes;
        uint64_t base = 0;
        std::map<uint64_t, uint64_t> pointer_map;
        bool readable(uint64_t address) const {
            return address >= base && address - base < bytes.size();
        }
    };
    inline bool add(uint64_t a, uint64_t b, uint64_t& out) {
        if (b > UINT64_MAX - a)
            return false;
        out = a + b;
        return true;
    }
    inline bool add_signed(uint64_t a, int64_t b, uint64_t& out) {
        if (b >= 0)
            return add(a, uint64_t(b), out);
        const uint64_t magnitude = uint64_t(-(b + 1)) + 1;
        if (a < magnitude)
            return false;
        out = a - magnitude;
        return true;
    }
    enum class Encoding { SignedRelative8LE,
        SignedRelative32LE,
        AbsolutePointer64LE };
    enum class Continuation { Sequential,
        Target };
    class Reference {
        Encoding encoding_;
        int64_t adjustment_;

    public:
        Reference(Encoding e, int64_t adjustment = 0) : encoding_(e), adjustment_(adjustment) {
            if (e != Encoding::SignedRelative8LE && e != Encoding::SignedRelative32LE &&
                e != Encoding::AbsolutePointer64LE)
                throw Error("InvalidReferencePolicy", "Unknown reference encoding");
            if (e == Encoding::AbsolutePointer64LE && adjustment)
                throw Error("InvalidReferencePolicy", "ptr64 has no target_add");
        }
        Encoding encoding() const {
            return encoding_;
        }
        int64_t target_add() const {
            return adjustment_;
        }
        size_t width() const {
            switch (encoding_) {
            case Encoding::SignedRelative8LE: return 1;
            case Encoding::SignedRelative32LE: return 4;
            case Encoding::AbsolutePointer64LE: return 8;
            }
            throw Error("InvalidReferencePolicy", "Unknown encoding");
        }
        bool resolve(uint64_t raw, uint64_t end, uint64_t& target) const {
            if (encoding_ == Encoding::AbsolutePointer64LE) {
                target = raw;
                return true;
            }
            const unsigned bits = unsigned(width() * 8);
            const int64_t displacement = (raw & (uint64_t(1) << (bits - 1)))
                                             ? int64_t(raw) - (int64_t(1) << bits)
                                             : int64_t(raw);
            return add_signed(end, displacement, target) && add_signed(target, adjustment_, target);
        }
    };
    namespace detail {
        enum class Op { Byte,
            Gap,
            Capture,
            Reference,
            Split,
            Jump,
            Accept };
        struct Instruction {
            Op op = Op::Accept;
            uint8_t mask = 0, value = 0;
            uint64_t min = 0, max = 0;
            size_t id = 0, target = 0;
            Reference reference{ Encoding::SignedRelative32LE };
            Continuation continuation = Continuation::Sequential;
        };
        struct Node {
            Instruction instruction;
            std::vector<std::vector<Node>> branches;
        };
        class Parser {
            std::string_view source;
            size_t pos = 0;
            std::vector<std::string>& names;
            [[noreturn]] void fail(std::string code, std::string message) const {
                throw Error(std::move(code), std::move(message), pos);
            }
            void ws() {
                while (pos < source.size() && std::isspace(static_cast<unsigned char>(source[pos])))
                    ++pos;
            }
            bool take(char c) {
                ws();
                if (pos < source.size() && source[pos] == c) {
                    ++pos;
                    return true;
                }
                return false;
            }
            void need(char c) {
                if (!take(c))
                    fail("InvalidSyntax", std::string("Expected '") + c + "'");
            }
            std::string identifier() {
                ws();
                size_t begin = pos;
                if (pos == source.size() || !(std::isalpha(static_cast<unsigned char>(source[pos])) || source[pos] == '_'))
                    fail("InvalidSyntax", "Expected an identifier");
                while (pos < source.size() && (std::isalnum(static_cast<unsigned char>(source[pos])) || source[pos] == '_'))
                    ++pos;
                return std::string(source.substr(begin, pos - begin));
            }
            size_t capture() {
                auto name = identifier();
                if (std::find(names.begin(), names.end(), name) != names.end())
                    fail("DuplicateCapture", "Duplicate capture: " + name);
                if (names.size() >= 256)
                    fail("ResourceLimit", "Pattern exceeds 256 captures");
                names.push_back(std::move(name));
                return names.size() - 1;
            }
            template<class T>
            T number() {
                ws();
                size_t begin = pos;
                if (pos < source.size() && source[pos] == '-')
                    ++pos;
                while (pos < source.size() && std::isdigit(static_cast<unsigned char>(source[pos])))
                    ++pos;
                T value{};
                auto r = std::from_chars(source.data() + begin, source.data() + pos, value);
                if (r.ec != std::errc{} || r.ptr != source.data() + pos)
                    fail("InvalidArgument", "Integer is missing or out of range");
                return value;
            }
            static int hex(char c) {
                if (c >= '0' && c <= '9')
                    return c - '0';
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;
                return -1;
            }

        public:
            Parser(std::string_view s, std::vector<std::string>& n) : source(s), names(n) {
                if (s.size() > 65536)
                    fail("ResourceLimit", "Pattern exceeds 65536 characters");
            }
            std::vector<Node> sequence(unsigned depth = 0) {
                if (depth > 64)
                    fail("ResourceLimit", "Pattern nesting exceeds 64");
                std::vector<Node> nodes;
                for (;;) {
                    ws();
                    if (pos == source.size() || source[pos] == ')' || source[pos] == '|')
                        break;
                    Node node;
                    auto& i = node.instruction;
                    if (take('(')) {
                        do {
                            auto branch = sequence(depth + 1);
                            if (branch.empty())
                                fail("InvalidSyntax", "Empty alternative");
                            node.branches.push_back(std::move(branch));
                        } while (take('|'));
                        need(')');
                    } else if (take('[')) {
                        i.op = Op::Gap;
                        i.min = number<uint64_t>();
                        i.max = i.min;
                        if (take('.')) {
                            need('.');
                            i.max = number<uint64_t>();
                        }
                        need(']');
                        if (i.max < i.min)
                            fail("InvalidArgument", "Gap maximum precedes minimum");
                    } else if (take('@')) {
                        i.op = Op::Capture;
                        need('(');
                        i.id = capture();
                        need(')');
                    } else if (source.substr(pos, 5) == "rel32" || source.substr(pos, 4) == "rel8" || source.substr(pos, 5) == "ptr64") {
                        const auto name = identifier();
                        Encoding encoding;
                        if (name == "rel32")
                            encoding = Encoding::SignedRelative32LE;
                        else if (name == "rel8")
                            encoding = Encoding::SignedRelative8LE;
                        else if (name == "ptr64")
                            encoding = Encoding::AbsolutePointer64LE;
                        else
                            fail("InvalidReferencePolicy", "Unknown reference: " + name);
                        i.op = Op::Reference;
                        need('(');
                        i.id = capture();
                        int64_t adjustment = 0;
                        if (take(',')) {
                            auto arg = identifier();
                            if (arg != "target_add" || encoding == Encoding::AbsolutePointer64LE)
                                fail("InvalidReferencePolicy", "Unsupported reference parameter");
                            need('=');
                            adjustment = number<int64_t>();
                        }
                        need(')');
                        i.reference = Reference(encoding, adjustment);
                    } else {
                        ws();
                        if (pos + 2 > source.size())
                            fail("InvalidSyntax", "Expected a two-nibble byte");
                        i.op = Op::Byte;
                        for (int n = 0; n < 2; ++n) {
                            char c = source[pos++];
                            int h = hex(c);
                            if (c != '?' && h < 0)
                                fail("InvalidSyntax", "Expected a hex nibble or ?");
                            i.mask = uint8_t((i.mask << 4) | (c == '?' ? 0 : 15));
                            i.value = uint8_t((i.value << 4) | (h < 0 ? 0 : h));
                        }
                    }
                    if (take(':')) {
                        if (!node.branches.empty() || i.op != Op::Reference)
                            fail("InvalidModifier", "Only references accept :follow");
                        if (identifier() != "follow")
                            fail("InvalidModifier", "Unknown modifier");
                        i.continuation = Continuation::Target;
                        if (take(':'))
                            fail("InvalidModifier", "Repeated modifier");
                    }
                    nodes.push_back(std::move(node));
                }
                return nodes;
            }
            std::vector<Node> parse() {
                auto nodes = sequence();
                ws();
                if (pos != source.size() || nodes.empty())
                    fail("InvalidSyntax", "Expected a nonempty pattern");
                return nodes;
            }
        };
        inline void lower(const std::vector<Node>& nodes, std::vector<Instruction>& code) {
            for (const auto& n : nodes) {
                if (n.branches.empty()) {
                    code.push_back(n.instruction);
                    continue;
                }
                std::vector<size_t> exits;
                for (size_t b = 0; b < n.branches.size(); ++b) {
                    size_t split = code.size();
                    if (b + 1 < n.branches.size()) {
                        Instruction i;
                        i.op = Op::Split;
                        code.push_back(i);
                    }
                    lower(n.branches[b], code);
                    if (b + 1 < n.branches.size()) {
                        exits.push_back(code.size());
                        Instruction i;
                        i.op = Op::Jump;
                        code.push_back(i);
                        code[split].target = code.size();
                    }
                }
                for (auto e : exits)
                    code[e].target = code.size();
            }
        }
    } // namespace detail

    class Pattern {
        std::vector<std::string> schema_;
        std::vector<detail::Instruction> code_;
        struct Seed {
            size_t offset;
            std::vector<uint8_t> bytes;
        };
        // Read only the compiled control flow. Never infer reference semantics from text.
        std::vector<Seed> seeds() const {
            using detail::Op;
            std::vector<Seed> out;
            size_t offset = 0;
            for (size_t pc = 0; pc < code_.size();) {
                const auto& i = code_[pc];
                if (i.op == Op::Byte && i.mask == 255) {
                    Seed s{ offset, {} };
                    while (pc < code_.size() && code_[pc].op == Op::Byte && code_[pc].mask == 255) {
                        s.bytes.push_back(code_[pc++].value);
                        ++offset;
                    }
                    out.push_back(std::move(s));
                    continue;
                }
                if (i.op == Op::Capture) {
                } else if (i.op == Op::Byte)
                    ++offset;
                else if (i.op == Op::Reference && i.continuation == Continuation::Sequential)
                    offset += i.reference.width();
                else if (i.op == Op::Gap && i.min == i.max && i.min <= SIZE_MAX - offset)
                    offset += size_t(i.min);
                else
                    break;
                ++pc;
            }
            return out;
        }

    public:
        explicit Pattern(std::string_view source) {
            detail::Parser parser(source, schema_);
            auto ast = parser.parse();
            detail::lower(ast, code_);
            code_.push_back({});
        }
        const std::vector<std::string>& schema() const {
            return schema_;
        }
        // Generalize only aligned linear programs. Control flow and reference
        // policies must agree; differing literal nibbles lose their constraints.
        std::optional<std::string> generalize(const Pattern& other) const {
            using detail::Op;
            if (schema_ != other.schema_ || code_.size() != other.code_.size())
                return std::nullopt;
            std::string out;
            constexpr char hex[] = "0123456789ABCDEF";
            for (size_t k = 0; k < code_.size(); ++k) {
                const auto& a = code_[k];
                const auto& b = other.code_[k];
                if (a.op != b.op)
                    return std::nullopt;
                std::string token;
                if (a.op == Op::Byte) {
                    for (unsigned shift : { 4u, 0u }) {
                        const unsigned mask = 15u << shift;
                        const bool same = (a.mask & mask) == mask && (b.mask & mask) == mask && (a.value & mask) == (b.value & mask);
                        token += same ? hex[(a.value >> shift) & 15] : '?';
                    }
                } else if (a.op == Op::Reference) {
                    if (a.id != b.id || a.reference.encoding() != b.reference.encoding() ||
                        a.reference.target_add() != b.reference.target_add() || a.continuation != b.continuation)
                        return std::nullopt;
                    token = a.reference.encoding() == Encoding::SignedRelative8LE ? "rel8(" : a.reference.encoding() == Encoding::SignedRelative32LE ? "rel32("
                                                                                                                                                     : "ptr64(";
                    token += schema_[a.id];
                    if (a.reference.target_add())
                        token += ", target_add=" + std::to_string(a.reference.target_add());
                    token += ")";
                    if (a.continuation == Continuation::Target)
                        token += ":follow";
                } else if (a.op == Op::Capture) {
                    if (a.id != b.id)
                        return std::nullopt;
                    token = "@(" + schema_[a.id] + ")";
                } else if (a.op == Op::Gap) {
                    if (a.min != b.min || a.max != b.max)
                        return std::nullopt;
                    token = "[" + std::to_string(a.min);
                    if (a.min != a.max)
                        token += ".." + std::to_string(a.max);
                    token += "]";
                } else if (a.op == Op::Accept)
                    continue;
                else
                    return std::nullopt;
                if (!out.empty())
                    out += ' ';
                out += token;
            }
            return out;
        }
        size_t fixed_literal_count() const {
            return size_t(std::count_if(code_.begin(), code_.end(), [](const detail::Instruction& i) {
                return i.op == detail::Op::Byte && i.mask == 255;
            }));
        }
        locate::Seed select_seed(std::span<const uint8_t> image) const {
            locate::Seed best;
            size_t count = SIZE_MAX;
            for (const auto& s : seeds()) {
                const auto n = locate::count_up_to(image, s.bytes, count);
                if (n < count) {
                    best.offset = s.offset;
                    best.bytes = s.bytes;
                    count = n;
                }
                if (!count)
                    break;
            }
            return best;
        }
        std::optional<Match> match_at(const Image& image, uint64_t start, size_t work_limit = 1000000) const {
            using detail::Op;
            if (start > image.bytes.size())
                return std::nullopt;
            struct State {
                size_t pc;
                uint64_t cursor;
                std::vector<std::optional<Value>> captures;
            };
            std::vector<State> stack{ { 0, start, std::vector<std::optional<Value>>(schema_.size()) } };
            while (!stack.empty()) {
                State s = std::move(stack.back());
                stack.pop_back();
                for (;;) {
                    if (!work_limit--)
                        throw Error("ResourceLimit", "Match execution budget exhausted");
                    const auto& i = code_[s.pc++];
                    uint64_t address;
                    if (!add(image.base, s.cursor, address))
                        break;
                    if (i.op == Op::Accept) {
                        Match m{ start, schema_, {} };
                        for (size_t k = 0; k < schema_.size(); ++k)
                            if (s.captures[k])
                                m.captures.push_back({ schema_[k], *s.captures[k] });
                        return m;
                    }
                    if (i.op == Op::Jump) {
                        s.pc = i.target;
                        continue;
                    }
                    if (i.op == Op::Split) {
                        if (stack.size() >= 1024)
                            throw Error("ResourceLimit", "Checkpoint limit exceeded");
                        State other = s;
                        other.pc = i.target;
                        stack.push_back(std::move(other));
                        continue;
                    }
                    if (i.op == Op::Capture) {
                        s.captures[i.id] = Value{ address, "CursorAddress", "image" };
                        continue;
                    }
                    if (i.op == Op::Gap) {
                        if (s.cursor > image.bytes.size() || i.min > image.bytes.size() - s.cursor)
                            break;
                        const uint64_t hi = std::min<uint64_t>(i.max, image.bytes.size() - s.cursor);
                        // Bound queued alternatives as well as instruction execution.
                        if (hi - i.min > 1024 || stack.size() > 1024 - (hi - i.min) || hi - i.min > work_limit)
                            throw Error("ResourceLimit", "Gap checkpoint budget exhausted");
                        for (uint64_t n = hi; n > i.min; --n) {
                            State other = s;
                            other.cursor += n;
                            stack.push_back(std::move(other));
                        }
                        s.cursor += i.min;
                        continue;
                    }
                    if (s.cursor >= image.bytes.size())
                        break;
                    if (i.op == Op::Byte) {
                        if ((image.bytes[size_t(s.cursor)] & i.mask) != i.value)
                            break;
                        ++s.cursor;
                        continue;
                    }
                    const auto width = i.reference.width();
                    if (width > image.bytes.size() - s.cursor)
                        break;
                    uint64_t end, target, raw = 0;
                    if (!add(address, width, end))
                        break;
                    for (size_t k = 0; k < width; ++k)
                        raw |= uint64_t(image.bytes[size_t(s.cursor) + k]) << (8 * k);
                    if (!i.reference.resolve(raw, end, target))
                        break;
                    const bool absolute = i.reference.encoding() == Encoding::AbsolutePointer64LE;
                    s.captures[i.id] = Value{ target, absolute ? "AbsolutePointerValue" : "ResolvedRelativeTarget", absolute ? "absolute" : "image" };
                    if (i.continuation == Continuation::Sequential) {
                        s.cursor += width;
                        continue;
                    }
                    uint64_t destination = target;
                    if (absolute) {
                        auto found = image.pointer_map.find(target);
                        if (found == image.pointer_map.end())
                            break;
                        destination = found->second;
                    }
                    if (!image.readable(destination))
                        break;
                    s.cursor = destination - image.base;
                }
            }
            return std::nullopt;
        }
        std::vector<Match> find_all(const Image& image, size_t limit = 0, bool exhaustive = false) const {
            std::vector<Match> matches;
            auto accept = [&](uint64_t offset) {
                if (auto m = match_at(image, offset))
                    matches.push_back(std::move(*m));
                return limit && matches.size() >= limit;
            };
            const auto choices = seeds();
            if (!exhaustive && !choices.empty()) {
                if (image.bytes.empty())
                    return matches;
                const Seed* best = nullptr;
                size_t count = SIZE_MAX;
                for (const auto& s : choices) {
                    if (s.bytes.size() > image.bytes.size())
                        return matches;
                    const size_t c = locate::count_up_to(image.bytes, s.bytes, count);
                    if (c < count) {
                        best = &s;
                        count = c;
                    }
                    if (!count)
                        return matches;
                }
                if (best) {
                    locate::detail::scan_literal(image.bytes.data(), image.bytes.data() + image.bytes.size(),
                        best->bytes.data(), best->bytes.size(), [&](const uint8_t* at) {
                            size_t pos = size_t(at - image.bytes.data());
                            return pos >= best->offset && accept(pos - best->offset);
                        });
                    return matches;
                }
            }
            for (size_t pos = 0;; ++pos) {
                if (accept(pos) || pos == image.bytes.size())
                    break;
            }
            return matches;
        }
        std::optional<Match> find(const Image& image) const {
            auto matches = find_all(image, 1);
            return matches.empty() ? std::nullopt : std::optional<Match>(std::move(matches.front()));
        }
    };
    inline std::vector<Value> project(const std::vector<std::string>& schema, const std::vector<Match>& matches, std::string_view name, bool unique = false) {
        Match probe{ 0, schema, {} };
        (void)probe.capture(name);
        std::set<Value> values;
        for (const auto& m : matches)
            for (const auto& c : m.captures)
                if (c.name == name)
                    values.insert(c.data);
        if (unique && values.size() != 1)
            throw Error("Cardinality", "unique requires exactly one value");
        return { values.begin(), values.end() };
    }
} // namespace maml::v1
