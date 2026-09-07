#ifndef MAML_HPP
#define MAML_HPP
// Bumped together with CMakeLists.txt's project(VERSION). 0.1.0 added
// locate::Compiled, compile/prime, find_all, and exact-by-default seed
// selection, without changing any existing signature.
#define MAML_VERSION_MAJOR 0
#define MAML_VERSION_MINOR 1
#define MAML_VERSION_PATCH 0
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>
namespace maml {
    template<class... Ts>
    struct Overloaded : Ts... {
        using Ts::operator()...;
    };
    template<class... Ts>
    Overloaded(Ts...) -> Overloaded<Ts...>;
    enum class JumpType { RelByte,
        RelDWord,
        AbsQWord };
    enum class ReadWidth { Byte,
        Word,
        DWord };
    struct AtomByteSequence {
        uint16_t seq_start;
        uint16_t seq_end;
        auto operator<=>(const AtomByteSequence&) const = default;
    };
    struct AtomByteSequenceMasked {
        uint16_t seq_start;
        uint16_t mask_start;
        uint16_t len;
        auto operator<=>(const AtomByteSequenceMasked&) const = default;
    };
    struct AtomWildcardFixed {
        uint16_t length;
        auto operator<=>(const AtomWildcardFixed&) const = default;
    };
    struct AtomWildcardRange {
        uint16_t min;
        uint16_t max;
        auto operator<=>(const AtomWildcardRange&) const = default;
    };
    struct AtomJump {
        JumpType type;
        auto operator<=>(const AtomJump&) const = default;
    };
    struct AtomRead {
        ReadWidth width;
        auto operator<=>(const AtomRead&) const = default;
    };
    struct AtomBranch {
        uint16_t left_len;
        uint16_t right_len;
        auto operator<=>(const AtomBranch&) const = default;
    };
    struct AtomCursorPush {
        auto operator<=>(const AtomCursorPush&) const = default;
    };
    struct AtomCursorPop {
        uint16_t advance;
        auto operator<=>(const AtomCursorPop&) const = default;
    };
    struct AtomSaveCursor {
        auto operator<=>(const AtomSaveCursor&) const = default;
    };
    struct AtomSaveConstant {
        uint32_t value;
        auto operator<=>(const AtomSaveConstant&) const = default;
    };
    using AtomVariant = std::variant<AtomByteSequence, AtomByteSequenceMasked, AtomWildcardFixed, AtomWildcardRange, AtomJump, AtomRead, AtomBranch, AtomCursorPush, AtomCursorPop, AtomSaveCursor, AtomSaveConstant>;
    enum class ParseErrorType { UnexpectedToken,
        UnexpectedEnd,
        MaskByteLenMismatch,
        HexValueInvalid,
        HexValueIncomplete,
        GroupNotClosed,
        BlockNotClosed,
        RangeBoundInvalid,
        RangeEndMustBeGraterThenStart,
        SequenceTooLarge,
        InternalError,
    };
    class ParseException : public std::runtime_error {
    public:
        ParseErrorType type;
        std::pair<size_t, size_t> position;
        ParseException(ParseErrorType t, const std::string& m, std::pair<size_t, size_t> p) : std::runtime_error(m), type(t), position(p) {}
    };
    template<typename T>
    class Stack {
    public:
        virtual ~Stack() = default;
        virtual size_t len() const = 0;
        virtual void truncate(size_t) = 0;
        virtual bool push_value(const T&) = 0;
        virtual std::optional<T> pop_value() = 0;
        virtual T* data() = 0;
        virtual const T* data() const = 0;
    };
    template<typename T, size_t N>
    class StaticStack : public Stack<T> {
        std::array<T, N> s_{};
        size_t l_ = 0;

    public:
        size_t len() const override {
            return l_;
        }
        void truncate(size_t n) override {
            if (n > N)
                throw std::out_of_range("x");
            l_ = n;
        }
        bool push_value(const T& v) override {
            if (l_ >= N)
                return false;
            s_[l_++] = v;
            return true;
        }
        std::optional<T> pop_value() override {
            if (!l_)
                return std::nullopt;
            return s_[--l_];
        }
        T* data() override {
            return s_.data();
        }
        const T* data() const override {
            return s_.data();
        }
    };
    template<typename T>
    class HeapStack : public Stack<T> {
        std::vector<T> s_;

    public:
        size_t len() const override {
            return s_.size();
        }
        void truncate(size_t n) override {
            s_.resize(n);
        }
        bool push_value(const T& v) override {
            s_.push_back(v);
            return true;
        }
        std::optional<T> pop_value() override {
            if (s_.empty())
                return std::nullopt;
            T v = s_.back();
            s_.pop_back();
            return v;
        }
        T* data() override {
            return s_.data();
        }
        const T* data() const override {
            return s_.data();
        }
    };
    class BinaryPattern {
    public:
        virtual ~BinaryPattern() = default;
        virtual std::span<const AtomVariant> atoms() const = 0;
        virtual std::span<const uint8_t> byte_sequence() const = 0;
    };
    class OwnedBinaryPattern : public BinaryPattern {
        std::vector<AtomVariant> a_;
        std::vector<uint8_t> b_;

    public:
        OwnedBinaryPattern() = default;
        OwnedBinaryPattern(std::vector<AtomVariant> a, std::vector<uint8_t> b) : a_(std::move(a)), b_(std::move(b)) {}
        std::span<const AtomVariant> atoms() const override {
            return a_;
        }
        std::span<const uint8_t> byte_sequence() const override {
            return b_;
        }
        std::vector<AtomVariant>& atoms_mut() {
            return a_;
        }
        std::vector<uint8_t>& byte_sequence_mut() {
            return b_;
        }
    };
    class MatchTarget {
    public:
        virtual ~MatchTarget() = default;
        virtual size_t match_length() const = 0;
        virtual std::optional<std::span<const uint8_t>> subrange(size_t, size_t) const = 0;
        virtual std::optional<size_t> translate_absolute_address(uint64_t) const = 0;
    };
    class SpanMatchTarget : public MatchTarget {
        std::span<const uint8_t> d_;

    public:
        SpanMatchTarget(std::span<const uint8_t> d) : d_(d) {}
        size_t match_length() const override {
            return d_.size();
        }
        std::optional<std::span<const uint8_t>> subrange(size_t o, size_t n) const override {
            if (o > d_.size() || n > d_.size() - o)
                return std::nullopt; // FIX: o+n can overflow
            return d_.subspan(o, n);
        }
        std::optional<size_t> translate_absolute_address(uint64_t a) const override {
            const uint64_t b = reinterpret_cast<uint64_t>(d_.data());
            if (a < b || a >= (b + d_.size()))
                return std::nullopt;
            return (size_t)(a - b);
        }
    };
    // Scans a buffer that represents a loaded image at a KNOWN virtual base.
    // SpanMatchTarget resolves absolute pointers against the host address of the
    // buffer, which is only correct when scanning live process memory. When the
    // buffer is a file/dump, absolute pointers hold image VAs, so use this instead.
    class ImageMatchTarget : public MatchTarget {
        std::span<const uint8_t> d_;
        uint64_t base_;

    public:
        ImageMatchTarget(std::span<const uint8_t> d, uint64_t image_base) : d_(d), base_(image_base) {}
        size_t match_length() const override {
            return d_.size();
        }
        std::optional<std::span<const uint8_t>> subrange(size_t o, size_t n) const override {
            if (o > d_.size() || n > d_.size() - o)
                return std::nullopt;
            return d_.subspan(o, n);
        }
        std::optional<size_t> translate_absolute_address(uint64_t a) const override {
            if (a < base_ || a >= base_ + d_.size())
                return std::nullopt;
            return (size_t)(a - base_);
        }
        uint64_t image_base() const {
            return base_;
        }
        uint64_t to_va(size_t off) const {
            return base_ + off;
        }
    };

    namespace compiler {
        enum class TokenType { Text,
            Whildcard,
            Mask,
            RangeOpen,
            RangeSeperator,
            RangeClose,
            BlockOpen,
            BlockClose,
            GroupOpen,
            GroupPipe,
            GroupClose,
            JumpRel1,
            JumpRel4,
            JumpAbs64,
            Read1,
            Read2,
            Read4,
            PositionSave };
        struct Token {
            TokenType type;
            std::string_view text_value;
            size_t start_offset;
            size_t end_offset;
        };
        class Lexer {
            std::string_view in_;
            size_t off_ = 0, ts_ = 0;

        public:
            Lexer(std::string_view i) : in_(i) {}
            std::pair<size_t, size_t> token_range() const {
                return { ts_, off_ };
            }
            std::optional<Token> next_token() {
                while (off_ < in_.length()) {
                    const char c = in_[off_];
                    if (std::isspace((unsigned char)c)) {
                        off_++;
                        continue;
                    }
                    ts_ = off_;
                    if (c == '/' && off_ + 1 < in_.length()) {
                        if (in_[off_ + 1] == '/') {
                            off_ = in_.find('\n', off_ + 2);
                            if (off_ == std::string_view::npos)
                                off_ = in_.length();
                            continue;
                        } else if (in_[off_ + 1] == '*') {
                            off_ = in_.find("*/", off_ + 2);
                            if (off_ == std::string_view::npos)
                                off_ = in_.length();
                            else
                                off_ += 2;
                            continue;
                        }
                    }
                    auto mk = [&](TokenType t, size_t n) -> Token {
                        off_ += n;
                        return { t, {}, ts_, off_ };
                    };
                    switch (c) {
                    case '?': return mk(TokenType::Whildcard, 1);
                    case '&': return mk(TokenType::Mask, 1);
                    case '[': return mk(TokenType::RangeOpen, 1);
                    case '-': return mk(TokenType::RangeSeperator, 1);
                    case ']': return mk(TokenType::RangeClose, 1);
                    case '{': return mk(TokenType::BlockOpen, 1);
                    case '}': return mk(TokenType::BlockClose, 1);
                    case '(': return mk(TokenType::GroupOpen, 1);
                    case '|': return mk(TokenType::GroupPipe, 1);
                    case ')': return mk(TokenType::GroupClose, 1);
                    case '%': return mk(TokenType::JumpRel1, 1);
                    case '$': return mk(TokenType::JumpRel4, 1);
                    case '*': return mk(TokenType::JumpAbs64, 1);
                    case '\'': return mk(TokenType::PositionSave, 1);
                    // Anything else is not a single-character token; the
                    // multi-character forms and the text scanner below handle it.
                    default: break;
                    }
                    if (c == 'r' && off_ + 1 < in_.length()) {
                        const char n = in_[off_ + 1];
                        if (n == '1')
                            return mk(TokenType::Read1, 2);
                        if (n == '2')
                            return mk(TokenType::Read2, 2);
                        if (n == '4')
                            return mk(TokenType::Read4, 2);
                    }
                    size_t te = off_ + 1;
                    while (te < in_.length()) {
                        const char n = in_[te];
                        if (std::isspace((unsigned char)n) || std::string_view("?&[]{}()|%*'-").find(n) != std::string_view::npos)
                            break;
                        if (n == '$' && in_[te - 1] != 'r')
                            break;
                        te++;
                    }
                    const std::string_view t = in_.substr(off_, te - off_);
                    off_ = te;
                    return Token{ TokenType::Text, t, ts_, off_ };
                }
                ts_ = in_.length();
                return std::nullopt;
            }
        };
        class PatternParser {
            Lexer lx_;
            std::optional<Token> pk_;
            std::vector<AtomVariant> atoms_;
            std::vector<uint8_t> bytes_;
            Token pop_token(std::optional<TokenType> e = std::nullopt) {
                auto t = pk_ ? pk_ : lx_.next_token();
                pk_.reset();
                if (!t)
                    throw ParseException(ParseErrorType::UnexpectedEnd, "end", lx_.token_range());
                if (e && t->type != *e)
                    throw ParseException(ParseErrorType::UnexpectedToken, "tok", { t->start_offset, t->end_offset });
                return *t;
            }
            const std::optional<Token>& peek() {
                if (!pk_)
                    pk_ = lx_.next_token();
                return pk_;
            }
            std::pair<uint16_t, uint16_t> parse_bytes(const Token& tk) {
                // Accept an odd digit count: "12 3" parses as 12 03.
                std::string txt(tk.text_value);
                if (txt.empty())
                    throw ParseException(ParseErrorType::HexValueIncomplete, "hex", { tk.start_offset, tk.end_offset });
                if (txt.size() % 2 != 0)
                    txt.insert(txt.begin(), '0');
                if (bytes_.size() + txt.size() / 2 > 0xFFFFu)
                    throw ParseException(ParseErrorType::HexValueInvalid, "hex", { tk.start_offset, tk.end_offset });
                const uint16_t st = static_cast<uint16_t>(bytes_.size());
                for (size_t i = 0; i < txt.size(); i += 2) {
                    std::string b = txt.substr(i, 2);
                    if (!std::isxdigit((unsigned char)b[0]) || !std::isxdigit((unsigned char)b[1]))
                        throw ParseException(ParseErrorType::HexValueInvalid, "hex", { tk.start_offset + i, tk.start_offset + i + 2 });
                    bytes_.push_back((uint8_t)std::stoi(b, nullptr, 16));
                }
                return { st, static_cast<uint16_t>(bytes_.size()) };
            }
            void parse_byte_sequence() {
                const Token v = pop_token(TokenType::Text);
                auto [s, e] = parse_bytes(v);
                const auto& mask_tk = peek();
                if (mask_tk && mask_tk->type == TokenType::Mask) {
                    pop_token();
                    const Token m = pop_token(TokenType::Text);
                    auto [ms, me] = parse_bytes(m);
                    if ((e - s) != (me - ms))
                        throw ParseException(ParseErrorType::MaskByteLenMismatch, "mask", { m.start_offset, m.end_offset });
                    atoms_.push_back(AtomByteSequenceMasked{ s, ms, (uint16_t)(e - s) });
                } else
                    atoms_.push_back(AtomByteSequence{ s, e });
            }
            bool parse_until(const std::function<bool(const Token&)>& m) {
                while (true) {
                    const auto& t = peek();
                    if (!t)
                        break;
                    if (m(*t))
                        return true;
                    parse_token();
                }
                return false;
            }
            void parse_jump() {
                const Token tk = pop_token();
                JumpType jt;
                uint16_t w;
                if (tk.type == TokenType::JumpRel1) {
                    jt = JumpType::RelByte;
                    w = 1;
                } else if (tk.type == TokenType::JumpRel4) {
                    jt = JumpType::RelDWord;
                    w = 4;
                } else {
                    jt = JumpType::AbsQWord;
                    w = 8;
                }
                const auto& blk_tk = peek();
                if (blk_tk && blk_tk->type == TokenType::BlockOpen) {
                    pop_token();
                    atoms_.push_back(AtomCursorPush{});
                    atoms_.push_back(AtomJump{ jt });
                    if (!parse_until([](const Token& t) {
                            return t.type == TokenType::BlockClose;
                        }))
                        throw ParseException(ParseErrorType::BlockNotClosed, "blk", { tk.start_offset, tk.end_offset });
                    pop_token();
                    atoms_.push_back(AtomCursorPop{ w });
                } else
                    atoms_.push_back(AtomJump{ jt });
            }
            void parse_group() {
                const Token o = pop_token(TokenType::GroupOpen);
                // FIX: the original pushed one AtomBranch per alternative, yielding N branches
                // for N alternatives and a bogus right_len. AtomBranch is BINARY (left, right,
                // then continue), so N alternatives must be folded right-associatively into
                // N-1 nested branches. `( 01 | 02 03 )` -> Branch{1,2} BS BS BS  (4 atoms).
                std::vector<std::vector<AtomVariant>> alts;
                do {
                    const size_t s0 = atoms_.size();
                    if (!parse_until([](const Token& t) {
                            return t.type == TokenType::GroupPipe || t.type == TokenType::GroupClose;
                        }))
                        throw ParseException(ParseErrorType::GroupNotClosed, "grp", { o.start_offset, o.end_offset });
                    alts.emplace_back(atoms_.begin() + (std::ptrdiff_t)s0, atoms_.end());
                    atoms_.resize(s0);
                    const auto& close_tk = peek();
                    if (close_tk && close_tk->type == TokenType::GroupClose)
                        break;
                    pop_token(TokenType::GroupPipe);
                } while (true);
                pop_token(TokenType::GroupClose);
                if (alts.empty())
                    return;
                std::vector<AtomVariant> out = std::move(alts.back());
                for (size_t k = alts.size() - 1; k-- > 0;) {
                    if (alts[k].size() > UINT16_MAX || out.size() > UINT16_MAX)
                        throw ParseException(ParseErrorType::SequenceTooLarge, "grp", { o.start_offset, o.end_offset });
                    std::vector<AtomVariant> tmp;
                    tmp.push_back(AtomBranch{ (uint16_t)alts[k].size(), (uint16_t)out.size() });
                    tmp.insert(tmp.end(), alts[k].begin(), alts[k].end());
                    tmp.insert(tmp.end(), out.begin(), out.end());
                    out = std::move(tmp);
                }
                atoms_.insert(atoms_.end(), out.begin(), out.end());
            }
            void parse_range() {
                pop_token(TokenType::RangeOpen);
                const Token st = pop_token(TokenType::Text);
                uint16_t sv;
                try {
                    const int v = std::stoi(std::string(st.text_value));
                    if (v < 0 || v > 0xFFFF)
                        throw std::out_of_range("rng");
                    sv = static_cast<uint16_t>(v);
                } catch (...) {
                    throw ParseException(ParseErrorType::RangeBoundInvalid, "rng", { st.start_offset, st.end_offset });
                }
                const auto& sep_tk = peek();
                if (sep_tk && sep_tk->type == TokenType::RangeSeperator) {
                    pop_token();
                    const Token et = pop_token(TokenType::Text);
                    uint16_t ev;
                    try {
                        const int v = std::stoi(std::string(et.text_value));
                        if (v < 0 || v > 0xFFFF)
                            throw std::out_of_range("rng");
                        ev = static_cast<uint16_t>(v);
                    } catch (...) {
                        throw ParseException(ParseErrorType::RangeBoundInvalid, "rng", { et.start_offset, et.end_offset });
                    }
                    if (ev <= sv)
                        throw ParseException(ParseErrorType::RangeEndMustBeGraterThenStart, "rng", { et.start_offset, et.end_offset });
                    atoms_.push_back(AtomWildcardRange{ sv, ev });
                } else
                    atoms_.push_back(AtomWildcardFixed{ sv });
                pop_token(TokenType::RangeClose);
            }
            void parse_token() {
                const auto& pt = peek();
                if (!pt)
                    throw ParseException(ParseErrorType::UnexpectedEnd, "end", lx_.token_range());
                const Token& t = *pt;
                switch (t.type) {
                case TokenType::Text: parse_byte_sequence(); break;
                case TokenType::Whildcard:
                    pop_token();
                    atoms_.push_back(AtomWildcardFixed{ 1 });
                    break;
                case TokenType::PositionSave:
                    pop_token();
                    atoms_.push_back(AtomSaveCursor{});
                    break;
                case TokenType::JumpRel1:
                case TokenType::JumpRel4:
                case TokenType::JumpAbs64: parse_jump(); break;
                case TokenType::Read1:
                    pop_token();
                    atoms_.push_back(AtomRead{ ReadWidth::Byte });
                    break;
                case TokenType::Read2:
                    pop_token();
                    atoms_.push_back(AtomRead{ ReadWidth::Word });
                    break;
                case TokenType::Read4:
                    pop_token();
                    atoms_.push_back(AtomRead{ ReadWidth::DWord });
                    break;
                case TokenType::GroupOpen: parse_group(); break;
                case TokenType::RangeOpen: parse_range(); break;
                default: throw ParseException(ParseErrorType::UnexpectedToken, "tok", { t.start_offset, t.end_offset });
                }
            }

        public:
            PatternParser(std::string_view i) : lx_(i) {}
            OwnedBinaryPattern parse() {
                while (peek())
                    parse_token();
                return OwnedBinaryPattern(std::move(atoms_), std::move(bytes_));
            }
        };
        class Optimizer {
            std::vector<AtomVariant> atoms_;
            struct BranchState {
                size_t atom_idx, right_idx, end_idx;
            };
            std::vector<BranchState> branches_;
            void build_branch_state() {
                branches_.clear();
                for (size_t i = 0; i < atoms_.size(); ++i)
                    if (auto* b = std::get_if<AtomBranch>(&atoms_[i]))
                        branches_.push_back({ i, i + 1 + b->left_len, i + 1 + b->left_len + b->right_len });
            }
            bool merge_pass(const std::function<std::optional<AtomVariant>(const AtomVariant&, const AtomVariant&)>& mg) {
                bool up = false;
                size_t i = 0;
                while (i + 1 < atoms_.size()) {
                    bool bd = false;
                    for (const auto& b : branches_)
                        if (i + 1 == b.right_idx || i + 1 == b.end_idx) {
                            bd = true;
                            break;
                        }
                    if (bd) {
                        i++;
                        continue;
                    }
                    if (auto na = mg(atoms_[i], atoms_[i + 1])) {
                        atoms_[i] = *na;
                        atoms_.erase(atoms_.begin() + (std::ptrdiff_t)(i + 1));
                        up = true;
                        for (auto& b : branches_) {
                            if (b.atom_idx > i)
                                b.atom_idx--;
                            if (b.right_idx > i + 1)
                                b.right_idx--;
                            if (b.end_idx > i + 1)
                                b.end_idx--;
                        }
                    } else
                        i++;
                }
                return up;
            }
            void fixup_branches() {
                for (const auto& bs : branches_) {
                    auto& ba = std::get<AtomBranch>(atoms_[bs.atom_idx]);
                    ba.left_len = static_cast<uint16_t>(bs.right_idx - bs.atom_idx - 1);
                    ba.right_len = static_cast<uint16_t>(bs.end_idx - bs.right_idx);
                }
            }

        public:
            Optimizer(const BinaryPattern& p) : atoms_(p.atoms().begin(), p.atoms().end()) {}
            OwnedBinaryPattern optimize() {
                build_branch_state();
                bool ch;
                do {
                    ch = false;
                    if (merge_pass([](const auto& l, const auto& r) -> std::optional<AtomVariant> {
                            if (auto *b1 = std::get_if<AtomByteSequence>(&l), *b2 = std::get_if<AtomByteSequence>(&r); b1 && b2)
                                if (b1->seq_end == b2->seq_start)
                                    return AtomByteSequence{ b1->seq_start, b2->seq_end };
                            return std::nullopt;
                        }))
                        ch = true;
                    if (merge_pass([](const auto& l, const auto& r) -> std::optional<AtomVariant> {
                            // Guard the merge: AtomWildcardFixed::length is uint16_t, so folding two
                            // long runs together could wrap and silently shorten the pattern.
                            if (auto *w1 = std::get_if<AtomWildcardFixed>(&l), *w2 = std::get_if<AtomWildcardFixed>(&r); w1 && w2)
                                if (w1->length + w2->length <= 0xFFFF)
                                    return AtomWildcardFixed{ (uint16_t)(w1->length + w2->length) };
                            return std::nullopt;
                        }))
                        ch = true;
                    if (merge_pass([](const auto& l, const auto& r) -> std::optional<AtomVariant> {
                            // Same uint16_t wrap guard as the fixed-run merge above.
                            if (auto *w1 = std::get_if<AtomWildcardRange>(&l), *w2 = std::get_if<AtomWildcardRange>(&r); w1 && w2)
                                if (w1->max + w2->max <= 0xFFFF)
                                    return AtomWildcardRange{ (uint16_t)(w1->min + w2->min), (uint16_t)(w1->max + w2->max) };
                            return std::nullopt;
                        }))
                        ch = true;
                    if (merge_pass([](const auto& l, const auto& r) -> std::optional<AtomVariant> {
                            if (auto* f = std::get_if<AtomWildcardFixed>(&l))
                                if (auto* rg = std::get_if<AtomWildcardRange>(&r))
                                    if (f->length + rg->max <= 0xFFFF)
                                        return AtomWildcardRange{ (uint16_t)(f->length + rg->min), (uint16_t)(f->length + rg->max) };
                            if (auto* rg2 = std::get_if<AtomWildcardRange>(&l); rg2)
                                if (auto* f2 = std::get_if<AtomWildcardFixed>(&r); f2)
                                    if (rg2->max + f2->length <= 0xFFFF)
                                        return AtomWildcardRange{ (uint16_t)(rg2->min + f2->length), (uint16_t)(rg2->max + f2->length) };
                            return std::nullopt;
                        }))
                        ch = true;
                } while (ch);
                fixup_branches();
                return OwnedBinaryPattern(std::move(atoms_), {});
            }
        };
        inline OwnedBinaryPattern parse_pattern(std::string_view s) {
            PatternParser p(s);
            return p.parse();
        }
        inline OwnedBinaryPattern optimize_pattern(const BinaryPattern& p) {
            std::vector<uint8_t> bytes(p.byte_sequence().begin(), p.byte_sequence().end());
            Optimizer o(p);
            OwnedBinaryPattern r = o.optimize();
            r.byte_sequence_mut() = std::move(bytes);
            return r;
        }
    } // namespace compiler
    template<typename SaveStackT = HeapStack<uint32_t>, typename CursorStackT = HeapStack<size_t>>
    class BinaryMatcher {
        const BinaryPattern& p_;
        const MatchTarget& t_;
        size_t mo_ = 0;
        size_t limit_ = SIZE_MAX;
        SaveStackT ss_;
        CursorStackT cs_;
        // Element type of the save stack. Cursors are size_t internally but are stored
        // narrowed to this on save, so the casts below are explicit rather than implicit.
        using save_value_t = std::remove_cvref_t<decltype(*std::declval<SaveStackT&>().data())>;
        template<typename I>
        static std::optional<I> read_le(std::span<const uint8_t> s) {
            if (s.size() < sizeof(I))
                return std::nullopt;
            I v = 0;
            for (size_t i = 0; i < sizeof(I); ++i)
                v |= static_cast<I>(s[i]) << (i * 8);
            return v;
        }
        std::optional<size_t> match_atoms(size_t dc, std::span<const AtomVariant> atoms) {
            if (atoms.empty())
                return dc;
            const auto& a0 = atoms.front();
            auto rem = atoms.subspan(1);
            std::optional<size_t> res;
            std::visit(Overloaded{
                           [&](const AtomByteSequence& a) {
                               auto pb = p_.byte_sequence().subspan(a.seq_start, a.seq_end - a.seq_start);
                               if (auto tb = t_.subrange(dc, pb.size()))
                                   if (std::equal(pb.begin(), pb.end(), tb->begin()))
                                       res = match_atoms(dc + pb.size(), rem);
                           },
                           [&](const AtomByteSequenceMasked& a) {
                               auto pb = p_.byte_sequence().subspan(a.seq_start, a.len);
                               auto mb = p_.byte_sequence().subspan(a.mask_start, a.len);
                               if (auto tb = t_.subrange(dc, a.len)) {
                                   bool m = true;
                                   for (uint16_t i = 0; i < a.len; ++i)
                                       if ((pb[i] & mb[i]) != ((*tb)[i] & mb[i])) {
                                           m = false;
                                           break;
                                       }
                                   if (m)
                                       res = match_atoms(dc + a.len, rem);
                               }
                           },
                           [&](const AtomWildcardFixed& a) {
                               if (dc + a.length <= t_.match_length())
                                   res = match_atoms(dc + a.length, rem);
                           },
                           [&](const AtomWildcardRange& a) {
                               const size_t sl = ss_.len();
                               const size_t cl = cs_.len();
                               for (uint32_t i = a.min; i <= (uint32_t)a.max; ++i) { // FIX: uint16 counter wraps when max==0xFFFF
                                   ss_.truncate(sl);
                                   cs_.truncate(cl);
                                   if (auto sm = match_atoms(dc + i, rem)) {
                                       res = sm;
                                       return;
                                   }
                               }
                           },
                           [&](const AtomBranch& a) {
                               const size_t sl = ss_.len();
                               const size_t cl = cs_.len();
                               auto l = rem.subspan(0, a.left_len);
                               auto r = rem.subspan(a.left_len, a.right_len);
                               auto af = rem.subspan(a.left_len + a.right_len);
                               if (auto le = match_atoms(dc, l))
                                   if (auto fm = match_atoms(*le, af)) {
                                       res = fm;
                                       return;
                                   }
                               ss_.truncate(sl);
                               cs_.truncate(cl);
                               if (auto re = match_atoms(dc, r))
                                   if (auto fm = match_atoms(*re, af)) {
                                       res = fm;
                                       return;
                                   }
                           },
                           [&](const AtomJump& a) {
                               std::optional<size_t> ta;
                               switch (a.type) {
                               case JumpType::RelByte: {
                                   if (auto v = t_.subrange(dc, 1))
                                       ta = (dc + 1) + (int8_t)(*v)[0];
                                   break;
                               }
                               case JumpType::RelDWord: {
                                   if (auto v = t_.subrange(dc, 4))
                                       ta = (dc + 4) + *read_le<int32_t>(*v);
                                   break;
                               }
                               case JumpType::AbsQWord: {
                                   if (auto v = t_.subrange(dc, 8))
                                       ta = t_.translate_absolute_address(*read_le<uint64_t>(*v));
                                   break;
                               }
                               }
                               if (ta)
                                   res = match_atoms(*ta, rem);
                           },
                           [&](const AtomRead& a) {
                               size_t w = 0;
                               uint32_t val = 0;
                               bool ok = false;
                               switch (a.width) {
                               case ReadWidth::Byte:
                                   if (auto v = t_.subrange(dc, 1)) {
                                       w = 1;
                                       val = (*v)[0];
                                       ok = true;
                                   }
                                   break;
                               case ReadWidth::Word:
                                   if (auto v = t_.subrange(dc, 2)) {
                                       w = 2;
                                       val = *read_le<uint16_t>(*v);
                                       ok = true;
                                   }
                                   break;
                               case ReadWidth::DWord:
                                   if (auto v = t_.subrange(dc, 4)) {
                                       w = 4;
                                       val = *read_le<uint32_t>(*v);
                                       ok = true;
                                   }
                                   break;
                               }
                               if (ok && ss_.push_value(val))
                                   res = match_atoms(dc + w, rem);
                           },
                           [&](const AtomCursorPush&) {
                               if (cs_.push_value(dc))
                                   res = match_atoms(dc, rem);
                           },
                           [&](const AtomCursorPop& a) {
                               if (auto c = cs_.pop_value())
                                   res = match_atoms(*c + a.advance, rem);
                           },
                           [&](const AtomSaveCursor&) {
                               if (ss_.push_value(static_cast<save_value_t>(dc)))
                                   res = match_atoms(dc, rem);
                           },
                           [&](const AtomSaveConstant& a) {
                               if (ss_.push_value(a.value))
                                   res = match_atoms(dc, rem);
                           } },
                a0);
            return res;
        }

    public:
        BinaryMatcher(const BinaryPattern& p, const MatchTarget& t) : p_(p), t_(t) {}
        // Start scanning at `start`, and optionally give up after `limit` start
        // offsets. next_match() otherwise always begins at 0 and runs forward until
        // it matches or the target is exhausted, which is the right default for
        // "find this somewhere" but wrong for "does this match HERE".
        //
        // The second question is what a caller asks when a cheap prefilter has
        // already located a candidate: it wants a yes or no at one offset, and a no
        // should cost nothing. Without a bound it costs a scan of the entire
        // remainder -- 950 rejected candidates over a 133MB image took six minutes,
        // and the same run with `limit = 1` takes 262ms.
        BinaryMatcher(const BinaryPattern& p, const MatchTarget& t, size_t start, size_t limit = SIZE_MAX)
            : p_(p), t_(t), mo_(start), limit_(limit == SIZE_MAX ? SIZE_MAX : start + limit) {}
        std::optional<std::span<const uint32_t>> next_match() {
            while (mo_ < t_.match_length() && mo_ < limit_) {
                ss_.truncate(0);
                ss_.push_value(0);
                cs_.truncate(0);
                if (match_atoms(mo_, p_.atoms())) {
                    ss_.data()[0] = static_cast<save_value_t>(mo_);
                    mo_++;
                    return std::span<const uint32_t>(ss_.data(), ss_.len());
                }
                mo_++;
            }
            return std::nullopt;
        }
    };
} // namespace maml
#endif
