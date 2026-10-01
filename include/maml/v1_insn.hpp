// SPDX-License-Identifier: BSL-1.0 OR MIT
#pragma once
#include "decode.hpp"
#include "v1.hpp"

namespace maml::v1 {
    enum class InstructionDecode { Metadata,
        Linear };
    struct InsnSpec {
        enum Access { Any,
            Read,
            Write,
            Lea } access = Any;
        unsigned size = 0;
        std::string base = "nonstack", index = "none", mnemonic;
        bool explicit_only = true;
        std::optional<unsigned> operand;
        bool displacement_address = false;
        std::string capture;
        static InsnSpec parse(std::string_view spec) {
            if (!decode::available)
                throw Error("UnsupportedFeature", "insn requires a build with MAML_ENABLE_INSN enabled");
            InsnSpec out;
            std::set<std::string> seen;
            size_t p = 0;
            while (p < spec.size()) {
                while (p < spec.size() && std::isspace(static_cast<unsigned char>(spec[p])))
                    ++p;
                if (p == spec.size())
                    break;
                size_t begin = p;
                while (p < spec.size() && !std::isspace(static_cast<unsigned char>(spec[p])))
                    ++p;
                const auto tok = spec.substr(begin, p - begin);
                const auto eq = tok.find('=');
                auto key = eq == tok.npos ? tok : tok.substr(0, eq);
                auto value = eq == tok.npos ? std::string_view{} : tok.substr(eq + 1);
                if (tok == "read" || tok == "write" || tok == "lea" || tok == "mem")
                    key = "access";
                else if (tok.starts_with("disp(") || tok.starts_with("disp_addr("))
                    key = "capture";
                if (!seen.insert(std::string(key)).second)
                    throw Error("InvalidArgument", "insn: duplicate " + std::string(key));
                if (key == "access" && tok != "read" && tok != "write" && tok != "lea" && tok != "mem")
                    throw Error("InvalidArgument", "insn: access must be read, write, lea or mem");
                if (key == "access")
                    out.access = tok == "read" ? Read : tok == "write" ? Write
                                                    : tok == "lea"     ? Lea
                                                                       : Any;
                else if (key == "size") {
                    if (value.empty())
                        throw Error("InvalidArgument", "insn: size requires a value");
                    auto r = std::from_chars(value.data(), value.data() + value.size(), out.size);
                    if (value.empty() || r.ec != std::errc{} || r.ptr != value.data() + value.size() ||
                        (out.size != 1 && out.size != 2 && out.size != 4 && out.size != 8 && out.size != 16 && out.size != 32 && out.size != 64))
                        throw Error("InvalidArgument", "insn: size must be 1,2,4,8,16,32,64 bytes");
                } else if (key == "base") {
                    if (value != "any" && value != "gpr" && value != "nonstack" && value != "stack" && value != "none" && !decode::known_register(value))
                        throw Error("InvalidArgument", "insn: unknown base register or class");
                    out.base = value;
                } else if (key == "index") {
                    if (value != "any" && value != "none" && (!decode::known_register(value) || value == "rip" || value == "eip"))
                        throw Error("InvalidArgument", "insn: unknown index register");
                    out.index = value;
                } else if (key == "operand") {
                    if (value == "any")
                        out.explicit_only = false;
                    else if (value != "explicit") {
                        if (value.empty())
                            throw Error("InvalidArgument", "insn: operand requires a value");
                        unsigned n = 0;
                        auto r = std::from_chars(value.data(), value.data() + value.size(), n);
                        if (value.empty() || r.ec != std::errc{} || r.ptr != value.data() + value.size() || n >= 10)
                            throw Error("InvalidArgument", "insn: operand must be explicit, any, or index 0..9");
                        out.operand = n;
                        out.explicit_only = false;
                    }
                } else if (key == "mnemonic") {
                    if (!decode::known_mnemonic(value))
                        throw Error("InvalidArgument", "insn: unknown mnemonic");
                    out.mnemonic = value;
                } else if (key == "capture") {
                    out.displacement_address = tok.starts_with("disp_addr(");
                    size_t prefix = out.displacement_address ? 10 : 5;
                    if (tok.back() != ')' || tok.size() <= prefix + 1)
                        throw Error("InvalidArgument", "insn: expected disp(name) or disp_addr(name)");
                    out.capture = tok.substr(prefix, tok.size() - prefix - 1);
                    auto letter = [](char c) {
                        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
                    };
                    if (!letter(out.capture[0]))
                        throw Error("InvalidArgument", "insn: invalid capture identifier");
                    for (char c : out.capture)
                        if (!letter(c) && !(c >= '0' && c <= '9'))
                            throw Error("InvalidArgument", "insn: invalid capture identifier");
                } else
                    throw Error("InvalidArgument", "insn: unknown token '" + std::string(tok) + "'");
            }
            if (!seen.contains("access"))
                throw Error("InvalidArgument", "insn requires read, write, lea or mem");
            if (out.capture.empty())
                throw Error("InvalidArgument", "insn requires a disp(name) or disp_addr(name) capture");
            if (out.access == Lea && out.size)
                throw Error("InvalidArgument", "insn: lea has no memory access size");
            return out;
        }
        bool matches(const decode::Instruction& insn, const decode::MemoryOperand& m) const {
            if (explicit_only && m.visibility != decode::Visibility::Explicit)
                return false;
            if (operand && m.index != *operand)
                return false;
            if (!mnemonic.empty() && insn.mnemonic != mnemonic)
                return false;
            if (base == "gpr" && !m.base_is_gpr)
                return false;
            if (base == "nonstack" && (!m.base_is_gpr || m.base_is_stack))
                return false;
            if (base == "stack" && !m.base_is_stack)
                return false;
            if (base != "gpr" && base != "nonstack" && base != "stack" && base != "any" && m.base != base)
                return false;
            if (index != "any" && m.index_register != index)
                return false;
            const bool lea = insn.mnemonic == "lea";
            if (access == Lea ? !lea : lea)
                return false;
            if (access == Read && !m.reads)
                return false;
            if (access == Write && !m.writes)
                return false;
            if (size && m.size_bytes != size)
                return false;
            if (displacement_address && m.disp_size == 0)
                return false;
            return true;
        }
    };
} // namespace maml::v1
