// SPDX-License-Identifier: BSL-1.0 OR MIT
#pragma once
// Normalized x86-64 decoding for the optional instruction pipeline stage.
// A decoded access width is an encoding fact, not evidence of an object's type.
#ifndef MAML_ENABLE_INSN
    #define MAML_ENABLE_INSN 0
#endif
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>
#if MAML_ENABLE_INSN
    #include <Zydis/Zydis.h>
#endif

namespace maml::decode {
    inline constexpr bool available = MAML_ENABLE_INSN != 0;
    enum class Visibility { Explicit,
        Implicit,
        Hidden };
    struct MemoryOperand {
        unsigned index = 0;
        Visibility visibility = Visibility::Explicit;
        std::string_view base, index_register, segment;
        bool base_is_gpr = false, base_is_stack = false;
        unsigned scale = 0;
        int64_t displacement = 0;
        unsigned size_bytes = 0;
        bool reads = false, writes = false;
        unsigned disp_offset = 0, disp_size = 0;
    };
    struct Instruction {
        unsigned length = 0;
        std::string_view mnemonic;
        std::vector<MemoryOperand> memory;
    };
    inline bool known_register(std::string_view name) {
        constexpr std::string_view names[] = {
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
            "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
            "rip", "eip"
        };
        for (auto n : names)
            if (n == name)
                return true;
        return false;
    }
    inline bool known_mnemonic(std::string_view name) {
#if MAML_ENABLE_INSN
        for (unsigned i = 1; i <= ZYDIS_MNEMONIC_MAX_VALUE; ++i)
            if (const char* text = ZydisMnemonicGetString(static_cast<ZydisMnemonic>(i)); text && name == text)
                return true;
#endif
        return false;
    }
    inline std::optional<Instruction> decode_one(const uint8_t* data, size_t available_bytes) {
#if MAML_ENABLE_INSN
        static const ZydisDecoder decoder = [] {
            ZydisDecoder d;
            ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            return d;
        }();
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, available_bytes, &insn, operands)))
            return std::nullopt;
        Instruction out{ insn.length, ZydisMnemonicGetString(insn.mnemonic), {} };
        for (unsigned i = 0; i < insn.operand_count; ++i) {
            const auto& o = operands[i];
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;
            MemoryOperand m;
            m.index = o.id;
            m.visibility = o.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT   ? Visibility::Explicit
                           : o.visibility == ZYDIS_OPERAND_VISIBILITY_IMPLICIT ? Visibility::Implicit
                                                                               : Visibility::Hidden;
            m.base = o.mem.base == ZYDIS_REGISTER_NONE ? "none" : ZydisRegisterGetString(o.mem.base);
            m.index_register = o.mem.index == ZYDIS_REGISTER_NONE ? "none" : ZydisRegisterGetString(o.mem.index);
            m.segment = ZydisRegisterGetString(o.mem.segment);
            const auto cls = ZydisRegisterGetClass(o.mem.base);
            m.base_is_gpr = cls >= ZYDIS_REGCLASS_GPR8 && cls <= ZYDIS_REGCLASS_GPR64;
            const auto root = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.mem.base);
            m.base_is_stack = root == ZYDIS_REGISTER_RSP || root == ZYDIS_REGISTER_RBP;
            m.scale = o.mem.scale;
            m.displacement = o.mem.disp.has_displacement ? o.mem.disp.value : 0;
            m.size_bytes = o.size / 8;
            m.reads = (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
            m.writes = (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
            // Hidden stack operands have no corresponding encoded displacement.
            if (m.visibility == Visibility::Explicit) {
                m.disp_offset = insn.raw.disp.offset;
                m.disp_size = insn.raw.disp.size / 8;
            }
            out.memory.push_back(m);
        }
        return out;
#else
        (void)data;
        (void)available_bytes;
        return std::nullopt;
#endif
    }
} // namespace maml::decode
