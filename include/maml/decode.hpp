// SPDX-License-Identifier: BSL-1.0 OR MIT
#pragma once
// Instruction-aware decoding, Zydis-backed.
//
// Everything else in the engine is byte scanning and rel32/disp32 arithmetic
// (see generate.hpp). That cannot tell `movss xmm,[rcx+0x228]` (a 4-byte float
// read) from `movups xmm,[rcx+0x228]` (a 16-byte GUID read): the bytes differ
// only by a prefix, and a raw pattern happily matches mid-instruction. The
// `insn` pipeline stage decodes real instructions through this one wrapper so a
// match can be keyed on operand semantics -- a memory read of a given access
// size at `[reg + disp]` -- and capture the displacement.
//
// This is the single decode path; do not add a second one (the hand-rolled
// rel32/ripref arithmetic in generate.hpp is slated to move here later).
#include <Zydis/Zydis.h>
#include <cstdint>
#include <optional>

namespace maml::decode {

    // One decoded memory operand reduced to what `insn` matches on.
    struct MemoryOperand {
        bool present = false;        // the instruction has a memory operand
        bool base_is_gpr = false;    // base is a general-purpose register (object pointer)
        bool base_is_rip = false;    // RIP-relative (a global, not a struct field)
        bool has_index = false;      // an index register participates
        bool has_displacement = false;
        int64_t displacement = 0;
        unsigned size_bytes = 0;     // memory access width in bytes (1/2/4/8/16/32)
        bool reads = false;          // the memory operand is read
        bool writes = false;         // the memory operand is written
    };

    struct Instruction {
        unsigned length = 0;
        ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;
        bool is_lea = false;
        MemoryOperand mem;
    };

    inline const ZydisDecoder& long64_decoder() {
        static const ZydisDecoder decoder = [] {
            ZydisDecoder d;
            ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            return d;
        }();
        return decoder;
    }

    // Decode one instruction at `data` (up to `available` bytes). Returns
    // nullopt when the bytes are not a valid instruction. Pure: no engine state.
    inline std::optional<Instruction> decode_one(const uint8_t* data, size_t available) {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&long64_decoder(), data, available, &insn, operands)))
            return std::nullopt;
        Instruction out;
        out.length = insn.length;
        out.mnemonic = insn.mnemonic;
        out.is_lea = insn.mnemonic == ZYDIS_MNEMONIC_LEA;
        for (unsigned i = 0; i < insn.operand_count; ++i) {
            const auto& o = operands[i];
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;
            out.mem.present = true;
            out.mem.base_is_rip = o.mem.base == ZYDIS_REGISTER_RIP || o.mem.base == ZYDIS_REGISTER_EIP;
            out.mem.base_is_gpr = !out.mem.base_is_rip && o.mem.base != ZYDIS_REGISTER_NONE &&
                ZydisRegisterGetClass(o.mem.base) >= ZYDIS_REGCLASS_GPR8 &&
                ZydisRegisterGetClass(o.mem.base) <= ZYDIS_REGCLASS_GPR64;
            out.mem.has_index = o.mem.index != ZYDIS_REGISTER_NONE;
            out.mem.has_displacement = o.mem.disp.has_displacement;
            out.mem.displacement = o.mem.disp.value;
            out.mem.size_bytes = o.size / 8;
            out.mem.reads = (o.actions & ZYDIS_OPERAND_ACTION_READ) != 0;
            out.mem.writes = (o.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
            break; // the first (and for field access, only) memory operand
        }
        return out;
    }

} // namespace maml::decode
