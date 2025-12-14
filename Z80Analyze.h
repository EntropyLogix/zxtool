//  ▄▄▄▄▄▄▄▄    ▄▄▄▄      ▄▄▄▄
//  ▀▀▀▀▀███  ▄██▀▀██▄   ██▀▀██
//      ██▀   ██▄  ▄██  ██    ██
//    ▄██▀     ██████   ██ ██ ██
//   ▄██      ██▀  ▀██  ██    ██
//  ███▄▄▄▄▄  ▀██▄▄██▀   ██▄▄██
//  ▀▀▀▀▀▀▀▀    ▀▀▀▀      ▀▀▀▀   Analyze.h
// Verson: 1.1.5a
//
// This file contains the Z80Analyzer class,
// which provides functionality for disassembling Z80 machine code.
//
// Copyright (c) 2025 Adam Szulc
// MIT License

#ifndef __Z80ANALYZE_H__
#define __Z80ANALYZE_H__

#include "Z80.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <optional>
#include <set>
#include <iostream>
#include <functional>

#if defined(__GNUC__) || defined(__clang__)
#define Z80_PACKED_STRUCT __attribute__((packed))
#else
#define Z80_PACKED_STRUCT
#endif

#if defined(_MSC_VER)
#define Z80_PUSH_PACK(n) __pragma(pack(push, n))
#define Z80_POP_PACK() __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
#define Z80_PUSH_PACK(n) _Pragma("pack(push, n)")
#define Z80_POP_PACK() _Pragma("pack(pop)")
#else
#define Z80_PUSH_PACK(n)
#define Z80_POP_PACK()
#endif

class ILabels {
public:
    virtual ~ILabels() = default;
    virtual std::string get_label(uint16_t address) const = 0;
    virtual void add_label(uint16_t address, const std::string& label) = 0;
};

template <typename TMemory> class Z80Analyzer {
public:
    using CodeMap = std::vector<uint8_t>;
    enum MapFlags : uint8_t {
        FLAG_NONE = 0,
        FLAG_CODE_START = 1 << 0,    // Start of instruction
        FLAG_CODE_INTERIOR = 1 << 1, // Arguments/interior of instruction
        FLAG_DATA_READ = 1 << 2,     // Data read
        FLAG_DATA_WRITE = 1 << 3,    // Data write
        FLAG_VISITED = 1 << 4        // For heuristic - visited
    };
    struct CodeLine {
        enum Type : uint32_t {
            UNKNOWN      = 0,
            LOAD         = 1 << 0,
            EXCHANGE     = 1 << 1,
            BLOCK        = 1 << 2,
            ALU          = 1 << 3,
            SHIFT_ROTATE = 1 << 4,
            BIT          = 1 << 5,
            JUMP         = 1 << 6,
            CALL         = 1 << 7,
            RETURN       = 1 << 8,
            STACK        = 1 << 9,
            IO           = 1 << 10,
            CPU_CONTROL  = 1 << 11,
            DATA         = 1 << 12
        };
        struct Operand {
            enum Type {
                REG8, REG16, IMM8, IMM16, MEM_IMM16, MEM_REG16, MEM_INDEXED, CONDITION, PORT_IMM8, STRING, CHAR_LITERAL, UNKNOWN
            };
            Operand(Type t, int32_t n) : type(t), num_val(n), offset(0), base_reg("") {}
            Operand(Type t, const std::string& s) : type(t), s_val(s), num_val(0), offset(0), base_reg("") {}
            Operand(Type t, const std::string& s, int8_t o) : type(t), s_val(s), num_val(0), offset(o), base_reg("") {}
            Operand(Type t, const std::string& s, int8_t o, const std::string& base_r) : type(t), s_val(s), num_val(0), offset(o), base_reg(base_r) {}

            Type type;
            std::string s_val;
            int32_t num_val;
            int8_t offset;
            std::string label;
            std::string base_reg;
        };
        uint16_t address;
        std::string label;
        std::string mnemonic;
        int ticks;
        int ticks_alt;
        uint32_t type;
        std::vector<Operand> operands;
        std::vector<uint8_t> bytes;

        bool has_flag(Type t) const { return (type & t) != 0; }
    };
    Z80Analyzer(TMemory* memory, ILabels* labels = nullptr) : m_memory(memory), m_labels(labels) {}
    virtual ~Z80Analyzer() = default;

    enum class AnalysisMode { RAW, HEURISTIC, EXEC };
    class CodeMapProfiler {
    public:
        CodeMapProfiler(CodeMap& map, TMemory* mem) 
            : m_code_map(map), m_memory(mem), m_cpu(nullptr), m_labels(nullptr) {}

        void connect(Z80<CodeMapProfiler, Z80StandardEvents, CodeMapProfiler>* cpu) {
            m_cpu = cpu;
        }
        void set_labels(ILabels* labels) {
            m_labels = labels;
        }
        uint8_t read(uint16_t address) {
            if (m_inside_instruction && m_cpu && m_cpu->get_PC() == address) {
                m_instruction_byte_count++;
                m_code_map[address] |= (m_instruction_byte_count == 1) ? FLAG_CODE_START : FLAG_CODE_INTERIOR;
            } else
                m_code_map[address] |= FLAG_DATA_READ;
            return m_memory->peek(address);
        }
        void write(uint16_t address, uint8_t value) {
            m_code_map[address] |= FLAG_DATA_WRITE;
            m_memory->poke(address, value);
        }
        void reset() {
            std::fill(m_code_map.begin(), m_code_map.end(), FLAG_NONE);
            m_pc_before_step = 0;
            m_inside_instruction = false;
            m_instruction_byte_count = 0;
        }
        void before_step() {
            m_inside_instruction = true;
            if (m_cpu) {
                m_pc_before_step = m_cpu->get_PC();
                m_instruction_byte_count = 0;
            }
        }
        void after_step() {
            m_inside_instruction = false;
            if (m_cpu && m_labels) {
               uint16_t pc_after = m_cpu->get_PC();
               if (m_pc_before_step + m_instruction_byte_count != pc_after) {
                    bool is_ret = false;
                    uint8_t opcode = m_memory->peek(m_pc_before_step);
                    if (opcode == 0xC9 || (opcode & 0xC7) == 0xC0) {
                       is_ret = true; // RET or RET cc
                    } else if (opcode == 0xED) {
                        uint8_t opcode2 = m_memory->peek(m_pc_before_step + 1);
                        if ((opcode2 & 0xC7) == 0x45)
                            is_ret = true; // RETN / RETI
                   }
                   if (!is_ret && m_labels->get_label(pc_after).empty()) {
                        bool is_call = (opcode == 0xCD) || ((opcode & 0xC7) == 0xC4) || ((opcode & 0xC7) == 0xC7);
                        std::stringstream ss;
                        ss << (is_call ? "SUB_" : "L_") << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << pc_after;
                        m_labels->add_label(pc_after, ss.str());
                   }
               }
            }
        }
        uint8_t in(uint16_t port) { return 0xFF; }
        void out(uint16_t port, uint8_t value) {}        
        void before_IRQ() {} void after_IRQ() {} void before_NMI() {} void after_NMI() {}
    private:
        CodeMap& m_code_map;
        TMemory* m_memory;
        Z80<CodeMapProfiler, Z80StandardEvents, CodeMapProfiler>* m_cpu;
        ILabels* m_labels;
        uint16_t m_pc_before_step = 0;
        bool m_inside_instruction = false;
        uint8_t m_instruction_byte_count = 0;
    };
    virtual std::vector<CodeLine> parse_code(uint16_t& start_address, size_t instruction_limit, CodeMap* external_code_map = nullptr, bool use_execution = false, bool use_heuristic = false) {
        CodeMap local_map;
        CodeMap* pMap = external_code_map; 
        if (!pMap) {
            local_map.resize(0x10000, FLAG_NONE);
            pMap = &local_map;
        } else if (pMap->size() < 0x10000)
            pMap->resize(0x10000, FLAG_NONE);
        bool has_map_info = (external_code_map != nullptr);
        if (use_execution) {
            run_execution_phase(*pMap, start_address);
            has_map_info = true; 
        }
        if (use_heuristic) {
            run_heuristic_phase(*pMap, start_address);
            has_map_info = true;
        }
        return generate_listing(*pMap, start_address, instruction_limit, has_map_info);
    }
    virtual CodeLine parse_db(uint16_t& address, size_t count = 1) {
        CodeLine line_info;
        line_info.address = address;
        line_info.type = CodeLine::Type::DATA;
        line_info.mnemonic = "DB";
        line_info.ticks = 0;
        line_info.ticks_alt = 0;
        if (m_labels)
            line_info.label = m_labels->get_label(address);
        for (size_t i = 0; i < count; ++i) {
            uint8_t byte = m_memory->peek(address++);
            line_info.bytes.push_back(byte);
            line_info.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::IMM8, byte));
        }
        return line_info;
    }
    virtual CodeLine parse_dw(uint16_t& address, size_t count = 1) {
        CodeLine line_info;
        line_info.address = address;
        line_info.type = CodeLine::Type::DATA;
        line_info.mnemonic = "DW";
        line_info.ticks = 0;
        line_info.ticks_alt = 0;
        if (m_labels)
            line_info.label = m_labels->get_label(address);
        for (size_t i = 0; i < count; ++i) {
            uint8_t low = m_memory->peek(address++);
            uint8_t high = m_memory->peek(address++);
            line_info.bytes.push_back(low);
            line_info.bytes.push_back(high);
            line_info.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::IMM16, (uint16_t)(high << 8) | low));
        }
        return line_info;
    }
    virtual CodeLine parse_dz(uint16_t& address) {
        CodeLine line_info;
        line_info.address = address;
        line_info.type = CodeLine::Type::DATA;
        line_info.mnemonic = "DZ";
        line_info.ticks = 0;
        line_info.ticks_alt = 0;
        if (m_labels)
            line_info.label = m_labels->get_label(address);
        std::string text;
        uint8_t byte;
        while ((byte = m_memory->peek(address++)) != 0) {
            line_info.bytes.push_back(byte);
            text += (char)byte;
        }
        line_info.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::STRING, text));
        return line_info;
    }
    virtual CodeLine parse_ds(uint16_t& address, size_t count, std::optional<uint8_t> fill_byte = std::nullopt) {
        CodeLine line_info;
        line_info.address = address;
        line_info.type = CodeLine::Type::DATA;
        line_info.mnemonic = "DS";
        line_info.ticks = 0;
        line_info.ticks_alt = 0;
        if (m_labels)
            line_info.label = m_labels->get_label(address);
        line_info.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::IMM16, count));
        if (fill_byte.has_value())
            line_info.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::IMM8, *fill_byte));
        address += count;
        return line_info;
    }
    virtual CodeLine parse_instruction(uint16_t& address) {
        CodeLine line_info;
        line_info.address = address;
        line_info.type = CodeLine::Type::UNKNOWN;
        line_info.ticks = 0;
        line_info.ticks_alt = 0;
        ParseContext ctx(address, line_info.bytes, m_memory);
        if (m_labels)
            line_info.label = m_labels->get_label(address);
        set_index_mode(IndexMode::HL);
        std::optional<uint8_t> opcode_opt = ctx.peek_byte();
        if (!opcode_opt)
            return line_info;
        uint8_t opcode = *opcode_opt;
        while (opcode == 0xDD || opcode == 0xFD) {
            set_index_mode((opcode == 0xDD) ? IndexMode::IX : IndexMode::IY);
            opcode_opt = ctx.peek_byte();
            if (!opcode_opt)
                return to_db(line_info);
            opcode = *opcode_opt;
        }
        switch (opcode) {
        case 0x00:
            line_info.mnemonic = "NOP";
            line_info.type = CodeLine::Type::CPU_CONTROL;
            line_info.ticks = 4;
            break;
        case 0x01: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "BC"), typename CodeLine::Operand(CodeLine::Operand::IMM16, *word_opt)};
            line_info.ticks = 10;
            break;
        }
        case 0x02:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "BC"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 7;
            break;
        case 0x03:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
            line_info.ticks = 6;
            break;
        case 0x04:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x05:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x06: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0x07:
            line_info.mnemonic = "RLCA";
            line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x08:
            line_info.mnemonic = "EX AF, AF'";
            line_info.type = CodeLine::Type::EXCHANGE;
            line_info.ticks = 4;
            break;
        case 0x09:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str()), typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 15;
            break;
        case 0x0A:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "BC")};
            line_info.ticks = 7;
            break;
        case 0x0B:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
            line_info.ticks = 6;
            break;
        case 0x0C:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x0D:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x0E: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0x0F:
            line_info.mnemonic = "RRCA";
            line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x10: {
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            int8_t offset = (int8_t)*byte_opt;
            uint16_t target_address = address + offset;
            line_info.mnemonic = "DJNZ";
            line_info.type = CodeLine::Type::JUMP | CodeLine::Type::ALU;
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, target_address);
            if (m_labels)
                target_op.label = m_labels->get_label(target_address);
            line_info.operands = {target_op};
            line_info.ticks = 8;
            line_info.ticks_alt = 13;
            break;
        }
        case 0x11: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE"), typename CodeLine::Operand(CodeLine::Operand::IMM16, *word_opt)};
            line_info.ticks = 10;
            break;
        }
        case 0x12:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "DE"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 7;
            break;
        case 0x13:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
            line_info.ticks = 6;
            break;
        case 0x14:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x15:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x16: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0x17:
            line_info.mnemonic = "RLA";
            line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x18: {
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            int8_t offset = (int8_t)*byte_opt;
            uint16_t target_address = address + offset;
            line_info.mnemonic = "JR";
            line_info.type = CodeLine::Type::JUMP;
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, target_address);
            if (m_labels)
                target_op.label = m_labels->get_label(target_address);
            line_info.operands = {target_op};
            line_info.ticks = 12;
            break;
        }
        case 0x19:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str()), typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 15;
            break;
        case 0x1A:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "DE")};
            line_info.ticks = 7;
            break;
        case 0x1B:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
            line_info.ticks = 6;
            break;
        case 0x1C:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x1D:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x1E: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0x1F:
            line_info.mnemonic = "RRA";
            line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x20: {
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            int8_t offset = (int8_t)*byte_opt;
            uint16_t target_address = address + offset;
            line_info.mnemonic = "JR";
            line_info.type = CodeLine::Type::JUMP;
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, target_address);
            if (m_labels)
                target_op.label = m_labels->get_label(target_address);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NZ"), target_op};
            line_info.ticks = 7;
            line_info.ticks_alt = 12;
            break;
        }
        case 0x21: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str()), typename CodeLine::Operand(CodeLine::Operand::IMM16, *word_opt)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 10 : 14;
            break;
        }
        case 0x22: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt), typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 16 : 20;
            break;
        }
        case 0x23:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 6 : 10;
            break;
        case 0x24:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x25:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x26: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 11; 
            break;
        }
        case 0x27:
            line_info.mnemonic = "DAA";
            line_info.type = CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x28: {
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            int8_t offset = (int8_t)*byte_opt;
            uint16_t target_address = address + offset;
            line_info.mnemonic = "JR";
            line_info.type = CodeLine::Type::JUMP;
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, target_address);
            if (m_labels)
                target_op.label = m_labels->get_label(target_address);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "Z"), target_op};
            line_info.ticks = 7;
            line_info.ticks_alt = 12;
            break;
        }
        case 0x29: {
            std::string reg = get_indexed_reg_str();
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, reg), typename CodeLine::Operand(CodeLine::Operand::REG16, reg)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 15;
            break;
        }
        case 0x2A: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str()), typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 16 : 20;
            break;
        }
        case 0x2B:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 6 : 10;
            break;
        case 0x2C:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x2D:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x2E: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 11; 
            break;
        }
        case 0x2F:
            line_info.mnemonic = "CPL";
            line_info.type = CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x30: {
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            int8_t offset = (int8_t)*byte_opt;
            uint16_t target_address = address + offset;
            line_info.mnemonic = "JR";
            line_info.type = CodeLine::Type::JUMP;
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, target_address);
            if (m_labels)
                target_op.label = m_labels->get_label(target_address);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NC"), target_op};
            line_info.ticks = 7;
            line_info.ticks_alt = 12;
            break;
        }
        case 0x31: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "SP"), typename CodeLine::Operand(CodeLine::Operand::IMM16, *word_opt)};
            line_info.ticks = 10;
            break;
        }
        case 0x32: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 13;
            break;
        }
        case 0x33:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "SP")};
            line_info.ticks = 6;
            break;
        case 0x34:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 23;
            break;
        case 0x35:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 23;
            break;
        case 0x36: {
            typename CodeLine::Operand addr_op = get_indexed_addr_operand(ctx);
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {addr_op, typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 10 : 19;
            break;
        }
        case 0x37:
            line_info.mnemonic = "SCF";
            line_info.type = CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x38: {
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            int8_t offset = (int8_t)*byte_opt;
            uint16_t target_address = address + offset;
            line_info.mnemonic = "JR";
            line_info.type = CodeLine::Type::JUMP;
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, target_address);
            if (m_labels)
                target_op.label = m_labels->get_label(target_address);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "C"), target_op};
            line_info.ticks = 7;
            line_info.ticks_alt = 12;
            break;
        }
        case 0x39:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str()), typename CodeLine::Operand(CodeLine::Operand::REG16, "SP")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 15;
            break;
        case 0x3A: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt)};
            line_info.ticks = 13;
            break;
        }
        case 0x3B:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "SP")};
            line_info.ticks = 6;
            break;
        case 0x3C:
            line_info.mnemonic = "INC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x3D:
            line_info.mnemonic = "DEC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x3E: {
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0x3F:
            line_info.mnemonic = "CCF";
            line_info.type = CodeLine::Type::ALU;
            line_info.ticks = 4;
            break;
        case 0x40:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x41:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x42:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x43:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x44:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x45:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x46:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x47:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x48:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x49:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x4A:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x4B:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x4C:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x4D:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x4E:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x4F:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x50:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x51:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x52:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x53:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x54:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x55:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x56:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x57:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x58:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x59:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x5A:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x5B:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x5C:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x5D:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x5E:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x5F:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x60:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x61:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x62:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x63:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x64: {
            std::string reg = get_indexed_h_str();
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, reg), typename CodeLine::Operand(CodeLine::Operand::REG8, reg)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        }
        case 0x65:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x66:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "H"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x67:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x68:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x69:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x6A:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x6B:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x6C:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x6D: {
            std::string reg = get_indexed_l_str();
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, reg), typename CodeLine::Operand(CodeLine::Operand::REG8, reg)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        }
        case 0x6E:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "L"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x6F:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str()), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x70:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x71:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x72:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x73:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x74:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "H")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x75:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "L")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x76:
            line_info.mnemonic = "HALT";
            line_info.type = CodeLine::Type::CPU_CONTROL;
            line_info.ticks = 4;
            break;
        case 0x77:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {get_indexed_addr_operand(ctx), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x78:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x79:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x7A:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x7B:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x7C:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x7D:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x7E:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x7F:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x80:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x81:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x82:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x83:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x84:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x85:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x86:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x87:
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x88:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x89:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x8A:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x8B:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x8C:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x8D:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x8E:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x8F:
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x90:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x91:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x92:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x93:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x94:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x95:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x96:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x97:
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0x98:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0x99:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0x9A:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0x9B:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0x9C:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x9D:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0x9E:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0x9F:
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0xA0:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0xA1:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0xA2:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0xA3:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0xA4:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xA5:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xA6:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0xA7:
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0xA8:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0xA9:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0xAA:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0xAB:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0xAC:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xAD:
            line_info.mnemonic = "XOR"; 
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xAE:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0xAF:
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0xB0:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0xB1:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0xB2:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0xB3:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0xB4:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xB5:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xB6:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0xB7:
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0xB8:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
            line_info.ticks = 4;
            break;
        case 0xB9:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
            line_info.ticks = 4;
            break;
        case 0xBA:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
            line_info.ticks = 4;
            break;
        case 0xBB:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
            line_info.ticks = 4;
            break;
        case 0xBC:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_h_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xBD:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, get_indexed_l_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xBE:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {get_indexed_addr_operand(ctx)};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 7 : 19;
            break;
        case 0xBF:
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 4;
            break;
        case 0xC0:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NZ")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xC1:
            line_info.mnemonic = "POP";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
            line_info.ticks = 10;
            break;
        case 0xC2: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NZ"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xC3: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xC4: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NZ"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xC5:
            line_info.mnemonic = "PUSH";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
            line_info.ticks = 11;
            break;
        case 0xC6: {
            line_info.mnemonic = "ADD";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xC7:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x00)};
            line_info.ticks = 11;
            break;
        case 0xC8:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "Z")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xC9:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.ticks = 10;
            break;
        case 0xCA: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "Z"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xCB: {
            if (get_index_mode() == IndexMode::HL) {
                auto byte_opt = ctx.peek_byte();
                if (!byte_opt) return to_db(line_info);
                uint8_t cb_opcode = *byte_opt;
                const char* registers[] = {"B", "C", "D", "E", "H", "L", "(HL)", "A"};
                const char* operations[] = {"RLC", "RRC", "RL", "RR", "SLA", "SRA", "SLL", "SRL"};
                const char* bit_ops[] = {"BIT", "RES", "SET"};
                uint8_t operation_group = cb_opcode >> 6;
                uint8_t bit = (cb_opcode >> 3) & 0x07;
                uint8_t reg_code = cb_opcode & 0x07;
                std::string reg_str = registers[reg_code];
                if (operation_group == 0) {
                    line_info.mnemonic = operations[bit];
                    line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
                    line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, reg_str)};
                    line_info.ticks = (reg_code == 6) ? 15 : 8;
                } else {
                    line_info.mnemonic = bit_ops[operation_group - 1];
                    line_info.type = CodeLine::Type::BIT | CodeLine::Type::ALU;
                    line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, (int32_t)bit), typename CodeLine::Operand(CodeLine::Operand::REG8, reg_str)};
                    line_info.ticks = (reg_code == 6) ? (operation_group == 1 ? 12 : 15) : 8;
                }
            } else {
                auto offset_opt = ctx.peek_byte();
                if (!offset_opt)
                    return to_db(line_info);
                int8_t offset = (int8_t)*offset_opt;
                auto cb_opcode_opt = ctx.peek_byte();
                if (!cb_opcode_opt)
                    return to_db(line_info);
                uint8_t cb_opcode = *cb_opcode_opt;
                const char* operations[] = {"RLC", "RRC", "RL", "RR", "SLA", "SRA", "SLL", "SRL"};
                const char* bit_ops[] = {"BIT", "RES", "SET"};
                const char* registers[] = {"B", "C", "D", "E", "H", "L", "", "A"};
                std::string base_reg = (get_index_mode() == IndexMode::IX) ? "IX" : "IY"; 
                typename CodeLine::Operand addr_op(CodeLine::Operand::MEM_INDEXED, "", offset, base_reg);
                uint8_t operation_group = cb_opcode >> 6;
                uint8_t bit = (cb_opcode >> 3) & 0x07;
                uint8_t reg_code = cb_opcode & 0x07;
                if (operation_group == 0) {
                    line_info.mnemonic = operations[bit];
                    line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
                    line_info.operands = {addr_op};
                    line_info.ticks = 23;
                } else {
                    line_info.mnemonic = bit_ops[operation_group - 1];
                    line_info.type = CodeLine::Type::BIT | CodeLine::Type::ALU;
                    line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, (int32_t)bit), addr_op};
                    line_info.ticks = (operation_group == 1) ? 20 : 23;
                }
                if (reg_code != 6) {
                    std::string reg_name = registers[reg_code];
                    if (reg_code == 4) reg_name = get_indexed_h_str();
                    else if (reg_code == 5) reg_name = get_indexed_l_str();
                    line_info.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::REG8, reg_name));
                }
            }
            break;
        }
        case 0xCC: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "Z"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xE9:
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 4 : 8;
            break;
        case 0xCD: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {target_op};
            line_info.ticks = 17;
            break;
        }
        case 0xCE: {
            line_info.mnemonic = "ADC";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt) return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xCF:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x08)};
            line_info.ticks = 11;
            break;
        case 0xD0:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NC")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xD1:
            line_info.mnemonic = "POP";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
            line_info.ticks = 10;
            break;
        case 0xD2: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NC"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xD3: {
            line_info.mnemonic = "OUT";
            line_info.type = CodeLine::Type::IO;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt) return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::PORT_IMM8, *byte_opt), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
            line_info.ticks = 11;
            break;
        }
        case 0xD4: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "NC"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xD5:
            line_info.mnemonic = "PUSH";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
            line_info.ticks = 11;
            break;
        case 0xD6: {
            line_info.mnemonic = "SUB";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt) return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xD7:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x10)};
            line_info.ticks = 11;
            break;
        case 0xD8:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "C")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xD9:
            line_info.mnemonic = "EXX";
            line_info.type = CodeLine::Type::EXCHANGE;
            line_info.ticks = 4;
            break;
        case 0xDA: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "C"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xDB: {
            line_info.mnemonic = "IN";
            line_info.type = CodeLine::Type::IO;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt) return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::PORT_IMM8, *byte_opt)};
            line_info.ticks = 11;
            break;
        }
        case 0xDC: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "C"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xDE: {
            line_info.mnemonic = "SBC";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt) return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xDF:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x18)};
            line_info.ticks = 11;
            break;
        case 0xE0:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "PO")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xE1:
            line_info.mnemonic = "POP";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 10 : 14;
            break;
        case 0xE2: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "PO"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xE3:
            line_info.mnemonic = "EX";
            line_info.type = CodeLine::Type::EXCHANGE | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "SP"), typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 19 : 23;
            break;
        case 0xE4: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "PO"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xE5:
            line_info.mnemonic = "PUSH";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 11 : 15;
            break;
        case 0xE6: {
            line_info.mnemonic = "AND";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt) return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xE7:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x20)};
            line_info.ticks = 11;
            break;
        case 0xE8:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "PE")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xEA: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels) target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "PE"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xEB:
            line_info.mnemonic = "EX";
            line_info.type = CodeLine::Type::EXCHANGE;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE"), typename CodeLine::Operand(CodeLine::Operand::REG16, "HL")};
            line_info.ticks = 4;
            break;
        case 0xED: {
            auto opcodeED_opt = ctx.peek_byte();
            if (!opcodeED_opt) return to_db(line_info);
            uint8_t opcodeED = *opcodeED_opt;
            set_index_mode(IndexMode::HL);
            switch (opcodeED) {
            case 0x40:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "B"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x41:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "B")};
                line_info.ticks = 12;
                break;
            case 0x42:
                line_info.mnemonic = "SBC HL, BC";
                line_info.type = CodeLine::Type::ALU;
                line_info.ticks = 15;
                break;
            case 0x43: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt), typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
                line_info.ticks = 20;
                break;
            }
            case 0x44:
            case 0x4C:
            case 0x54:
            case 0x5C:
            case 0x64:
            case 0x6C:
            case 0x74:
            case 0x7C:
                line_info.mnemonic = "NEG";
                line_info.type = CodeLine::Type::ALU;
                line_info.ticks = 8;
                break;
            case 0x45:
            case 0x55:
            case 0x5D:
            case 0x65:
            case 0x6D:
            case 0x75:
            case 0x7D:
                line_info.mnemonic = "RETN";
                line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
                line_info.ticks = 14;
                break;
            case 0x46:
            case 0x4E:
            case 0x66:
            case 0x6E:
                line_info.mnemonic = "IM";
                line_info.type = CodeLine::Type::CPU_CONTROL;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0)};
                line_info.ticks = 8;
                break;
            case 0x47:
                line_info.mnemonic = "LD I, A";
                line_info.type = CodeLine::Type::LOAD;
                line_info.ticks = 9;
                break;
            case 0x48:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "C"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x49:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "C")};
                line_info.ticks = 12;
                break;
            case 0x4A:
                line_info.mnemonic = "ADC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "BC")};
                line_info.ticks = 15;
                break;
            case 0x4B: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "BC"), typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt)};
                line_info.ticks = 20;
                break;
            }
            case 0x4D:
                line_info.mnemonic = "RETI";
                line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
                line_info.ticks = 14;
                break;
            case 0x4F:
                line_info.mnemonic = "LD R, A";
                line_info.type = CodeLine::Type::LOAD;
                line_info.ticks = 9;
                break;
            case 0x50:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "D"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x51:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "D")};
                line_info.ticks = 12;
                break;
            case 0x52:
                line_info.mnemonic = "SBC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
                line_info.ticks = 15;
                break;
            case 0x53: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt), typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
                line_info.ticks = 20;
                break;
            }
            case 0x56:
            case 0x76:
                line_info.mnemonic = "IM";
                line_info.type = CodeLine::Type::CPU_CONTROL;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 1)};
                line_info.ticks = 8;
                break;
            case 0x57:
                line_info.mnemonic = "LD A, I";
                line_info.type = CodeLine::Type::LOAD;
                line_info.ticks = 9;
                break;
            case 0x58:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "E"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x59:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "E")};
                line_info.ticks = 12;
                break;
            case 0x5A:
                line_info.mnemonic = "ADC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "DE")};
                line_info.ticks = 15;
                break;
            case 0x5B: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "DE"), typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt)};
                line_info.ticks = 20;
                break;
            }
            case 0x5E:
            case 0x7E:
                line_info.mnemonic = "IM";
                line_info.type = CodeLine::Type::CPU_CONTROL;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 2)};
                line_info.ticks = 8;
                break;
            case 0x5F:
                line_info.mnemonic = "LD A, R";
                line_info.type = CodeLine::Type::LOAD;
                line_info.ticks = 9;
                break;
            case 0x60:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "H"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x61:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "H")};
                line_info.ticks = 12;
                break;
            case 0x62:
                line_info.mnemonic = "SBC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "HL")};
                line_info.ticks = 15;
                break;
            case 0x63: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt), typename CodeLine::Operand(CodeLine::Operand::REG16, "HL")};
                line_info.ticks = 20;
                break;
            }
            case 0x67:
                line_info.mnemonic = "RRD";
                line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
                line_info.ticks = 18;
                break;
            case 0x68:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "L"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x69:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "L")};
                line_info.ticks = 12;
                break;
            case 0x6A:
                line_info.mnemonic = "ADC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "HL")};
                line_info.ticks = 15;
                break;
            case 0x6B: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt)};
                line_info.ticks = 20;
                break;
            }
            case 0x6F:
                line_info.mnemonic = "RLD";
                line_info.type = CodeLine::Type::SHIFT_ROTATE | CodeLine::Type::ALU;
                line_info.ticks = 18;
                break;
            case 0x70:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x71:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::IMM8, 0)};
                line_info.ticks = 12;
                break;
            case 0x72:
                line_info.mnemonic = "SBC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "SP")};
                line_info.ticks = 15;
                break;
            case 0x73: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt), typename CodeLine::Operand(CodeLine::Operand::REG16, "SP")};
                line_info.ticks = 20;
                break;
            }
            case 0x78:
                line_info.mnemonic = "IN";
                line_info.type = CodeLine::Type::IO;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG8, "A"), typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C")};
                line_info.ticks = 12;
                break;
            case 0x79:
                line_info.mnemonic = "OUT";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "C"), typename CodeLine::Operand(CodeLine::Operand::REG8, "A")};
                line_info.ticks = 12;
                break;
            case 0x7A:
                line_info.mnemonic = "ADC";
                line_info.type = CodeLine::Type::ALU;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "HL"), typename CodeLine::Operand(CodeLine::Operand::REG16, "SP")};
                line_info.ticks = 15;
                break;
            case 0x7B: {
                line_info.mnemonic = "LD";
                line_info.type = CodeLine::Type::LOAD;
                auto word_opt = ctx.peek_word();
                if (!word_opt)
                    return to_db(line_info);
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "SP"), typename CodeLine::Operand(CodeLine::Operand::MEM_IMM16, *word_opt)};
                line_info.ticks = 20;
                break;
            }
            case 0xA0:
                line_info.mnemonic = "LDI";
                line_info.type = CodeLine::Type::LOAD | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xA1:
                line_info.mnemonic = "CPI";
                line_info.type = CodeLine::Type::ALU | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xA2:
                line_info.mnemonic = "INI";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xA3:
                line_info.mnemonic = "OUTI";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xA8:
                line_info.mnemonic = "LDD";
                line_info.type = CodeLine::Type::LOAD | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xA9:
                line_info.mnemonic = "CPD";
                line_info.type = CodeLine::Type::ALU | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xAA:
                line_info.mnemonic = "IND";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xAB:
                line_info.mnemonic = "OUTD";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                break;
            case 0xB0:
                line_info.mnemonic = "LDIR";
                line_info.type = CodeLine::Type::LOAD | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xB1:
                line_info.mnemonic = "CPIR";
                line_info.type = CodeLine::Type::ALU | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xB2:
                line_info.mnemonic = "INIR";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xB3:
                line_info.mnemonic = "OTIR";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xB8:
                line_info.mnemonic = "LDDR";
                line_info.type = CodeLine::Type::LOAD | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xB9:
                line_info.mnemonic = "CPDR";
                line_info.type = CodeLine::Type::ALU | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xBA:
                line_info.mnemonic = "INDR";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            case 0xBB:
                line_info.mnemonic = "OTDR";
                line_info.type = CodeLine::Type::IO | CodeLine::Type::BLOCK;
                line_info.ticks = 16;
                line_info.ticks_alt = 21;
                break;
            default:
                line_info.mnemonic = "NOP";
                line_info.type = CodeLine::Type::CPU_CONTROL;
                line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0xED), typename CodeLine::Operand(CodeLine::Operand::IMM8, opcodeED)};
                line_info.ticks = 8;
            }
            break;
        }
        case 0xEC: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "PE"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xEE: {
            line_info.mnemonic = "XOR";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xEF:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x28)};
            line_info.ticks = 11;
            break;
        case 0xF0:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "P")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xF1:
            line_info.mnemonic = "POP";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "AF")};
            line_info.ticks = 10;
            break;
        case 0xF2: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "P"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xF3:
            line_info.mnemonic = "DI";
            line_info.type = CodeLine::Type::CPU_CONTROL;
            line_info.ticks = 4;
            break;
        case 0xF4: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "P"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xF5:
            line_info.mnemonic = "PUSH";
            line_info.type = CodeLine::Type::STACK | CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "AF")};
            line_info.ticks = 11;
            break;
        case 0xF6: {
            line_info.mnemonic = "OR";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xF7:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x30)};
            line_info.ticks = 11;
            break;
        case 0xF8:
            line_info.mnemonic = "RET";
            line_info.type = CodeLine::Type::RETURN | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "M")};
            line_info.ticks = 5;
            line_info.ticks_alt = 11;
            break;
        case 0xF9:
            line_info.mnemonic = "LD";
            line_info.type = CodeLine::Type::LOAD;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::REG16, "SP"), typename CodeLine::Operand(CodeLine::Operand::REG16, get_indexed_reg_str())};
            line_info.ticks = (get_index_mode() == IndexMode::HL) ? 6 : 10;
            break;
        case 0xFA: {
            line_info.mnemonic = "JP";
            line_info.type = CodeLine::Type::JUMP;
            auto word_opt = ctx.peek_word();
            if (!word_opt)
                return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "M"), target_op};
            line_info.ticks = 10;
            break;
        }
        case 0xFB:
            line_info.mnemonic = "EI";
            line_info.type = CodeLine::Type::CPU_CONTROL;
            line_info.ticks = 4;
            break;
        case 0xFC: {
            line_info.mnemonic = "CALL";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            auto word_opt = ctx.peek_word();
            if (!word_opt) return to_db(line_info);
            typename CodeLine::Operand target_op(CodeLine::Operand::IMM16, *word_opt);
            if (m_labels)
                target_op.label = m_labels->get_label(target_op.num_val);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::CONDITION, "M"), target_op};
            line_info.ticks = 10;
            line_info.ticks_alt = 17;
            break;
        }
        case 0xFE: {
            line_info.mnemonic = "CP";
            line_info.type = CodeLine::Type::ALU;
            auto byte_opt = ctx.peek_byte();
            if (!byte_opt)
                return to_db(line_info);
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, *byte_opt)};
            line_info.ticks = 7;
            break;
        }
        case 0xFF:
            line_info.mnemonic = "RST";
            line_info.type = CodeLine::Type::CALL | CodeLine::Type::STACK;
            line_info.operands = {typename CodeLine::Operand(CodeLine::Operand::IMM8, 0x38)};
            line_info.ticks = 11;
            break;
        }
        if (line_info.mnemonic.empty())
            return to_db(line_info);
        return line_info;
    }
protected:
    static constexpr size_t EXECUTION_TRACE_LIMIT = 1000000;
    enum class IndexMode { HL, IX, IY };
    struct ParseContext {
        ParseContext(uint16_t& addr, std::vector<uint8_t>& b, TMemory* mem) : address(addr), bytes(b), memory(mem) {}
        std::optional<uint8_t> peek_byte() {
            if (address > 0xFFFF)
                return std::nullopt;
            uint8_t value = memory->peek(address++);
            bytes.push_back(value);
            return value;
        }
        std::optional<uint16_t> peek_word() {
            auto low_byte_opt = peek_byte();
            if (!low_byte_opt)
                return std::nullopt;
            auto high_byte_opt = peek_byte();
            if (!high_byte_opt)
                return std::nullopt;
            return ((uint16_t)*high_byte_opt << 8) | *low_byte_opt;
        }
        uint16_t& address;
        std::vector<uint8_t>& bytes;
        TMemory* memory;
    };
    void group_data_blocks(uint32_t& pc, std::vector<CodeLine>& result, size_t instruction_limit, std::function<bool(uint32_t)> is_data) {
        while (pc < 0x10000 && is_data(pc)) {
            if (result.size() >= instruction_limit)
                break;
            uint16_t scan_pc = (uint16_t)pc;
            uint8_t fill_byte = m_memory->peek(scan_pc);
            size_t repeat_count = 0;
            while (scan_pc + repeat_count < 0x10000 && is_data(scan_pc + repeat_count) && m_memory->peek(scan_pc + repeat_count) == fill_byte)
                repeat_count++;
            const size_t DS_THRESHOLD = 4;
            if (repeat_count >= DS_THRESHOLD) {
                result.push_back(parse_ds(scan_pc, repeat_count, fill_byte));
                pc += repeat_count;
            } else {
                uint16_t db_start_pc = (uint16_t)pc;
                size_t db_count = 0;
                while (pc < 0x10000 && is_data(pc)) {
                    uint8_t next_fill = m_memory->peek(pc);
                    size_t next_repeat = 0;
                    while (pc + next_repeat < 0x10000 && is_data(pc + next_repeat) && m_memory->peek(pc + next_repeat) == next_fill)
                        next_repeat++;
                    if (next_repeat >= DS_THRESHOLD)
                        break;
                    db_count++;
                    pc++;
                }
                if (db_count > 0)
                    result.push_back(parse_db(db_start_pc, db_count));
            }
        }
    }
    CodeLine to_db(CodeLine& line_info) {
        line_info.mnemonic = "DB";
        line_info.type = CodeLine::Type::DATA;
        line_info.operands.clear();
        for (uint8_t byte : line_info.bytes)
            line_info.operands.emplace_back(CodeLine::Operand::IMM8, byte);
        return line_info;
    }
    std::vector<uint16_t> analyze_code_map(const CodeMapProfiler& profiler) {
        std::vector<uint16_t> smc_locations;
        for (uint32_t i = 0; i < 0x10000; ++i) {
            uint8_t flags = profiler.m_code_map[i];
            bool is_code = (flags & CodeMapProfiler::FLAG_CODE_START) || (flags & CodeMapProfiler::FLAG_CODE_INTERIOR);
            bool is_written = (flags & CodeMapProfiler::FLAG_DATA_WRITE);
            if (is_code && is_written)
                smc_locations.push_back((uint16_t)i);
        }
        return smc_locations;
    }
    IndexMode get_index_mode() const { return m_index_mode; }
    std::string get_indexed_reg_str() {
        if (get_index_mode() == IndexMode::IX)
            return "IX";
        if (get_index_mode() == IndexMode::IY)
            return "IY";
        return "HL";
    }
    void set_index_mode(IndexMode mode) { m_index_mode = mode; }
    std::string get_indexed_h_str() {
        if (get_index_mode() == IndexMode::IX)
            return "IXH";
        if (get_index_mode() == IndexMode::IY)
            return "IYH";
        return "H";
    }
    std::string get_indexed_l_str() {
        if (get_index_mode() == IndexMode::IX)
            return "IXL";
        if (get_index_mode() == IndexMode::IY)
            return "IYL";
        return "L";
    }
    std::string format_indexed_address(const std::string& reg, int8_t offset) {
        std::stringstream ss;
        ss << "(" << reg << (offset >= 0 ? "+" : "") << (int)offset << ")";
        return ss.str();
    }
    typename CodeLine::Operand get_indexed_addr_operand(ParseContext& ctx) {
        if (get_index_mode() == IndexMode::HL)
            return typename CodeLine::Operand(CodeLine::Operand::MEM_REG16, "HL", 0, "HL");
        auto byte_opt = ctx.peek_byte();
        if (!byte_opt)
             return typename CodeLine::Operand(CodeLine::Operand::UNKNOWN, 0);
        int8_t offset = (int8_t)*byte_opt;
        std::string base_reg = (get_index_mode() == IndexMode::IX) ? "IX" : "IY"; 
        return typename CodeLine::Operand(CodeLine::Operand::MEM_INDEXED, "", offset, base_reg);
    }
    void run_execution_phase(CodeMap& map, uint16_t start_addr) {
        CodeMapProfiler profiler(map, m_memory);
        profiler.set_labels(m_labels);
        Z80<CodeMapProfiler, Z80DefaultEvents, CodeMapProfiler> cpu(&profiler, nullptr, &profiler);
        profiler.connect(&cpu);
        cpu.set_PC(start_addr);
        std::set<uint16_t> executed_pcs;
        for (size_t i = 0; i < EXECUTION_TRACE_LIMIT; ++i) {
            uint16_t pc = cpu.get_PC();
            executed_pcs.insert(pc);
            cpu.step();
            if (cpu.is_halted())
                break;
        }
    }
    void run_heuristic_phase(CodeMap& map, uint16_t start_addr) {
        std::vector<uint16_t> work_list;
        bool found_existing_code = false;
        for(size_t i=0; i<map.size(); ++i) {
            if (map[i] & FLAG_CODE_START) {
                if (!(map[i] & FLAG_VISITED))
                    work_list.push_back((uint16_t)i);
                found_existing_code = true;
            }
        }
        if (!found_existing_code || work_list.empty())
            work_list.push_back(start_addr);
        while (!work_list.empty()) {
            uint16_t current_addr = work_list.back();
            work_list.pop_back();
            if (map[current_addr] & FLAG_VISITED)
                continue;
            while (true) {
                if (map[current_addr] & FLAG_VISITED)
                    break;
                uint16_t temp_pc = current_addr;
                CodeLine line = parse_instruction(temp_pc);
                uint16_t len = temp_pc - current_addr;
                map[current_addr] |= (FLAG_CODE_START | FLAG_VISITED);
                for(size_t k=1; k<len && (current_addr+k < 0x10000); ++k)
                    map[current_addr+k] |= (FLAG_CODE_INTERIOR | FLAG_VISITED);
                if (line.has_flag(CodeLine::Type::JUMP) || line.has_flag(CodeLine::Type::CALL)) {
                    if (!line.operands.empty()) {
                        const auto& last_op = line.operands.back();
                        if (last_op.type == CodeLine::Operand::Type::IMM16) {
                            uint16_t target = (uint16_t)last_op.num_val;
                            work_list.push_back(target);
                            if (m_labels && m_labels->get_label(target).empty()) {
                                std::stringstream ss;
                                ss << (line.type == CodeLine::Type::CALL ? "SUB_" : "L_");
                                ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << target;
                                m_labels->add_label(target, ss.str());
                            }
                        }
                    }
                }
                bool stop = false;
                if (line.mnemonic == "RET" || line.mnemonic == "RETI" || line.mnemonic == "RETN" || line.mnemonic == "HALT") 
                    stop = true;
                else if (line.mnemonic == "JP" || line.mnemonic == "JR") {
                     bool is_conditional = !line.operands.empty() && line.operands[0].type == CodeLine::Operand::Type::CONDITION;
                     if (!is_conditional)
                        stop = true;
                }
                current_addr = temp_pc;
                if (stop)
                    break;
            }
        }
    }
    virtual std::vector<CodeLine> generate_listing(CodeMap& map, uint16_t& start_address, size_t instruction_limit, bool use_map) {
        std::vector<CodeLine> result;
        uint32_t pc = start_address;
        while (pc < 0x10000 && result.size() < instruction_limit) {
            uint16_t current_pc = (uint16_t)pc;
            bool is_code = true;
            if (use_map) {
                if (map[current_pc] & FLAG_CODE_INTERIOR) {
                    pc++;
                    continue;
                }
                if ((map[current_pc] & FLAG_DATA_READ) && !(map[current_pc] & FLAG_CODE_START))
                    is_code = false;
            }
            if (is_code) {
                uint16_t temp_pc = current_pc;
                CodeLine line = parse_instruction(temp_pc);
                if (line.bytes.empty()) {
                    result.push_back(parse_db(current_pc, 1));
                    pc++;
                } else {
                    result.push_back(line);
                    pc = temp_pc;
                }
            } else {
                group_data_blocks(pc, result, instruction_limit, [&](uint32_t addr) { 
                     if (addr >= 0x10000)
                        return false;
                     return !(map[addr] & (FLAG_CODE_START | FLAG_CODE_INTERIOR));
                });
            }
        }
        start_address = (uint16_t)pc;
        return result;
    }
    TMemory* m_memory;
    IndexMode m_index_mode;
    ILabels* m_labels = nullptr;
};

#endif //__Z80ANALYZE_H__
