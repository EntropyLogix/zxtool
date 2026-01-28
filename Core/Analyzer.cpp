#include "Analyzer.h"
#include "Core.h"
#include <fstream>
#include <sstream>
#include <iostream>

Analyzer::Analyzer(Memory* memory, Context* ctx) : /*Z80Disassembler<Memory>(memory, &ctx->getSymbols()),*/ context(*ctx), m_map(), m_memory(memory), m_decoder(memory) {
    m_decoder.set_options({true, true});
}

void Analyzer::set_map_type(CodeMap& map, uint16_t addr, ExtendedFlags type) {
    map[addr] = (map[addr] & ~TYPE_MASK) | (type << TYPE_SHIFT);
}

Analyzer::ExtendedFlags Analyzer::get_map_type(const CodeMap& map, uint16_t addr) {
    return static_cast<ExtendedFlags>((map[addr] & TYPE_MASK) >> TYPE_SHIFT);
}

std::vector<Analyzer::CodeLine> Analyzer::parse_code(uint16_t& start_address, size_t instruction_limit, Memory::Map* external_code_map, bool use_execution, bool use_heuristic, size_t max_data_group, std::function<bool(uint16_t)> validator) {
    std::vector<CodeLine> lines;
    if (instruction_limit == 0) instruction_limit = 1;
    for (size_t i = 0; i < instruction_limit; ++i) {
        CodeLine line = m_decoder.parse_instruction(start_address);
        if (line.bytes.empty()) line = parse_db(start_address);
        lines.push_back(line);
        start_address += line.bytes.size();
    }
    return lines;
}

Analyzer::CodeLine Analyzer::parse_instruction(uint16_t address) {
    return m_decoder.parse_instruction(address);
}

Analyzer::CodeLine Analyzer::parse_db(uint16_t address, size_t count) {
    CodeLine line;
    line.address = address;
    line.mnemonic = "DB";
    for (size_t i = 0; i < count; ++i) {
        uint8_t b = m_memory->peek(address + i);
        line.bytes.push_back(b);
        line.operands.push_back({CodeLine::Operand::IMM8, b});
    }
    return line;
}

Analyzer::CodeLine Analyzer::parse_dw(uint16_t address, size_t count) {
    return parse_db(address, count * 2);
}

uint16_t Analyzer::parse_instruction_backwards(uint16_t target_addr, CodeMap* map) {
    return target_addr - 1;
}

/*std::vector<Analyzer::CodeLine> Analyzer::generate_listing(CodeMap& map, uint16_t& start_address, size_t instruction_limit, bool use_map, size_t max_data_group) {
    std::vector<CodeLine> result;
    uint32_t pc = start_address;

    while (pc < 0x10000 && result.size() < instruction_limit) {
        uint16_t current_pc = static_cast<uint16_t>(pc);
        
        ExtendedFlags forcedType = get_map_type(map, current_pc);

        // Stop only if address is invalid AND we don't have a manual override (type is UNKNOWN)
        if (!is_valid_address(current_pc) && forcedType == TYPE_UNKNOWN) {
            break;
        }
        bool is_code = false;
        
        if (forcedType == TYPE_CODE)
            is_code = true;
        else if (forcedType == TYPE_UNKNOWN) {
            is_code = true;
            if (use_map) {
                if (map[current_pc] & CodeMap::FLAG_CODE_INTERIOR) {
                    pc++;
                    continue;
                }
                if ((map[current_pc] & CodeMap::FLAG_DATA_READ) && !(map[current_pc] & CodeMap::FLAG_CODE_START))
                    is_code = false;
            }
        }
        if (is_code) {
            uint16_t instr_start = current_pc;
            CodeLine line = m_decoder.parse_instruction(current_pc);
            
            uint16_t instr_end = instr_start + (uint16_t)line.bytes.size();
            if (use_map && !(map[instr_start] & CodeMap::FLAG_CODE_START)) {
                bool collision = false;
                for (uint16_t k = instr_start + 1; k < instr_end; ++k) {
                    if (map[k] & CodeMap::FLAG_CODE_START) {
                        collision = true;
                        break;
                    }
                }
                if (collision) {
                    uint16_t db_addr = instr_start;
                    result.push_back(m_decoder.parse_db(db_addr, 1));
                    pc = db_addr;
                    pc &= 0xFFFF;
                    continue;
                }
            }
            const Comment* c = context.getComments().find(line.address, Comment::Type::Inline);
            std::string comment = c ? c->getText() : "";
            if (!comment.empty()) {
                    // Tutaj prosta implementacja, w praktyce CodeLine może mieć pole 'comment'
                    // Dla teraz doklejamy do mnemonika lub labela, zależnie od struktury CodeLine
                    // Zakładam, że w CodeLine nie ma pola comment, więc zostawiam to użytkownikowi UI,
                    // ALE klasa context jest publiczna, więc UI może sobie pobrać komentarz po adresie.
            }
            
            if (line.bytes.empty()) { // Fail-safe
                uint16_t db_addr = instr_start;
                result.push_back(m_decoder.parse_db(db_addr, 1));
                pc = db_addr;
                pc &= 0xFFFF;
            } else {
                result.push_back(line);
                pc += line.bytes.size();
            }
        } 
        else if (forcedType == TYPE_BYTE) {
            uint16_t tmp = current_pc;
            result.push_back(m_decoder.parse_db(tmp, 1));
            pc++;
            pc &= 0xFFFF;
        }
        else if (forcedType == TYPE_WORD) {
            uint16_t tmp = current_pc;
            result.push_back(m_decoder.parse_dw(tmp, 1));
            pc = tmp;
        }
        else if (forcedType == TYPE_TEXT) {
            uint16_t tmp = current_pc;
            CodeLine line;
            line.address = tmp; 
            line.type = CodeLine::Type::DATA; 
            line.mnemonic = "DEFM";
            const Symbol* s = context.getSymbols().find(tmp);
            if (s)
                line.label = s->getName();
            
            std::string txt;
            size_t count = 0;
            while(pc + count < 0x10000 && get_map_type(map, pc+count) == TYPE_TEXT) {
                uint8_t b = this->m_memory->peek(pc+count);
                line.bytes.push_back(b);
                // Proste filtrowanie znaków
                txt += (b >= 32 && b <= 126) ? (char)b : '.';
                count++;
            }
            line.operands.push_back(typename CodeLine::Operand(CodeLine::Operand::STRING, txt));
            result.push_back(line);
            pc += count;
            pc &= 0xFFFF;
        }
        else if (forcedType == TYPE_IGNORE) {
                pc++; // Skip silently or add a dummy line
                pc &= 0xFFFF;
        }
        else {
            // Unknown Data (from Profiler or Heuristic finding hole)
            // Default Strategy: "Vertical Stream" (1 byte = 1 line)
            uint16_t tmp = current_pc;
            result.push_back(m_decoder.parse_db(tmp, 1));
            pc++;
            pc &= 0xFFFF;
        }
    }
    start_address = static_cast<uint16_t>(pc);
    return result;
}*/