#include "Analyzer.h"
#include <fstream>
#include <sstream>
#include <iostream>

// ---------------------------------------------------------
// ProjectContext Implementation
// ---------------------------------------------------------

std::string ProjectContext::get_label(uint16_t address) const {
    auto it = labels.find(address);
    return (it != labels.end()) ? it->second : "";
}

void ProjectContext::add_label(uint16_t address, const std::string& label) {
    // Nie nadpisuj istniejących etykiet (priorytet mają te z plików)
    if (labels.find(address) == labels.end()) {
        labels[address] = label;
    }
}

void ProjectContext::add_block_desc(uint16_t addr, const std::string& desc) {
    if (!metadata[addr].block_description.empty()) metadata[addr].block_description += "\n";
    metadata[addr].block_description += "; " + desc;
}

void ProjectContext::add_inline_comment(uint16_t addr, const std::string& comment) {
    metadata[addr].inline_comment = comment;
}

std::string ProjectContext::get_inline_comment(uint16_t addr) {
    if (metadata.count(addr)) return metadata[addr].inline_comment;
    return "";
}

std::string ProjectContext::get_block_desc(uint16_t addr) {
    if (metadata.count(addr)) return metadata[addr].block_description;
    return "";
}

// ---------------------------------------------------------
// Analyzer Implementation
// ---------------------------------------------------------

Analyzer::Analyzer(Memory* memory) : Z80Analyzer<Memory>(memory, &context) {}

void Analyzer::set_map_type(CodeMap& map, uint16_t addr, ExtendedFlags type) {
    map[addr] = (map[addr] & ~TYPE_MASK) | (type << TYPE_SHIFT);
}

Analyzer::ExtendedFlags Analyzer::get_map_type(const CodeMap& map, uint16_t addr) {
    return static_cast<ExtendedFlags>((map[addr] & TYPE_MASK) >> TYPE_SHIFT);
}

std::vector<Analyzer::CodeLine> Analyzer::generate_listing(CodeMap& map, uint16_t& start_address, size_t instruction_limit, bool use_map) {
    std::vector<CodeLine> result;
    uint32_t pc = start_address;

    while (pc < 0x10000 && result.size() < instruction_limit) {
        uint16_t current_pc = static_cast<uint16_t>(pc);
        
        // 1. Sprawdź, czy mamy wymuszony typ z CTL
        ExtendedFlags forcedType = get_map_type(map, current_pc);

        // Jeśli typ jest nieznany (0), ale mamy profilowanie (use_map=true),
        // to sprawdzamy flagi profilera.
        bool is_code = false;
        
        if (forcedType == TYPE_CODE) {
            is_code = true;
        } else if (forcedType == TYPE_UNKNOWN) {
            if (use_map) {
                // Fallback do flag profilera
                if (map[current_pc] & Z80Analyzer<Memory>::FLAG_CODE_START) is_code = true;
                else if (map[current_pc] & Z80Analyzer<Memory>::FLAG_CODE_INTERIOR) {
                    pc++; continue; // Skip inside
                }
                // Jeśli nie ma flagi Code, a mamy mapę -> to są dane
            } else {
                is_code = true; // Raw mode default
            }
        }

        // --- Przetwarzanie ---
        
        if (is_code) {
            CodeLine line = this->parse_instruction(current_pc); // pc przesuwane przez ref wewnątrz
            
            // Wzbogać linię o komentarz z metadanych
            std::string comment = context.get_inline_comment(line.address);
            if (!comment.empty()) {
                    // Tutaj prosta implementacja, w praktyce CodeLine może mieć pole 'comment'
                    // Dla teraz doklejamy do mnemonika lub labela, zależnie od struktury CodeLine
                    // Zakładam, że w CodeLine nie ma pola comment, więc zostawiam to użytkownikowi UI,
                    // ALE klasa context jest publiczna, więc UI może sobie pobrać komentarz po adresie.
            }
            
            if (line.bytes.empty()) { // Fail-safe
                result.push_back(this->parse_db(current_pc, 1));
                pc++;
            } else {
                result.push_back(line);
                pc = current_pc; // parse_instruction przesunęło
            }
        } 
        else if (forcedType == TYPE_BYTE) {
            // CTL says Byte
            size_t count = 1;
            // Zbijamy w grupę, jeśli kolejne też są BYTE
            while (pc + count < 0x10000 && get_map_type(map, pc+count) == TYPE_BYTE) count++;
            // Limit for single DB line (e.g. 8 bytes)
            if (count > 8) count = 8; 
            
            uint16_t tmp = current_pc;
            result.push_back(this->parse_db(tmp, count));
            pc += count;
        }
        else if (forcedType == TYPE_WORD) {
            uint16_t tmp = current_pc;
            result.push_back(this->parse_dw(tmp, 1));
            pc = tmp;
        }
        else if (forcedType == TYPE_TEXT) {
            // SkoolKit text/string
            uint16_t tmp = current_pc;
            CodeLine line;
            line.address = tmp; 
            line.type = CodeLine::Type::DATA; 
            line.mnemonic = "DEFM";
            if (context.labels.count(tmp)) line.label = context.labels[tmp];
            
            std::string txt;
            size_t count = 0;
            // Czytamy póki jest flaga TEXT
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
        }
        else if (forcedType == TYPE_IGNORE) {
                pc++; // Skip silently or add a dummy line
        }
        else {
            // Unknown Data (from Profiler or Heuristic finding hole)
            // Use base class grouping logic
            this->group_data_blocks(pc, result, instruction_limit, [&](uint32_t addr) {
                    if (addr >= 0x10000) return false;
                    // Stop if we hit a known block type or code flag
                    if (get_map_type(map, addr) != TYPE_UNKNOWN) return false;
                    return !(map[addr] & (Z80Analyzer<Memory>::FLAG_CODE_START | Z80Analyzer<Memory>::FLAG_CODE_INTERIOR));
            });
        }
    }
    start_address = static_cast<uint16_t>(pc);
    return result;
}