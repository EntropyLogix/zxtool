#include "Analyzer.h"
#include "Core.h"
#include <fstream>
#include <sstream>
#include <iostream>

Analyzer::Analyzer(Memory* memory, Context* ctx) : Z80Analyzer<Memory>(memory, &ctx->getSymbols()), context(*ctx) {}

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
        
        ExtendedFlags forcedType = get_map_type(map, current_pc);
        bool is_code = false;
        
        if (forcedType == TYPE_CODE)
            is_code = true;
        else if (forcedType == TYPE_UNKNOWN) {
            is_code = true;
            if (use_map) {
                if (map[current_pc] & Z80Analyzer<Memory>::FLAG_CODE_INTERIOR) {
                    pc++;
                    continue;
                }
                if ((map[current_pc] & Z80Analyzer<Memory>::FLAG_DATA_READ) && !(map[current_pc] & Z80Analyzer<Memory>::FLAG_CODE_START))
                    is_code = false;
            }
        }
        if (is_code) {
            uint16_t instr_start = current_pc;
            CodeLine line = this->parse_instruction(current_pc);
            if (use_map && !(map[instr_start] & Z80Analyzer<Memory>::FLAG_CODE_START)) {
                bool collision = false;
                for (uint16_t k = instr_start + 1; k < current_pc; ++k) {
                    if (map[k] & Z80Analyzer<Memory>::FLAG_CODE_START) {
                        collision = true;
                        break;
                    }
                }
                if (collision) {
                    uint16_t db_addr = instr_start;
                    result.push_back(this->parse_db(db_addr, 1));
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
                result.push_back(this->parse_db(db_addr, 1));
                pc = db_addr;
                pc &= 0xFFFF;
            } else {
                result.push_back(line);
                pc = current_pc;
            }
        } 
        else if (forcedType == TYPE_BYTE) {
            size_t count = 1;
            while (pc + count < 0x10000 && get_map_type(map, pc+count) == TYPE_BYTE) count++;
            if (count > 8)
                count = 8; 
            uint16_t tmp = current_pc;
            result.push_back(this->parse_db(tmp, count));
            pc += count;
            pc &= 0xFFFF;
        }
        else if (forcedType == TYPE_WORD) {
            uint16_t tmp = current_pc;
            result.push_back(this->parse_dw(tmp, 1));
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
            // Use base class grouping logic
            this->group_data_blocks(pc, result, instruction_limit, [&](uint32_t addr) {
                    if (addr >= 0x10000) return false;
                    // Stop if we hit a known block type or code flag
                    if (get_map_type(map, addr) != TYPE_UNKNOWN) return false;
                    return !(map[addr] & (Z80Analyzer<Memory>::FLAG_CODE_START | Z80Analyzer<Memory>::FLAG_CODE_INTERIOR));
            });
            pc &= 0xFFFF;
        }
    }
    start_address = static_cast<uint16_t>(pc);
    return result;
}

uint16_t Analyzer::find_prev_instruction(CodeMap& map, uint16_t target_addr) {
    uint16_t ptr = target_addr - 1;
    int safety = 0;
    const int MAX_SAFETY = 32;

    while (safety < MAX_SAFETY) {
        uint8_t flags = map[ptr];

        if (flags & Z80Analyzer<Memory>::FLAG_CODE_START) {
            uint16_t temp = ptr;
            this->parse_instruction(temp);
            if (temp == target_addr) return ptr;
            break; // Desync
        }
        
        if (flags & Z80Analyzer<Memory>::FLAG_CODE_INTERIOR) {
            ptr--;
            safety++;
            continue;
        }

        break; // Unknown
    }

    // 3. Slow Path: Heuristic
    int search_depth = 24;
    uint16_t start_scan = target_addr - search_depth;
    
    std::map<uint16_t, int> votes;
    
    for (int i = 0; i <= (search_depth - 4); ++i) {
        uint16_t pc = start_scan + i;
        uint16_t prev = pc;
        int steps = 0;
        
        while (pc != target_addr && steps < 32) {
            uint16_t dist = (target_addr - pc) & 0xFFFF;
            if (dist > 0x8000) break; // Overshot target

            prev = pc;
            auto line = this->parse_instruction(pc);
            if (line.bytes.empty()) pc++;
            else pc += line.bytes.size();
            pc &= 0xFFFF;
            steps++;
        }
        if (pc == target_addr) {
            votes[prev]++;
        }
    }

    uint16_t winner = target_addr - 1;
    int max_votes = -1;
    
    for (auto const& [addr, count] : votes) {
        if (count > max_votes) {
            max_votes = count;
            winner = addr;
        }
    }

    // 4. Self-repair
    uint16_t temp_winner = winner;
    auto line = this->parse_instruction(temp_winner);
    size_t len = temp_winner - winner;
    
    map[winner] |= Z80Analyzer<Memory>::FLAG_CODE_START;
    for (size_t i = 1; i < len; ++i) {
        map[(uint16_t)(winner + i)] |= Z80Analyzer<Memory>::FLAG_CODE_INTERIOR;
    }

    return winner;
}