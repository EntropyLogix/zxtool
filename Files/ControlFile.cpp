#include "ControlFile.h"
#include <fstream>
#include <sstream>
#include <vector>

static uint16_t parse_hex_addr(const std::string& s) {
    size_t dollar = s.find('$');
    std::string clean = (dollar != std::string::npos) ? s.substr(dollar + 1) : s;
    try {
        return static_cast<uint16_t>(std::stoul(clean, nullptr, 16));
    } catch (...) { return 0; }
}

static int parse_int_len(const std::string& s) {
    size_t dollar = s.find('$');
    try {
        if (dollar != std::string::npos)
            return std::stoi(s.substr(dollar + 1), nullptr, 16);
        return std::stoi(s);
    } catch (...) { return 1; }
}

void ControlFile::load(const std::string& filename) {
    auto& map = m_analyzer.m_map;
    if (map.size() < 0x10000) map.resize(0x10000, 0);
    
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        char type = line[0];
        size_t dollar = line.find('$');
        if (dollar == std::string::npos) continue;
        
        size_t endOfAddr = line.find_first_of(" ,", dollar);
        std::string addrStr = line.substr(dollar, endOfAddr - dollar);
        uint16_t addr = parse_hex_addr(addrStr);

        int length = 1;
        std::string remainder;

        if (endOfAddr != std::string::npos) {
            if (line[endOfAddr] == ',') {
                size_t nextComma = line.find(',', endOfAddr + 1);
                size_t spaceAfterParams = line.find(' ', endOfAddr + 1);
                size_t endOfLen = (nextComma != std::string::npos && nextComma < spaceAfterParams) ? nextComma : spaceAfterParams;
                
                std::string lenStr = line.substr(endOfAddr + 1, endOfLen - endOfAddr - 1);
                length = parse_int_len(lenStr);

                if (spaceAfterParams != std::string::npos)
                    remainder = line.substr(spaceAfterParams + 1);
            } else {
                remainder = line.substr(endOfAddr + 1);
            }
        }

        auto set_range = [&](Analyzer::ExtendedFlags t) {
            if (length > 1) {
                for(int i=0; i<length && (addr+i < 0x10000); ++i)
                    m_analyzer.set_map_type(map, addr + i, t);
            } else {
                m_analyzer.set_map_type(map, addr, t);
            }
        };

        switch (type) {
            case 'c': // Code
                m_analyzer.set_map_type(map, addr, Analyzer::TYPE_CODE);
                if (!remainder.empty()) m_analyzer.context.add_block_desc(addr, remainder);
                break;
            case 'C': // Comment
                 if (!remainder.empty()) m_analyzer.context.add_inline_comment(addr, remainder);
                 break;
            case 'b': case 'B': // Byte
            case 's': case 'S': // Space
            case 'g':           // Game state
                set_range(Analyzer::TYPE_BYTE);
                if (!remainder.empty() && type == 'b') m_analyzer.context.add_block_desc(addr, remainder);
                break;
            case 'w': case 'W': // Word
                set_range(Analyzer::TYPE_WORD);
                break;
            case 't': case 'T': case 'Z': // Text
                set_range(Analyzer::TYPE_TEXT);
                break;
            case 'i': // Ignore
                set_range(Analyzer::TYPE_IGNORE);
                break;
            case '@': { // Label
                size_t labelPos = remainder.find("label=");
                if (labelPos != std::string::npos) {
                    std::string name = remainder.substr(labelPos + 6);
                    size_t space = name.find_first_of(" \r\n\t");
                    if (space != std::string::npos) name = name.substr(0, space);
                    m_analyzer.context.add_label(addr, name);
                }
                break;
            }
            case 'D': case 'N': // Description
                m_analyzer.context.add_block_desc(addr, remainder);
                break;
            case 'R': // Register info
                m_analyzer.context.add_block_desc(addr, "[Regs: " + remainder + "]");
                break;
        }
    }
}
