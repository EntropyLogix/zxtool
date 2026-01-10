#include "ControlFile.h"
#include "../Core/Core.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <regex>

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

static std::string clean_skool_tags(const std::string& text, Analyzer& analyzer) {
    std::string result;
    static const std::regex r_tag("#R\\$([0-9A-Fa-f]+)");
    
    std::smatch match;
    std::string::const_iterator searchStart(text.cbegin());
    while (std::regex_search(searchStart, text.cend(), match, r_tag)) {
        result.append(searchStart, match[0].first);
        std::string addrStr = match[1].str();
        uint16_t addr = parse_hex_addr(addrStr);
        std::string label = analyzer.context.getSymbols().get_label(addr);
        if (!label.empty())
            result += label + " ($" + addrStr + ")";
        else
            result += "$" + addrStr;
        searchStart = match[0].second;
    }
    result.append(searchStart, text.cend());

    return result;
}

bool ControlFile::load(const std::string& filename) {
    auto& map = m_analyzer.m_map;
    if (map.size() < 0x10000) map.resize(0x10000, 0);
    
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    
    // Pass 1: Load labels
    for (const auto& line : lines) {
        if (line.empty() || line[0] != '@') continue;
        
        size_t dollar = line.find('$');
        if (dollar == std::string::npos) continue;
        
        size_t endOfAddr = line.find_first_of(" ,", dollar);
        std::string addrStr = line.substr(dollar, endOfAddr - dollar);
        uint16_t addr = parse_hex_addr(addrStr);
        
        std::string remainder;
        if (endOfAddr != std::string::npos)
             remainder = line.substr(endOfAddr + 1);

        size_t labelPos = remainder.find("label=");
        if (labelPos != std::string::npos) {
            std::string name = remainder.substr(labelPos + 6);
            size_t space = name.find_first_of(" \r\n\t,");
            if (space != std::string::npos) name = name.substr(0, space);
            m_analyzer.context.getSymbols().add_label(addr, name);
        }
    }

    // Pass 2: Process everything else
    for (const auto& line : lines) {
        if (line.empty()) continue;
        
        char type = line[0];
        if (type == '@') continue;

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
                m_analyzer.set_map_type(map, addr, Analyzer::TYPE_CODE); // This should probably be add_inline_comment
                if (!remainder.empty()) m_analyzer.context.getComments().add(Comment(addr, clean_skool_tags(remainder, m_analyzer), Comment::Type::Inline));
                break;
            case 'C': // Comment
                if (!remainder.empty()) {
                    size_t first = remainder.find_first_not_of(" \t\r");
                    if (first != std::string::npos) {
                        size_t last = remainder.find_last_not_of(" \t\r");
                        m_analyzer.context.getComments().add(Comment(addr, clean_skool_tags(remainder.substr(first, (last - first + 1)), m_analyzer), Comment::Type::Inline));
                    }
                }
                break;
            case 'b': case 'B': // Byte
            case 's': case 'S': // Space
            case 'g':           // Game state
                set_range(Analyzer::TYPE_BYTE);
                if (!remainder.empty() && type == 'b') m_analyzer.context.getComments().add(Comment(addr, "; " + clean_skool_tags(remainder, m_analyzer), Comment::Type::Block));
                break;
            case 'w': case 'W': // Word
                set_range(Analyzer::TYPE_WORD);
                break;
            case 't': case 'T': case 'Z': // Text
                set_range(Analyzer::TYPE_TEXT);
                break;
            case 'u': case 'U': // Unused
                set_range(Analyzer::TYPE_IGNORE);
                if (!remainder.empty()) m_analyzer.context.getComments().add(Comment(addr, "; Unused: " + clean_skool_tags(remainder, m_analyzer), Comment::Type::Block));
                break;
            case 'M': // Memory map
                // Format: M base,length,description
                if (!remainder.empty()) m_analyzer.context.getComments().add(Comment(addr, "; Block: " + clean_skool_tags(remainder, m_analyzer), Comment::Type::Block));
                break;
            case 'i': // Ignore
                set_range(Analyzer::TYPE_IGNORE);
                break;
            case 'D': case 'N': // Description
                m_analyzer.context.getComments().add(Comment(addr, "; " + clean_skool_tags(remainder, m_analyzer), Comment::Type::Block));
                break;
            case 'R': // Register info
                m_analyzer.context.getComments().add(Comment(addr, "; [Regs: " + clean_skool_tags(remainder, m_analyzer) + "]", Comment::Type::Block));
                break;
        }
    }
    return true;
}

std::vector<std::string> ControlFile::get_extensions() const {
    return { ".ctl", ".txt" };
}
