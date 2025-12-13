#include "SymbolFile.h"
#include <fstream>
#include <sstream>
#include <iostream>

static uint16_t parse_hex_addr(const std::string& s) {
    size_t dollar = s.find('$');
    std::string clean = (dollar != std::string::npos) ? s.substr(dollar + 1) : s;
    try {
        return static_cast<uint16_t>(std::stoul(clean, nullptr, 16));
    } catch (...) { return 0; }
}

void SymbolFile::load_sym(const std::string& filename) {
    std::ifstream file(filename);
    std::string line, label, dummy, valStr;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == ';') continue;
        std::stringstream ss(line);
        ss >> label >> dummy >> valStr; // LAB EQU VAL
        if (dummy == "EQU" || dummy == "=") {
            if (valStr.back() == 'H' || valStr.back() == 'h')
                valStr.pop_back();
            uint16_t addr = parse_hex_addr(valStr);
            m_analyzer.context.add_label(addr, label);
        }
    }
}

void SymbolFile::load_map(const std::string& filename) {
    std::ifstream file(filename);
    std::string line, addrStr, label;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        ss >> addrStr >> label;
        uint16_t addr = parse_hex_addr(addrStr);
        if (!label.empty())
            m_analyzer.context.add_label(addr, label);
    }
}
