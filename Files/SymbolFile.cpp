#include "SymbolFile.h"
#include "../Core/Core.h"
#include "../Core/Symbol.h"
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

void SymbolFormat::load_sym(const std::string& filename) {
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == ';') continue;

        std::string comment;
        size_t comment_pos = line.find(';');
        if (comment_pos != std::string::npos) {
            comment = line.substr(comment_pos + 1);
            line = line.substr(0, comment_pos);
            
            size_t first = comment.find_first_not_of(" \t\r");
            if (first != std::string::npos) {
                size_t last = comment.find_last_not_of(" \t\r");
                comment = comment.substr(first, (last - first + 1));
            } else {
                comment.clear();
            }
        }

        std::stringstream ss(line);
        std::string label, dummy, valStr;
        if ((ss >> label >> dummy >> valStr) && (dummy == "EQU" || dummy == "=")) {
            if (valStr.back() == 'H' || valStr.back() == 'h')
                valStr.pop_back();
            uint16_t addr = parse_hex_addr(valStr);
            Symbol symbol(label, addr, Symbol::Type::Constant);
            m_analyzer.context.getSymbols().add_label(symbol.read(), symbol.getName());
            if (!comment.empty()) {
                m_analyzer.context.getComments().add(Comment(symbol.read(), comment, Comment::Type::Inline));
            }
        }
    }
}

void SymbolFormat::load_map(const std::string& filename) {
    std::ifstream file(filename);
    std::string line, addrStr, label;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        ss >> addrStr >> label;
        uint16_t addr = parse_hex_addr(addrStr);
        if (!label.empty()) {
            Symbol symbol(label, addr, Symbol::Type::Label);
            m_analyzer.context.getSymbols().add_label(symbol.read(), symbol.getName());
        }
    }
}

bool SymbolFormat::load(const std::string& filename) {
    if (filename.find(".map") != std::string::npos) {
        load_map(filename);
        return true;
    } else {
        load_sym(filename);
        return true;
    }
}

std::vector<std::string> SymbolFormat::get_extensions() const {
    return { ".sym", ".map" };
}
