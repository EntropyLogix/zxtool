#include "LstFile.h"
#include "../Utils/Strings.h"
#include "../Utils/Commands.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>
#include <set>

LstFile::LstFile(Core& core) : m_core(core) {}

LoadResult LstFile::load(const std::string& path, std::vector<LoadedBlock>& blocks, uint16_t load_address) {
    // LST files are typically not loaded as binary content, but we can support it if needed.
    // For now, we treat them primarily as auxiliary files for symbols and map info.
    if (load(path)) {
        return {true, std::nullopt};
    }
    return {false, std::nullopt};
}

bool LstFile::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        parse_line(line);
    }
    return true;
}

void LstFile::parse_data(const std::string& data) {
    std::stringstream ss(data);
    std::string line;
    while (std::getline(ss, line)) {
        parse_line(line);
    }
}

std::vector<std::string> LstFile::get_extensions() const {
    return {".lst"};
}

static bool is_mnemonic(const std::string& s) {
    static const std::set<std::string> mnemonics = {
        "ADC", "ADD", "AND", "BIT", "CALL", "CCF", "CP", "CPD", "CPDR", "CPI", "CPIR", "CPL", "DAA", "DEC", "DI",
        "DJNZ", "EI", "EX", "EXX", "HALT", "IM", "IN", "INC", "IND", "INDR", "INI", "INIR", "JP", "JR", "LD",
        "LDD", "LDDR", "LDI", "LDIR", "NEG", "NOP", "OR", "OTDR", "OTIR", "OUT", "OUTD", "OUTI", "POP", "PUSH",
        "RES", "RET", "RETI", "RETN", "RL", "RLA", "RLC", "RLCA", "RLD", "RR", "RRA", "RRC", "RRCA", "RRD",
        "RST", "SBC", "SCF", "SET", "SLA", "SRA", "SRL", "SUB", "XOR",
        // Z80N
        "NEXTREG", "PIXELAD", "PIXELDN", "SETAE", "LDIX", "LDWS", "LDIRX", "LDDX", "LDDRX", "LDPIRX", "OUTINB",
        "SWAPNIB", "MIRROR", "BSLA", "BSRA", "BSRL", "BSRF", "BRLC", "MUL", "TEST", "LDIRSCALE"
    };
    std::string upper = Strings::upper(s);
    return mnemonics.count(upper);
}

void LstFile::parse_line(const std::string& line) {
    // Typical LST format:
    // Pasmo:      0000 3E 01      LD A, 1
    // SjasmPlus:  1 0000 3E 01    LD A, 1
    // Generic:    0000: 3E 01     LD A, 1
    
    std::string clean_line = Strings::trim(line);
    if (clean_line.empty()) return;

    // Regex for "ADDR[:] BYTES..."
    // Matches: Optional line number, 4 hex digits (Addr), optional colon, optional spaces, hex bytes
    static const std::regex re_line(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{4})[:]?\s+((?:[0-9A-Fa-f]{2}\s*)+)(.*))");
    // Regex for "VALUE LABEL EQU..." or "ADDR LABEL:" (No bytes)
    static const std::regex re_symbol(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{4,})[:]?\s+(.*))");

    std::smatch match;
    
    if (std::regex_search(line, match, re_line)) {
        std::string addr_str = match[1];
        std::string bytes_str = match[2];
        std::string rest = match[3];

        try {
            // LST files usually have hex addresses without 0x/$ prefix
            uint16_t addr = (uint16_t)std::stoul(addr_str, nullptr, 16);
            
            // Count bytes to mark code map
            std::stringstream ss(bytes_str);
            std::string byte_s;
            int byte_count = 0;
            while (ss >> byte_s) {
                if (byte_s.length() == 2) byte_count++;
            }

            if (byte_count > 0) {
                bool is_code = true;
                std::string upper_rest = Strings::upper(rest);
                if (upper_rest.find(" DB ") != std::string::npos || upper_rest.find(" DEFB ") != std::string::npos ||
                    upper_rest.find(" DW ") != std::string::npos || upper_rest.find(" DEFW ") != std::string::npos ||
                    upper_rest.find(" DS ") != std::string::npos || upper_rest.find(" DEFS ") != std::string::npos ||
                    upper_rest.find(" DM ") != std::string::npos || upper_rest.find(" DEFM ") != std::string::npos) {
                    is_code = false;
                }

                auto& map = m_core.get_code_map();
                if (is_code) {
                    map.mark_code(addr, byte_count, true);
                } else {
                    map.mark_data(addr, byte_count, false, true);
                }
            }

            std::string trim_rest = Strings::trim(rest);
            if (!trim_rest.empty()) {
                size_t col_pos = trim_rest.find(':');
                if (col_pos != std::string::npos) {
                    std::string label = Strings::trim(trim_rest.substr(0, col_pos));
                    if (Commands::is_identifier(label)) {
                        m_core.get_context().getSymbols().add_label(addr, label);
                    }
                } else {
                    std::stringstream ss_rest(trim_rest);
                    std::string first_word;
                    ss_rest >> first_word;
                    if (Commands::is_identifier(first_word) && !is_mnemonic(first_word)) {
                         m_core.get_context().getSymbols().add_label(addr, first_word);
                    }
                    // Add the rest of the line as a comment
                    m_core.get_context().getComments().add(Comment(addr, trim_rest, Comment::Type::Inline));
                }
            }
        } catch (...) {}
    } else if (std::regex_search(line, match, re_symbol)) {
        // Handle EQU / Labels without bytes
        std::string val_str = match[1];
        std::string rest = match[2];
        
        try {
            uint16_t val = (uint16_t)std::stoul(val_str, nullptr, 16);
            std::string upper_rest = Strings::upper(rest);
            std::string trim_rest = Strings::trim(rest);

            // Check for EQU / DEFL / =
            if (upper_rest.find(" EQU ") != std::string::npos || upper_rest.find(" DEFL ") != std::string::npos || upper_rest.find(" = ") != std::string::npos) {
                std::stringstream ss(trim_rest);
                std::string label;
                ss >> label;
                if (Commands::is_identifier(label)) {
                    m_core.get_context().getSymbols().add(Symbol(label, val, Symbol::Type::Constant));
                }
            } else {
                // Check for Label definition (e.g. "Label:")
                size_t col_pos = trim_rest.find(':');
                if (col_pos != std::string::npos) {
                    std::string label = Strings::trim(trim_rest.substr(0, col_pos));
                    if (Commands::is_identifier(label)) {
                        m_core.get_context().getSymbols().add_label(val, label);
                    }
                }
            }
        } catch (...) {}
    }
}