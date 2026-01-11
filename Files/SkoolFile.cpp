#include "SkoolFile.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <iomanip>
#include <optional>
#include <algorithm>
#include <set>
#include "../Core/Assembler.h"

static uint16_t parse_addr_from_string(const std::string& s) {
    try {
        size_t dollar = s.find('$');
        if (dollar != std::string::npos) {
            return static_cast<uint16_t>(std::stoul(s.substr(dollar + 1), nullptr, 16));
        }
        return static_cast<uint16_t>(std::stoul(s, nullptr, 10));
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
        uint16_t addr = parse_addr_from_string("$" + addrStr);
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

SkoolFile::SkoolFile(Core& core) : m_core(core) {}

std::vector<std::string> SkoolFile::get_extensions() const {
    return { ".skool", ".ctl" };
}

LoadResult SkoolFile::load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) {
    std::string asm_content;
    try {
        // Parse skool file, populate context, and generate ASM string
        parse_and_process(filename, true, asm_content);

        // Register generated ASM as a virtual file in Core
        std::string virtual_filename = filename + ".gen.asm";
        m_core.add_virtual_file(virtual_filename, asm_content);

        // Use the existing assembler to compile the generated code
        if (!m_core.get_assembler().compile(virtual_filename, address)) {
            return {false, std::nullopt};
        }
        
        const auto& asm_blocks = m_core.get_assembler().get_blocks();

        if (asm_blocks.empty()) {
            return {false, std::nullopt};
        }

        uint16_t start_addr = asm_blocks.front().start_address;
        for (const auto& b : asm_blocks) {
            blocks.push_back({b.start_address, b.size, "Assembled from Skool: " + filename});
        }
        
        return {true, start_addr};

    } catch (const std::exception& e) {
        std::cerr << "Skool load error: " << e.what() << std::endl;
        return {false, std::nullopt};
    }
}

bool SkoolFile::load(const std::string& filename) {
    std::string ext = filename.substr(filename.find_last_of("."));
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == ".ctl") {
        return parse_control_file(filename);
    }

    std::string dummy;
    try {
        // Only parse for metadata (comments, labels)
        parse_and_process(filename, false, dummy);
        return true;
    } catch (...) {
        return false;
    }
}

void SkoolFile::parse_and_process(const std::string& filename, bool generate_asm, std::string& out_asm) {
    std::ifstream file(filename);
    if (!file.is_open()) throw std::runtime_error("Cannot open file: " + filename);

    struct LineInfo {
        uint16_t addr;
        std::string instruction;
        std::string comment;
        std::string mnemonic;
        bool is_org = false;
    };
    std::vector<LineInfo> lines;
    std::vector<std::string> pending_labels;
    std::string pending_refs;
    bool assemble_enabled = true;

    std::string line;
    std::regex r_line("^\\s*([a-zA-Z*]?\\$?[0-9A-Fa-f]+)\\s+(.*)$");
    std::smatch match;

    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        // Handle Directives
        if (line[0] == '@') {
            if (line.find("@start") == 0) {
                // Start of content marker - proceed
            } else if (line.find("@end") == 0) {
                break;
            } else if (line.find("@label=") == 0) {
                std::string label = line.substr(7);
                // Basic trim
                size_t first = label.find_first_not_of(" \t\r");
                size_t last = label.find_last_not_of(" \t\r");
                if (first != std::string::npos)
                    pending_labels.push_back(label.substr(first, (last - first + 1)));
            } else if (line.find("@equ=") == 0) {
                // Format: @equ=NAME=VALUE
                std::string content = line.substr(5);
                size_t eq_pos = content.find('=');
                if (eq_pos != std::string::npos) {
                    std::string name = content.substr(0, eq_pos);
                    std::string val_str = content.substr(eq_pos + 1);
                    uint16_t val = parse_addr_from_string(val_str);
                    m_core.get_context().getSymbols().add(Symbol(name, val, Symbol::Type::Constant));
                }
            } else if (line.find("@org=") == 0) {
                std::string val_str = line.substr(5);
                uint16_t val = parse_addr_from_string(val_str);
                lines.push_back({val, "", "", "", true});
            } else if (line.find("@defb=") == 0) {
                std::string content = line.substr(6);
                size_t col_pos = content.find(':');
                if (col_pos != std::string::npos) {
                    std::string addr_str = content.substr(0, col_pos);
                    std::string data_part = content.substr(col_pos + 1);
                    uint16_t addr = parse_addr_from_string(addr_str);
                    
                    std::string comment;
                    size_t comment_pos = data_part.find(';');
                    if (comment_pos != std::string::npos) {
                        comment = data_part.substr(comment_pos + 1);
                        data_part = data_part.substr(0, comment_pos);
                        size_t first = comment.find_first_not_of(" \t");
                        if (first != std::string::npos) comment = comment.substr(first);
                    }
                    
                    lines.push_back({addr, "DEFB " + data_part, comment, "DEFB", false});
                }
            } else if (line.find("@refs=") == 0) {
                if (!pending_refs.empty()) pending_refs += ", ";
                pending_refs += line.substr(6);
            } else if (line.find("@assemble=") == 0) {
                try {
                    assemble_enabled = std::stoi(line.substr(10)) != 0;
                } catch (...) {
                    assemble_enabled = true;
                }
            }
            continue;
        }

        if (line[0] == ';') continue;

        if (std::regex_search(line, match, r_line)) {
            if (!assemble_enabled) continue;

            std::string addr_str = match[1].str();
            std::string remainder = match[2].str();

            uint16_t addr = parse_addr_from_string(addr_str);

            // Apply pending labels
            for (const auto& lbl : pending_labels) {
                m_core.get_context().getSymbols().add_label(addr, lbl);
            }
            pending_labels.clear();

            if (!pending_refs.empty()) {
                m_core.get_context().getComments().add(Comment(addr, "Refs: " + pending_refs, Comment::Type::Block));
                pending_refs.clear();
            }

            std::string instruction = remainder;
            std::string comment;
            
            size_t comment_pos = std::string::npos;
            bool in_quote = false;
            char quote_char = 0;
            for (size_t i = 0; i < remainder.size(); ++i) {
                char c = remainder[i];
                if (in_quote) {
                    if (c == '\\' && i + 1 < remainder.size()) {
                        i++;
                        continue;
                    }
                    if (c == quote_char) in_quote = false;
                } else {
                    if (c == '"') { in_quote = true; quote_char = c; }
                    else if (c == '\'') {
                        // Treat ' as quote only if not preceded by alphanumeric (shadow register check)
                        if (i == 0 || !isalnum(remainder[i-1])) {
                            in_quote = true;
                            quote_char = c;
                        }
                    }
                    else if (c == ';') { comment_pos = i; break; }
                }
            }

            if (comment_pos != std::string::npos) {
                instruction = remainder.substr(0, comment_pos);
                comment = remainder.substr(comment_pos + 1);
                size_t first = comment.find_first_not_of(" \t");
                if (first != std::string::npos) comment = comment.substr(first);
            }

            // Trim instruction
            size_t last_instr = instruction.find_last_not_of(" \t");
            if (last_instr != std::string::npos) instruction = instruction.substr(0, last_instr + 1);
            else instruction = "";

            std::string mnemonic;
            std::stringstream ss(instruction);
            ss >> mnemonic;

            lines.push_back({addr, instruction, comment, mnemonic, false});
        }
    }

    std::sort(lines.begin(), lines.end(), [](const auto& a, const auto& b) {
        if (a.addr != b.addr) return a.addr < b.addr;
        // If addresses are equal, put ORG first
        return a.is_org > b.is_org;
    });

    std::stringstream asm_ss;
    auto& map = m_core.get_analyzer().m_map;
    if (map.size() < 0x10000) map.resize(0x10000, 0);

    uint16_t last_gen_addr = 0xFFFF;
    LineAssembler assembler;

    for (size_t i = 0; i < lines.size(); ++i) {
        const auto& info = lines[i];

        if (info.is_org) {
            if (generate_asm) {
                asm_ss << "\tORG $" << std::hex << std::uppercase << info.addr << "\n";
                last_gen_addr = info.addr;
            }
            continue;
        }
        
        uint16_t next_addr = (i + 1 < lines.size()) ? lines[i+1].addr : (uint16_t)(info.addr + 1);
        int length = (next_addr >= info.addr) ? (next_addr - info.addr) : 1;

        Analyzer::ExtendedFlags type = Analyzer::TYPE_CODE;
        std::string m = info.mnemonic;
        std::transform(m.begin(), m.end(), m.begin(), ::toupper);
        
        bool is_data = false;
        if (m == "DEFB" || m == "DB" || m == "DEFS" || m == "DS") { type = Analyzer::TYPE_BYTE; is_data = true; }
        else if (m == "DEFW" || m == "DW") { type = Analyzer::TYPE_WORD; is_data = true; }
        else if (m == "DEFM" || m == "DM" || m == "DEFT" || m == "DT") { type = Analyzer::TYPE_TEXT; is_data = true; }
        
        if (is_data) {
            for (int k = 0; k < length && (info.addr + k < 0x10000); ++k) {
                 m_core.get_analyzer().set_map_type(map, info.addr + k, type);
            }
        } else {
            m_core.get_analyzer().set_map_type(map, info.addr, Analyzer::TYPE_CODE);
        }

        if (!info.comment.empty()) {
            m_core.get_context().getComments().add(Comment(info.addr, clean_skool_tags(info.comment, m_core.get_analyzer()), Comment::Type::Inline));
        }

        if (generate_asm) {
            int estimated_size = 1;

            // Try to assemble line to get size
            std::map<std::string, uint16_t> dummy_symbols;
            std::string word;
            std::string temp_instr = info.instruction;
            
            // Replace strings content and operators with spaces to isolate words
            bool in_str = false;
            for(char& c : temp_instr) {
                if (c == '"') in_str = !in_str;
                else if (in_str) c = ' ';
                else if (c == ',' || c == '(' || c == ')' || c == '+' || c == '-') c = ' ';
            }
            
            std::stringstream ss(temp_instr);
            while (ss >> word) {
                std::string clean;
                for(char c : word) if(isalnum(c) || c=='_') clean += c;
                std::string upper_clean = clean;
                std::transform(upper_clean.begin(), upper_clean.end(), upper_clean.begin(), ::toupper);

                if (!clean.empty() && !isdigit(clean[0]) && !assembler.is_reserved(upper_clean)) {
                    dummy_symbols[clean] = info.addr; // Use current addr to satisfy JR range
                }
            }
            
            std::vector<uint8_t> bytes;
            try {
                assembler.assemble(info.instruction, dummy_symbols, info.addr, bytes);
                if (!bytes.empty()) estimated_size = bytes.size();
            } catch (...) {
                // Fallback to 1
            }

            if (info.addr != last_gen_addr) {
                if (last_gen_addr != 0xFFFF && info.addr < last_gen_addr) {
                    std::cerr << "Warning: Address overlap at $" << std::hex << info.addr << " (expected $" << last_gen_addr << ")" << std::endl;
                }
                asm_ss << "\tORG $" << std::hex << std::uppercase << info.addr << "\n";
            }
            asm_ss << "\t" << info.instruction << "\n";
            
            last_gen_addr = info.addr + estimated_size;
        }
    }
    out_asm = asm_ss.str();
}

bool SkoolFile::parse_control_file(const std::string& filename) {
    auto& map = m_core.get_analyzer().m_map;
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
        uint16_t addr = parse_addr_from_string(addrStr);
        
        std::string remainder;
        if (endOfAddr != std::string::npos)
             remainder = line.substr(endOfAddr + 1);

        size_t labelPos = remainder.find("label=");
        if (labelPos != std::string::npos) {
            std::string name = remainder.substr(labelPos + 6);
            size_t space = name.find_first_of(" \r\n\t,");
            if (space != std::string::npos) name = name.substr(0, space);
            m_core.get_context().getSymbols().add_label(addr, name);
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
        uint16_t addr = parse_addr_from_string(addrStr);

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
                    m_core.get_analyzer().set_map_type(map, addr + i, t);
            } else {
                m_core.get_analyzer().set_map_type(map, addr, t);
            }
        };

        switch (type) {
            case 'c': // Code
                m_core.get_analyzer().set_map_type(map, addr, Analyzer::TYPE_CODE);
                if (!remainder.empty()) m_core.get_context().getComments().add(Comment(addr, clean_skool_tags(remainder, m_core.get_analyzer()), Comment::Type::Inline));
                break;
            case 'C': // Comment
                if (!remainder.empty()) {
                    size_t first = remainder.find_first_not_of(" \t\r");
                    if (first != std::string::npos) {
                        size_t last = remainder.find_last_not_of(" \t\r");
                        m_core.get_context().getComments().add(Comment(addr, clean_skool_tags(remainder.substr(first, (last - first + 1)), m_core.get_analyzer()), Comment::Type::Inline));
                    }
                }
                break;
            case 'b': case 'B': // Byte
            case 's': case 'S': // Space
            case 'g':           // Game state
                set_range(Analyzer::TYPE_BYTE);
                if (!remainder.empty() && type == 'b') m_core.get_context().getComments().add(Comment(addr, "; " + clean_skool_tags(remainder, m_core.get_analyzer()), Comment::Type::Block));
                break;
            case 'w': case 'W': // Word
                set_range(Analyzer::TYPE_WORD);
                break;
            case 't': case 'T': case 'Z': // Text
                set_range(Analyzer::TYPE_TEXT);
                break;
            case 'u': case 'U': // Unused
                set_range(Analyzer::TYPE_IGNORE);
                if (!remainder.empty()) m_core.get_context().getComments().add(Comment(addr, "; Unused: " + clean_skool_tags(remainder, m_core.get_analyzer()), Comment::Type::Block));
                break;
            case 'M': // Memory map
                // Format: M base,length,description
                if (!remainder.empty()) m_core.get_context().getComments().add(Comment(addr, "; Block: " + clean_skool_tags(remainder, m_core.get_analyzer()), Comment::Type::Block));
                break;
            case 'i': // Ignore
                set_range(Analyzer::TYPE_IGNORE);
                break;
            case 'D': case 'N': // Description
                m_core.get_context().getComments().add(Comment(addr, "; " + clean_skool_tags(remainder, m_core.get_analyzer()), Comment::Type::Block));
                break;
            case 'R': // Register info
                m_core.get_context().getComments().add(Comment(addr, "; [Regs: " + clean_skool_tags(remainder, m_core.get_analyzer()) + "]", Comment::Type::Block));
                break;
        }
    }
    return true;
}