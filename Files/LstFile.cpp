#include "LstFile.h"
#include "../Utils/Strings.h"
#include "../Core/Memory.h"
#include "../Core/Assembler.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>
#include <cctype>
#include <charconv>
#include <stack>
#include <algorithm>


ListingFormat::ListingFormat(Core& core) : m_core(core) {
}

void ListingFormat::extract_label(uint16_t addr, const std::string& source) {
    std::stringstream ss(source);
    std::string token;
    if (!(ss >> token))
        return;
    std::string label = token;
    if (label.back() == ':')
        label.pop_back();
    else if (m_core.get_assembler().is_reserved(Strings::upper(label)))
        return;
    if (m_core.get_assembler().is_valid_label_name(label))
        m_core.get_context().getSymbols().add_label(addr, label);
}

void ListingFormat::parse_equ(const std::string& label, const std::string& operand) {
    int32_t parsed_val = 0;
    if (Strings::parse_integer(operand, parsed_val)) {
        uint16_t val = static_cast<uint16_t>(parsed_val);
        m_core.get_context().getSymbols().add(Symbol(label, val, Symbol::Type::Constant));
    }
}

bool ListingFormat::parse_hex_address(const std::string& token, uint16_t& addr) {
    uint32_t val = 0;
    auto res = std::from_chars(token.data(), token.data() + token.size(), val, 16);
    if (res.ec != std::errc() || val > 0xFFFF)
        return false;
    addr = static_cast<uint16_t>(val);
    return true;
}

bool ListingFormat::verify_assembly(const std::vector<uint8_t>& memory_backup) {
    auto& assembler = m_core.get_assembler();
    const auto& asm_blocks = assembler.get_blocks();
    auto& memory = m_core.get_memory();
    bool match = true;
    for (const auto& block : asm_blocks) {
        for (size_t i = 0; i < block.size; ++i) {
            uint16_t addr = block.start_address + i;
            uint8_t compiled_byte = memory.peek(addr);
            uint8_t memory_byte = memory_backup[addr];
            if (compiled_byte != memory_byte) {
                match = false;
                break;
            }
        }
        if (!match)
            break;
    }
    return match;
}

void ListingFormat::import_results(bool update_map) {
    auto& assembler = m_core.get_assembler();
    auto& context = m_core.get_context();
    auto& memory = m_core.get_memory();
    for (const auto& pair : assembler.get_symbols()) {
        const auto& info = pair.second;
        Symbol::Type type = info.label ? Symbol::Type::Label : Symbol::Type::Constant;
        context.getSymbols().add(Symbol(info.name, (uint16_t)info.value, type));
    }
}

std::string ListingFormat::format_bytes(const std::string& raw) {
    std::stringstream ss(raw);
    std::string b, res;
    bool first = true;
    while (ss >> b) {
        for (size_t i = 0; i < b.length(); i += 2) {
            if (!first)
                res += ",";
            res += "$" + b.substr(i, 2);
            first = false;
        }
    }
    return res;
}

ListingFormat::LstLine ListingFormat::parse_lst_line(const std::string& line) {
    LstLine info;
    std::stringstream ss(line);
    std::vector<std::string> tokens;
    std::string t;
    while (ss >> t) tokens.push_back(t);

    if (tokens.empty()) return info;

    size_t idx = 0;

    // 1. Try Parse Line Number
    if (std::all_of(tokens[0].begin(), tokens[0].end(), ::isdigit)) {
        try {
            info.line_num = std::stoi(tokens[0]);
            info.has_line_num = true;
            idx++;
        } catch (...) {}
    }

    // 2. Try Parse Address
    if (idx < tokens.size()) {
        std::string t_addr = tokens[idx];
        if (t_addr.back() == ':') t_addr.pop_back();
        
        if (parse_hex_address(t_addr, info.address)) {
            // Heuristic: If no line number, 2-char hex might be data, not address
            bool is_likely_addr = true;
            if (!info.has_line_num && t_addr.length() <= 2 && tokens[idx].back() != ':') {
                is_likely_addr = false;
            }
            
            if (is_likely_addr) {
                info.has_address = true;
                idx++;
            }
        }
    }

    // 3. Parse Hex Bytes vs Source
    size_t source_idx = tokens.size();
    auto& assembler = m_core.get_assembler();
    
    for (size_t i = idx; i < tokens.size(); ++i) {
        std::string upper = Strings::upper(tokens[i]);
        bool is_hex = (upper.length() == 2 && std::isxdigit(upper[0]) && std::isxdigit(upper[1]));
        
        if (!is_hex) {
            source_idx = i;
            break;
        }
        
        if (assembler.is_keyword(upper)) {
            bool found_later = false;
            for (size_t j = i + 1; j < tokens.size(); ++j) {
                if (assembler.is_keyword(Strings::upper(tokens[j]))) {
                    found_later = true;
                    break;
                }
            }
            if (!found_later) {
                source_idx = i;
                break;
            }
        }
    }
    
    for (size_t i = idx; i < source_idx; ++i) {
        info.hex_bytes.push_back(tokens[i]);
    }

    // Reconstruct Source
    if (source_idx < tokens.size()) {
        size_t pos = 0;
        for(size_t i=0; i<source_idx; ++i) {
            pos = line.find(tokens[i], pos);
            if (pos != std::string::npos) pos += tokens[i].length();
        }
        
        if (pos != std::string::npos) {
            pos = line.find(tokens[source_idx], pos);
            if (pos != std::string::npos) {
                info.source = line.substr(pos);
            }
        }
        
        if (info.source.empty()) {
             for (size_t i = source_idx; i < tokens.size(); ++i) {
                 if (i > source_idx) info.source += " ";
                 info.source += tokens[i];
             }
        }
    }

    return info;
}

bool ListingFormat::handle_incbin(const std::string& src, const std::string& bytes_str, std::stringstream& out_source, bool& inside_incbin) {
    static const std::regex re_incbin(R"(\bINCBIN\b)", std::regex_constants::icase);
    std::smatch m_inc;
    bool is_incbin_start = false;
    if (std::regex_search(src, m_inc, re_incbin)) {
        size_t incbin_pos = m_inc.position();
        size_t comment_pos = src.find(';');
        if (comment_pos == std::string::npos || incbin_pos < comment_pos)
            is_incbin_start = true;
    }
    if (is_incbin_start) {
        inside_incbin = true;
        size_t idx = m_inc.position();
        std::string label = src.substr(0, idx);
        out_source << label << " DB " << format_bytes(bytes_str) << "\n";
        return true;
    } else if (inside_incbin && src.find_first_not_of(" \t\r") == std::string::npos) {
        out_source << "\tDB " << format_bytes(bytes_str) << "\n";
        return true;
    }
    inside_incbin = false;
    return false;
}

bool ListingFormat::is_include_directive(const std::string& source) {
    std::stringstream ss(source);
    std::string token;
    if (ss >> token) {
        if (Strings::upper(token) == "INCLUDE") return true;
        if (token.back() == ':') token.pop_back();
        std::string token2;
        if (ss >> token2 && Strings::upper(token2) == "INCLUDE") return true;
    }
    return false;
}

bool ListingFormat::handle_include(const std::string& src, std::stringstream& out_source) {
    if (is_include_directive(src)) {
        out_source << "; " << src << "\n";
        return true;
    }
    return false;
}

bool ListingFormat::assemble_source(const std::string& path, std::ifstream& file, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    std::stringstream out_source;
    std::string line;
    bool inside_incbin = false;
    int last_line_num = -1;
    std::stack<int> include_stack;

    while (std::getline(file, line)) {
        LstLine info = parse_lst_line(line);
        
        if (info.has_line_num) {
            if (info.line_num <= last_line_num) {
                bool recovered = false;
                if (info.line_num < last_line_num) {
                    while (!include_stack.empty()) {
                        if (info.line_num > include_stack.top()) {
                            include_stack.pop();
                            recovered = true;
                            break;
                        }
                        include_stack.pop();
                    }
                }
                if (!recovered) continue;
            }
            last_line_num = info.line_num;
        } else {
            // Skip pure hex dump lines (continuation of data without source)
            if (info.source.empty()) continue;
        }

        if (!info.source.empty() && info.source[0] == '+') continue;
        
        if (handle_include(info.source, out_source)) {
            include_stack.push(last_line_num);
            last_line_num = -1;
            continue;
        }
        
        std::string bytes_str;
        for(size_t i = 0; i < info.hex_bytes.size(); ++i) {
            if (i>0) bytes_str += " ";
            bytes_str += info.hex_bytes[i];
        }
        
        if (handle_incbin(info.source, bytes_str, out_source, inside_incbin)) continue;
        
        out_source << info.source << "\n";
    }
    std::string source = out_source.str();
    if (source.empty())
        return false;

    // Debug: Save extracted source to disk
    {
        std::ofstream debug_file(path + ".extracted.asm");
        if (debug_file) debug_file << source;
        std::cout << "Debug: Saved extracted ASM to " << path << ".extracted.asm" << std::endl;
    }

    std::string virtual_filename = path + ".extracted.asm";
    m_core.add_virtual_file(virtual_filename, source);
    auto& assembler = m_core.get_assembler();
    assembler.set_silent(true);
    
    std::vector<uint8_t> asm_map;
    bool result = assembler.compile(virtual_filename, load_address, nullptr, nullptr, &asm_map);
    assembler.set_silent(false);
    
    if (result && !asm_map.empty())
        m_core.get_memory().getMap().import(asm_map);

    if (!result)
        return false;
    const auto& asm_blocks = assembler.get_blocks();
    for (const auto& block : asm_blocks)
        blocks.push_back({block.start_address, block.size, "Assembled from LST: " + path});
    return true;
}

bool ListingFormat::parse_listing_content(std::ifstream& file, std::vector<FileFormat::Block>& blocks) {
    auto& context = m_core.get_context();
    std::string line;
    int last_line_num = -1;
    std::stack<int> include_stack;

    while (std::getline(file, line)) {
        LstLine info = parse_lst_line(line);

        if (info.has_line_num) {
            if (info.line_num <= last_line_num) {
                bool recovered = false;
                if (info.line_num < last_line_num) {
                    while (!include_stack.empty()) {
                        if (info.line_num > include_stack.top()) {
                            include_stack.pop();
                            recovered = true;
                            break;
                        }
                        include_stack.pop();
                    }
                }
                if (!recovered) continue;
            }
            last_line_num = info.line_num;
        } else {
            if (info.source.empty()) continue;
        }

        std::string source = info.source;
        if (!source.empty() && source[0] == '+') source.erase(0, 1);

        size_t comment_pos = source.find(';');
        if (comment_pos != std::string::npos) {
            std::string comment = source.substr(comment_pos + 1);
            size_t first = comment.find_first_not_of(" \t\r");
            if (first != std::string::npos) {
                size_t last = comment.find_last_not_of(" \t\r");
                context.getComments().add(Comment(info.address, comment.substr(first, last - first + 1), Comment::Type::Inline));
            }
            source = source.substr(0, comment_pos);
        }
        
        if (is_include_directive(source)) {
            include_stack.push(last_line_num);
            last_line_num = -1;
        }

        std::string upper = Strings::upper(source);
        if (upper.find("EQU") != std::string::npos) {
            std::stringstream ss2(source);
            std::string label, op;
            ss2 >> label >> op;
            if (Strings::upper(op) == "EQU") {
                std::string operand;
                ss2 >> operand;
                parse_equ(label, operand);
            }
        } else {
            std::stringstream ss2(upper);
            std::string label, op;
            ss2 >> label >> op;
            if (op != "MACRO")
                extract_label(info.address, source);
        }
    }
    return true;
}

bool ListingFormat::assemble_hex(const std::string& path, std::ifstream& file, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    file.clear();
    file.seekg(0);
    std::stringstream out_source;
    std::string line;
    uint32_t current_pc = 0xFFFFFFFF;
    
    while (std::getline(file, line)) {
        LstLine info = parse_lst_line(line);

        if (info.has_address) {
            if (current_pc == 0xFFFFFFFF || info.address != current_pc) {
                out_source << "ORG $" << Strings::hex(info.address) << "\n";
                current_pc = info.address;
            }
        }

        if (!info.hex_bytes.empty()) {
            std::string db_line = "\tDB ";
            for (size_t i = 0; i < info.hex_bytes.size(); ++i) {
                if (i > 0) db_line += ",";
                db_line += "$" + info.hex_bytes[i];
            }
            out_source << db_line << "\n";
            
            if (current_pc != 0xFFFFFFFF) {
                current_pc += info.hex_bytes.size();
            }
        }
    }
    std::string source = out_source.str();
    if (source.empty())
        return false;
    std::string virtual_filename = path + ".hex.asm";
    m_core.add_virtual_file(virtual_filename, source);
    auto& assembler = m_core.get_assembler();
    
    std::vector<uint8_t> asm_map;
    if (assembler.compile(virtual_filename, load_address, nullptr, nullptr, &asm_map)) {
        if (!asm_map.empty())
            m_core.get_memory().getMap().import(asm_map);
    } else
        return false;
    const auto& asm_blocks = assembler.get_blocks();
    for (const auto& block : asm_blocks)
        blocks.push_back({block.start_address, block.size, "Assembled from LST (Hex): " + path});
    return true;
}

bool ListingFormat::load_binary(const std::string& path, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    m_load_mode = LoadMode::None;
    std::ifstream file(path);
    if (!file.is_open())
        return false;
    if (assemble_source(path, file, blocks, load_address)) {
        import_results(true);
        m_load_mode = LoadMode::Compilation;
        m_core.set_file_mode(path, "Compilation");
        return true;
    }
    if (assemble_hex(path, file, blocks, load_address)) {
        import_results(false);
        m_load_mode = LoadMode::Hex;
        m_core.set_file_mode(path, "Hex");
        return true;
    }
    return false;
}

bool ListingFormat::load_metadata(const std::string& path) {
    m_load_mode = LoadMode::None;
    std::ifstream file(path);
    if (!file.is_open())
        return false;
    std::vector<FileFormat::Block> dummy_blocks;
    auto memory_backup = m_core.get_memory().peek(0, 0x10000);
    if (assemble_source(path, file, dummy_blocks, 0) && verify_assembly(memory_backup)) {
        import_results(false);
        m_load_mode = LoadMode::Compilation;
        m_core.set_file_mode(path, "Compilation");
        return true;
    }
    m_core.get_memory().poke(0, memory_backup);
    file.clear();
    file.seekg(0);
    if (parse_listing_content(file, dummy_blocks)) {
        m_load_mode = LoadMode::SymbolsOnly;
        m_core.set_file_mode(path, "SymbolsOnly");
        return true;
    }
    return false;
}

std::vector<std::string> ListingFormat::get_extensions() const {
    return {".lst"};
}