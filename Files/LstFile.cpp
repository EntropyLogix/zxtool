#include "LstFile.h"
#include "../Utils/Strings.h"
#include "../Core/Memory.h"
#include "../Core/Assembler.h"
#include "../Core/Variables.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>
#include <cctype>
#include <charconv>

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
    const auto& asm_map = assembler.get_map();
    const auto& asm_blocks = assembler.get_blocks();
    for (const auto& pair : assembler.get_symbols()) {
        const auto& info = pair.second;
        Symbol::Type type = info.label ? Symbol::Type::Label : Symbol::Type::Constant;
        context.getSymbols().add(Symbol(info.name, (uint16_t)info.value, type));
    }
    if (update_map) {
        for (const auto& block : asm_blocks) {
            for (size_t i = 0; i < block.size; ++i) {
                uint16_t addr = block.start_address + i;
                if (addr < asm_map.size())
                    memory.getMap()[addr] = static_cast<uint8_t>(asm_map[addr]);
            }
        }
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

bool ListingFormat::assemble_source(const std::string& path, std::ifstream& file, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    std::stringstream out_source;
    std::string line;
    static const std::regex re_line(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{3,8})[:]?\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)(?!\w)\s*(.*))");
    static const std::regex re_symbol(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{3,8})[:]?\s+(.*))");
    std::smatch match;
    bool inside_incbin = false;
    while (std::getline(file, line)) {
        if (std::regex_search(line, match, re_line)) {
            uint16_t addr = 0;
            if (!parse_hex_address(match[1].str(), addr))
                return false;
            std::string src = match[3].str();
            if (!src.empty() && src[0] == '+')
                continue;
            std::string bytes_str = match[2].str();
            if (!handle_incbin(src, bytes_str, out_source, inside_incbin))
                out_source << src << "\n";
        } else if (std::regex_search(line, match, re_symbol)) {
            inside_incbin = false;
            uint16_t addr = 0;
            if (!parse_hex_address(match[1].str(), addr))
                return false;
            std::string src = match[2].str();
            if (!src.empty() && src[0] == '+')
                continue;
            out_source << src << "\n";
        }
    }
    std::string source = out_source.str();
    if (source.empty())
        return false;
    // DEBUG: Save extracted source to file
    {
        std::ofstream debug_out(path + ".extracted.asm");
        if (debug_out) {
            debug_out << source;
            std::cout << "Debug: Extracted ASM saved to " << path << ".extracted.asm" << std::endl;
        }
    }
    std::string virtual_filename = path + ".extracted.asm";
    m_core.add_virtual_file(virtual_filename, source);
    auto& assembler = m_core.get_assembler();
    assembler.set_silent(true);
    bool result = assembler.compile(virtual_filename, load_address);
    assembler.set_silent(false);
    if (!result)
        return false;
    const auto& asm_blocks = assembler.get_blocks();
    for (const auto& block : asm_blocks)
        blocks.push_back({block.start_address, block.size, "Assembled from LST: " + path});
    return true;
}

bool ListingFormat::parse_listing_content(std::ifstream& file, std::vector<FileFormat::Block>& blocks) {
    auto& context = m_core.get_context();
    static const std::regex re_line(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{3,8})[:]?\s+((?:[0-9A-Fa-f]{2}\s?)+)(?!\w)\s*(.*))");
    static const std::regex re_symbol(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{3,8})[:]?\s+(.*))");
    std::string line;
    std::smatch match;
    while (std::getline(file, line)) {
        if (std::regex_search(line, match, re_line)) {
            uint16_t addr = 0;
            if (!parse_hex_address(match[1].str(), addr))
                continue;
            std::string source = match[3].str();
            if (!source.empty() && source[0] == '+') source.erase(0, 1);
            size_t comment_pos = source.find(';');
            if (comment_pos != std::string::npos) {
                std::string comment = source.substr(comment_pos + 1);
                size_t first = comment.find_first_not_of(" \t\r");
                if (first != std::string::npos) {
                    size_t last = comment.find_last_not_of(" \t\r");
                    context.getComments().add(Comment(addr, comment.substr(first, last - first + 1), Comment::Type::Inline));
                }
                source = source.substr(0, comment_pos);
            }
            extract_label(addr, source);
        } else if (std::regex_search(line, match, re_symbol)) {
            uint16_t val = 0;
            if (!parse_hex_address(match[1].str(), val))
                continue;
            std::string source = match[2].str();
            if (!source.empty() && source[0] == '+') source.erase(0, 1);
            std::string upper = Strings::upper(source);
            if (upper.find("EQU") != std::string::npos) {
                std::stringstream ss(source);
                std::string label, op;
                ss >> label >> op;
                if (Strings::upper(op) == "EQU") {
                    std::string operand;
                    ss >> operand;
                    uint64_t parsed_val = 0;
                    bool parsed = false;
                    if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'x' || operand[1] == 'X')) {
                        auto res = std::from_chars(operand.data() + 2, operand.data() + operand.size(), parsed_val, 16);
                        if (res.ec == std::errc()) parsed = true;
                    } else if (operand.size() > 1 && operand[0] == '$') {
                        auto res = std::from_chars(operand.data() + 1, operand.data() + operand.size(), parsed_val, 16);
                        if (res.ec == std::errc()) parsed = true;
                    } else if (!operand.empty() && std::isdigit(operand[0])) {
                        auto res = std::from_chars(operand.data(), operand.data() + operand.size(), parsed_val, 10);
                        if (res.ec == std::errc()) parsed = true;
                    }
                    if (parsed && parsed_val > 0xFFFF) {
                        std::vector<uint8_t> bytes;
                        uint64_t temp = parsed_val;
                        for(int i=0; i<8; ++i) {
                            bytes.push_back(static_cast<uint8_t>(temp & 0xFF));
                            temp >>= 8;
                        }
                        context.getVariables().add(Variable(label, Expression::Value(bytes), "Imported from LST"));
                    } else {
                        if (parsed) val = static_cast<uint16_t>(parsed_val);
                        context.getSymbols().add(Symbol(label, val, Symbol::Type::Constant));
                    }
                }
            } else {
                std::stringstream ss(upper);
                std::string label, op;
                ss >> label >> op;
                if (op != "MACRO")
                    extract_label(val, source);
            }
        }
    }
    return true;
}

static bool assemble_hex_fallback(Core& core, const std::string& path, std::ifstream& file, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    file.clear();
    file.seekg(0);
    std::stringstream out_source;
    std::string line;
    static const std::regex re_line(R"(^\s*(?:(?:\d+[\+]?)\s+)?([0-9A-Fa-f]{3,8})[:]?\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)(?!\w)\s*(.*))");
    std::smatch match;
    uint32_t current_pc = 0xFFFFFFFF;
    while (std::getline(file, line)) {
        if (std::regex_search(line, match, re_line)) {
            std::string addr_str = match[1].str();
            uint32_t val = 0;
            auto res = std::from_chars(addr_str.data(), addr_str.data() + addr_str.size(), val, 16);
            if (res.ec != std::errc() || val > 0xFFFF)
                continue;
            uint16_t addr = static_cast<uint16_t>(val);
            if (current_pc == 0xFFFFFFFF || addr != current_pc) {
                out_source << "ORG $" << Strings::hex(addr) << "\n";
                current_pc = addr;
            }
            std::string bytes_str = match[2].str();
            std::stringstream ss(bytes_str);
            std::string b;
            std::string db_line = "\tDB ";
            bool first = true;
            int count = 0;
            while (ss >> b) {
                for (size_t i = 0; i < b.length(); i += 2) {
                    if (!first) db_line += ",";
                    db_line += "$" + b.substr(i, 2);
                    first = false;
                    count++;
                }
            }
            out_source << db_line << "\n";
            current_pc += count;
        }
    }
    std::string source = out_source.str();
    if (source.empty())
        return false;
    std::string virtual_filename = path + ".hex.asm";
    core.add_virtual_file(virtual_filename, source);
    auto& assembler = core.get_assembler();
    if (!assembler.compile(virtual_filename, load_address))
        return false;
    const auto& asm_blocks = assembler.get_blocks();
    for (const auto& block : asm_blocks)
        blocks.push_back({block.start_address, block.size, "Assembled from LST (Hex): " + path});
    return true;
}

bool ListingFormat::load_binary(const std::string& path, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    std::ifstream file(path);
    if (!file.is_open())
        return false;
    if (assemble_source(path, file, blocks, load_address)) {
        import_results(true);
        return true;
    }
    
    std::cerr << "Warning: Failed to assemble source from listing. Falling back to hex codes." << std::endl;
    if (assemble_hex_fallback(m_core, path, file, blocks, load_address)) {
        import_results(false);
        return true;
    }
    
    return false;
}

bool ListingFormat::load_metadata(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        return false;
    std::vector<FileFormat::Block> dummy_blocks;
    auto memory_backup = m_core.get_memory().peek(0, 0x10000);
    if (assemble_source(path, file, dummy_blocks, 0) && verify_assembly(memory_backup)) {
        import_results(false);
        return true;
    }
    m_core.get_memory().poke(0, memory_backup);
    file.clear();
    file.seekg(0);
    return parse_listing_content(file, dummy_blocks);
}

std::vector<std::string> ListingFormat::get_extensions() const {
    return {".lst"};
}