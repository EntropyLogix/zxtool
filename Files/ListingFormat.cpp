#include "ListingFormat.h"

#include "../Utils/Strings.h"
#include "../Core/Memory.h"
#include "../Core/Assembler.h"

#include <fstream>
#include <sstream>
#include <cctype>
#include <charconv>
#include <algorithm>

ListingFormat::ListingFormat(Core& core) : m_core(core) {
}

bool ListingFormat::parse_hex_address(const std::string& token, uint16_t& addr) {
    uint32_t val = 0;
    auto res = std::from_chars(token.data(), token.data() + token.size(), val, 16);
    if (res.ec != std::errc() || val > 0xFFFF)
        return false;
    if (res.ptr != token.data() + token.size())
        return false;
    addr = static_cast<uint16_t>(val);
    return true;
}

bool ListingFormat::load_binary(const std::string& path, std::vector<FileFormat::Block>& blocks, uint16_t load_address) {
    std::ifstream file(path);
    if (!file.is_open())
        return false;

    m_pending_line.clear();
    std::stringstream asm_src;
    bool found_any_lines = false;

    while (true) {
        LstLine line = read_lst_line(file);
        if (!line.valid && line.source.empty() && line.bytes.empty())
            break;

        found_any_lines = true;
        std::string trimmed_source = Strings::trim(line.source);
        
        // Skip macro expansions
        if (!trimmed_source.empty() && trimmed_source[0] == '+')
            continue;

        if (trimmed_source.empty()) {
            // If source is empty but we have bytes, preserve them as DB
            if (!line.bytes.empty()) {
                asm_src << "\tDB ";
                for (size_t i = 0; i < line.bytes.size(); ++i) {
                    if (i > 0) asm_src << ",";
                    asm_src << "0x" << Strings::hex(line.bytes[i]);
                }
                asm_src << "\t";
            }
            if (!line.comment.empty()) asm_src << line.comment;
            asm_src << "\n";
            continue;
        }

        std::stringstream ss(trimmed_source);
        std::string token;
        ss >> token;
        
        bool has_label = (!token.empty() && token.back() == ':');
        std::string directive = has_label ? "" : token;
        
        if (has_label) {
            if (ss >> directive) {
                // directive found after label
            } else {
                directive.clear();
            }
        }
        
        std::string upper_dir = Strings::upper(directive);
        
        if (upper_dir == "INCLUDE" || upper_dir == "INCBIN") {
            // Comment out the directive
            if (has_label) {
                size_t label_pos = line.source.find(token);
                if (label_pos != std::string::npos) {
                    asm_src << line.source.substr(0, label_pos + token.length());
                    size_t dir_pos = line.source.find(directive, label_pos + token.length());
                    if (dir_pos != std::string::npos) {
                        asm_src << line.source.substr(label_pos + token.length(), dir_pos - (label_pos + token.length()));
                        asm_src << "; " << line.source.substr(dir_pos);
                    } else {
                        asm_src << " ; " << directive; 
                    }
                } else {
                    asm_src << token << " ; " << directive;
                }
            } else {
                size_t first_ns = line.source.find_first_not_of(" \t");
                if (first_ns != std::string::npos) {
                    asm_src << line.source.substr(0, first_ns) << "; " << line.source.substr(first_ns);
                } else {
                    asm_src << "; " << line.source;
                }
            }

            if (upper_dir == "INCBIN" && !line.bytes.empty()) {
                asm_src << "\n\tDB ";
                for (size_t i = 0; i < line.bytes.size(); ++i) {
                    if (i > 0) asm_src << ",";
                    asm_src << "0x" << Strings::hex(line.bytes[i]);
                }
            }
        } else {
            asm_src << line.source;
        }

        if (!line.comment.empty()) asm_src << line.comment;
        asm_src << "\n";
    }

    if (!found_any_lines)
        return false;

    std::string source_code = asm_src.str();
    std::string virtual_filename = path + ".reconstructed.asm";
    m_core.add_virtual_file(virtual_filename, source_code);
    
    auto& assembler = m_core.get_assembler();
    if (assembler.compile(virtual_filename, load_address)) {
        const auto& asm_blocks = assembler.get_blocks();
        auto& context = m_core.get_context();
        auto& mem_map = m_core.get_memory().getMap();
        const auto& asm_map = assembler.get_map();

        for (const auto& pair : assembler.get_symbols()) {
            const auto& info = pair.second;
            Symbol::Type type = info.label ? Symbol::Type::Label : Symbol::Type::Constant;
            context.getSymbols().add(Symbol(info.name, (uint16_t)info.value, type));
        }

        for (const auto& b : asm_blocks) {
            blocks.push_back({b.start_address, b.size, "Reconstructed from LST: " + path});
            for (size_t i = 0; i < b.size; ++i) {
                uint16_t addr = b.start_address + i;
                if (addr < asm_map.size())
                    mem_map[addr] = static_cast<uint8_t>(asm_map[addr]);
            }
        }

        for (const auto& line : assembler.get_listing()) {
            std::string clean_content = Strings::trim(line.source_line.original_text);
            if (clean_content.empty())
                continue;
            if (!line.bytes.empty()) {
                std::string comment_text;
                bool in_quote = false;
                char quote_char = 0;
                size_t comment_pos = std::string::npos;
                
                for (size_t i = 0; i < clean_content.length(); ++i) {
                    char c = clean_content[i];
                    if (in_quote) {
                        if (c == quote_char) in_quote = false;
                    } else {
                        if (c == '"' || c == '\'') {
                            in_quote = true;
                            quote_char = c;
                        } else if (c == ';') {
                            comment_pos = i;
                            break;
                        } else if (c == '/' && i + 1 < clean_content.length() && (clean_content[i+1] == '/' || clean_content[i+1] == '*')) {
                            comment_pos = i;
                            break;
                        }
                    }
                }

                if (comment_pos != std::string::npos) {
                    comment_text = clean_content.substr(comment_pos);
                    if (!comment_text.empty() && comment_text[0] == ';') {
                        comment_text = comment_text.substr(1);
                    } else if (comment_text.length() >= 2 && comment_text[0] == '/' && comment_text[1] == '/') {
                        comment_text = comment_text.substr(2);
                    } else if (comment_text.length() >= 2 && comment_text[0] == '/' && comment_text[1] == '*') {
                        comment_text = comment_text.substr(2);
                        size_t end_pos = comment_text.rfind("*/");
                        if (end_pos != std::string::npos) {
                            comment_text = comment_text.substr(0, end_pos);
                        }
                    }
                    comment_text = Strings::trim(comment_text);
                    context.getComments().add(Comment(line.address, comment_text, Comment::Type::Inline));
                }
            } else {
                std::string text_to_use = clean_content;

                if (!text_to_use.empty()) {
                    bool is_comment = false;
                    if (text_to_use[0] == ';') is_comment = true;
                    else if (text_to_use.size() > 1 && text_to_use[0] == '/' && text_to_use[1] == '/') is_comment = true;
                    else if (text_to_use.size() > 1 && text_to_use[0] == '/' && text_to_use[1] == '*') is_comment = true;

                    if (is_comment) {
                        const Comment* existing = context.getComments().find(line.address, Comment::Type::Block);
                        std::string text = existing ? existing->getText() + "\n" + text_to_use : text_to_use;
                        context.getComments().add(Comment(line.address, text, Comment::Type::Block));
                    }
                }
            }
        }
        return true;
    }

    return false;
}

bool ListingFormat::load_metadata(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        return false;

    m_pending_line.clear();
    auto& context = m_core.get_context();

    while (true) {
        LstLine line = read_lst_line(file);
        if (!line.valid && line.source.empty() && line.bytes.empty())
            break;

        if (!line.comment.empty()) {
            std::string clean_comment = line.comment;
            if (clean_comment.length() > 0 && clean_comment[0] == ';') {
                clean_comment = clean_comment.substr(1);
            } else if (clean_comment.length() >= 2 && clean_comment[0] == '/' && clean_comment[1] == '/') {
                clean_comment = clean_comment.substr(2);
            } else if (clean_comment.length() >= 2 && clean_comment[0] == '/' && clean_comment[1] == '*') {
                clean_comment = clean_comment.substr(2);
                size_t end_pos = clean_comment.rfind("*/");
                if (end_pos != std::string::npos) {
                    clean_comment = clean_comment.substr(0, end_pos);
                }
            }
            context.getComments().add(Comment(line.address, Strings::trim(clean_comment), Comment::Type::Inline));
        }
    }
    return true;
}

std::vector<std::string> ListingFormat::get_extensions() const {
    return {".lst"};
}

void ListingFormat::extract_comment(std::string& source, std::string& comment) {
    bool in_quote = false;
    char quote_char = 0;
    size_t comment_pos = std::string::npos;
    
    for (size_t i = 0; i < source.length(); ++i) {
        char c = source[i];
        if (in_quote) {
            if (c == '\\' && i + 1 < source.length()) {
                i++; // Skip next char (escaped)
                continue;
            }
            if (c == quote_char) in_quote = false;
        } else {
            if (c == '"' || c == '\'') {
                in_quote = true;
                quote_char = c;
            } else if (c == ';') {
                comment_pos = i;
                break;
            } else if (c == '/' && i + 1 < source.length() && (source[i+1] == '/' || source[i+1] == '*')) {
                comment_pos = i;
                break;
            }
        }
    }

    if (comment_pos != std::string::npos) {
        comment = source.substr(comment_pos);
        source = source.substr(0, comment_pos);
        size_t last_c = comment.find_last_not_of("\r\n");
        if (last_c != std::string::npos) comment = comment.substr(0, last_c + 1);
    }
    
    size_t last = source.find_last_not_of(" \t\r");
    if (last != std::string::npos) source = source.substr(0, last + 1);
    else if (source.find_first_not_of(" \t\r") == std::string::npos) source.clear();
}

bool ListingFormat::parse_line_strict(const std::string& line, LstLine& result) {
    if (line.length() <= ListingLayout::LineWidth) return false;

    // Check if we are splitting a token at LineWidth
    if (ListingLayout::LineWidth > 0 && line.length() > ListingLayout::LineWidth) {
        if (!std::isspace(line[ListingLayout::LineWidth]) && !std::isspace(line[ListingLayout::LineWidth - 1]))
            return false;
    }

    // Check if we are splitting a token at LineWidth + AddrWidth
    if (ListingLayout::AddrWidth > 0 && line.length() > ListingLayout::LineWidth + ListingLayout::AddrWidth) {
        if (!std::isspace(line[ListingLayout::LineWidth + ListingLayout::AddrWidth]) && !std::isspace(line[ListingLayout::LineWidth + ListingLayout::AddrWidth - 1]))
            return false;
    }

    std::string s_num = line.substr(0, ListingLayout::LineWidth);
    std::string s_num_trimmed = Strings::trim(s_num);
    if (s_num_trimmed.empty() || !std::isdigit(static_cast<unsigned char>(s_num_trimmed[0]))) {
        return false;
    }

    size_t num_end;
    try {
        result.line_num = std::stoi(s_num_trimmed, &num_end);
        result.valid = true;
    } catch (...) { return false; }

    if (num_end < s_num_trimmed.length())
        return false;

    if (line.length() >= ListingLayout::LineWidth + ListingLayout::AddrWidth) {
        std::string s_addr = line.substr(ListingLayout::LineWidth, ListingLayout::AddrWidth);
        if (!parse_hex_address(Strings::trim(s_addr), result.address))
            return false;
    }

    if (line.length() > ListingLayout::LineWidth + ListingLayout::AddrWidth) {
        size_t len = std::min((size_t)ListingLayout::HexWidth, line.length() - (ListingLayout::LineWidth + ListingLayout::AddrWidth));
        std::string s_hex = line.substr(ListingLayout::LineWidth + ListingLayout::AddrWidth, len);
        std::stringstream ss(s_hex);
        std::string byte_str;
        while (ss >> byte_str) {
            uint32_t val;
            auto res = std::from_chars(byte_str.data(), byte_str.data() + byte_str.size(), val, 16);
            if (res.ec == std::errc() && res.ptr == byte_str.data() + byte_str.size()) {
                result.bytes.push_back(static_cast<uint8_t>(val));
            } else {
                return false;
            }
        }
    }

    if (line.length() > ListingLayout::SourceStart) {
        std::string full_source = line.substr(ListingLayout::SourceStart);
        result.source = full_source;
        extract_comment(result.source, result.comment);
    }
    return true;
}

bool ListingFormat::parse_line_fallback(const std::string& line, LstLine& result) {
    std::stringstream ss(line);
    std::vector<std::string> tokens;
    std::string t;
    while (ss >> t) tokens.push_back(t);

    if (tokens.empty()) return false;

    size_t idx = 0;
    // 1. Try Line Number
    if (std::all_of(tokens[0].begin(), tokens[0].end(), ::isdigit)) {
        try {
            result.line_num = std::stoi(tokens[0]);
            idx++;
        } catch (...) {}
    }

    // 2. Try Address
    if (idx < tokens.size()) {
        std::string s_addr = tokens[idx];
        if (s_addr.back() == ':') s_addr.pop_back();
        if (parse_hex_address(s_addr, result.address)) {
            result.valid = true;
            idx++;
        } else if (result.line_num > 0) {
            result.valid = true;
        }
    }

    if (result.valid) {
        // 3. Try Bytes (Heuristic: 2-digit hex)
        while (idx < tokens.size()) {
            std::string s_byte = tokens[idx];
            if (s_byte.length() == 2 && std::isxdigit(s_byte[0]) && std::isxdigit(s_byte[1])) {
                std::string upper_s = Strings::upper(s_byte);
                if (upper_s == "DB" || upper_s == "DW" || upper_s == "DS" || upper_s == "DM") {
                    break;
                }

                uint32_t val;
                auto res = std::from_chars(s_byte.data(), s_byte.data() + s_byte.size(), val, 16);
                if (res.ec == std::errc()) {
                    result.bytes.push_back(static_cast<uint8_t>(val));
                    idx++;
                    continue;
                }
            }
            break;
        }

        // 4. Source
        if (idx < tokens.size()) {
            size_t pos = line.find(tokens[idx]);
            if (pos != std::string::npos) {
                result.source = line.substr(pos);
                extract_comment(result.source, result.comment);
            }
        }
        return true;
    }
    return false;
}

ListingFormat::LstLine ListingFormat::read_lst_line(std::ifstream& file) {
    LstLine result;
    std::string line;

    while (true) {
        if (!m_pending_line.empty()) {
            line = m_pending_line;
            m_pending_line.clear();
        } else {
            if (!std::getline(file, line)) return result;
        }

        if (parse_line_strict(line, result)) break;
        if (parse_line_fallback(line, result)) break;
    }

    while (std::getline(file, line)) {
        std::string s_num = (line.length() >= ListingLayout::LineWidth) ? line.substr(0, ListingLayout::LineWidth) : line;
        if (!Strings::trim(s_num).empty()) {
            m_pending_line = line;
            break;
        }

        // Try strict continuation
        bool strict_cont = false;
        if (line.length() > ListingLayout::LineWidth + ListingLayout::AddrWidth && 
            line.substr(0, ListingLayout::LineWidth + ListingLayout::AddrWidth).find_first_not_of(" \t") == std::string::npos) {
            size_t len = std::min((size_t)ListingLayout::HexWidth, line.length() - (ListingLayout::LineWidth + ListingLayout::AddrWidth));
            std::string s_hex = line.substr(ListingLayout::LineWidth + ListingLayout::AddrWidth, len);
            std::stringstream ss(s_hex);
            std::string byte_str;
            while (ss >> byte_str) {
                uint32_t val;
                if (std::from_chars(byte_str.data(), byte_str.data() + byte_str.size(), val, 16).ec == std::errc()) {
                    result.bytes.push_back(static_cast<uint8_t>(val));
                    strict_cont = true;
                }
            }
        }

        if (!strict_cont) {
            std::stringstream ss(line);
            std::string byte_str;
            while (ss >> byte_str) {
                uint32_t val;
                if (std::from_chars(byte_str.data(), byte_str.data() + byte_str.size(), val, 16).ec == std::errc()) {
                    result.bytes.push_back(static_cast<uint8_t>(val));
                }
            }
        }
    }

    return result;
}