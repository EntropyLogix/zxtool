#include "AssemblyFormat.h"

#include "../Core/Core.h"
#include "../Utils/Strings.h"
#include "../Core/Analyzer.h"

AssemblyFormat::AssemblyFormat(Core& core) : m_core(core) {}

void AssemblyFormat::extract_comment(const std::string& source, std::string& comment) {
    bool in_quote = false;
    char quote_char = 0;
    size_t comment_pos = std::string::npos;
    
    for (size_t i = 0; i < source.length(); ++i) {
        char c = source[i];
        if (in_quote) {
            if (c == '\\' && i + 1 < source.length()) {
                i++;
                continue;
            }
            if (c == quote_char)
                in_quote = false;
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
    if (comment_pos != std::string::npos)
        comment = source.substr(comment_pos);
}

bool AssemblyFormat::load_binary(const std::string& filename, std::vector<FileFormat::Block>& blocks, uint16_t address) {
    auto& assembler = m_core.get_assembler();
    if (!assembler.compile(filename, address)) {
        return false;
    }
    auto& context = m_core.get_context();
    auto& mem_map = m_core.get_memory().getMap();
    const auto& asm_map = assembler.get_map();
    const auto& asm_blocks = assembler.get_blocks();
    if (asm_blocks.empty())
        return false;
    for (const auto& pair : assembler.get_symbols()) {
        const auto& info = pair.second;
        Symbol::Type type = info.label ? Symbol::Type::Label : Symbol::Type::Constant;
        context.getSymbols().add(Symbol(info.name, (uint16_t)info.value, type));
    }
    for (const auto& block : asm_blocks) {
        blocks.push_back({block.start_address, block.size, "Assembled from " + filename});
        for (size_t i = 0; i < block.size; ++i) {
            uint16_t addr = block.start_address + i;
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
            extract_comment(clean_content, comment_text);
            if (!comment_text.empty()) {
                if (comment_text[0] == ';') {
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
            bool is_comment = false;
            if (text_to_use[0] == ';')
                is_comment = true;
            else if (text_to_use.size() > 1 && text_to_use[0] == '/' && text_to_use[1] == '/')
                is_comment = true;
            else if (text_to_use.size() > 1 && text_to_use[0] == '/' && text_to_use[1] == '*')
                is_comment = true;
            if (is_comment) {
                const Comment* existing = context.getComments().find(line.address, Comment::Type::Block);
                std::string text = existing ? existing->getText() + "\n" + text_to_use : text_to_use;
                context.getComments().add(Comment(line.address, text, Comment::Type::Block));
            }
        }
    }
    return true;
}

bool AssemblyFormat::load_metadata(const std::string& filename) {
    auto& assembler = m_core.get_assembler();
    auto memory_backup = m_core.get_memory().peek(0, 0x10000);
    
    if (!assembler.compile(filename, 0)) {
        m_core.get_memory().poke(0, memory_backup);
        return false;
    }
    m_core.get_memory().poke(0, memory_backup);
    auto& context = m_core.get_context();
    for (const auto& pair : assembler.get_symbols()) {
        const auto& info = pair.second;
        Symbol::Type type = info.label ? Symbol::Type::Label : Symbol::Type::Constant;
        context.getSymbols().add(Symbol(info.name, (uint16_t)info.value, type));
    }
    return true;
}