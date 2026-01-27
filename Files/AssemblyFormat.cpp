#include "AssemblyFormat.h"
#include "../Core/Core.h"
#include <stdexcept>
#include <iostream>
#include "../Utils/Strings.h"
#include "../Core/Analyzer.h"

AssemblyFormat::AssemblyFormat(Core& core) : m_core(core) {}

bool AssemblyFormat::load_binary(const std::string& filename, std::vector<FileFormat::Block>& blocks, uint16_t address) {
    auto& assembler = m_core.get_assembler();
    if (!assembler.compile(filename, address)) {
        std::cerr << "Assembly failed for file: " << filename << std::endl;
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
        std::string clean_content = Strings::trim(line.source_line.content);
        if (clean_content.empty())
            continue;
        if (!line.bytes.empty())
            context.getComments().add(Comment(line.address, clean_content, Comment::Type::Inline));
        else {
            const Comment* existing = context.getComments().find(line.address, Comment::Type::Block);
            std::string text = existing ? existing->getText() + "\n" + clean_content : clean_content;
            context.getComments().add(Comment(line.address, text, Comment::Type::Block));
        }
    }
    return true;
}