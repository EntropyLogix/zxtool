#include "AsmFiles.h"
#include <stdexcept>
#include <iostream>
#include "../Utils/Strings.h"

AsmFiles::AsmFiles(ToolAssembler& assembler) : m_assembler(assembler) {}

std::vector<typename ToolAssembler::BlockInfo> AsmFiles::assemble(const std::string& path, uint16_t address, bool verbose) {
    try {
        if (!m_assembler.compile(path, address)) {
            throw std::runtime_error("Assembly failed for file: " + path);
        }

        if (verbose) {
            std::cout << "Assembly successful." << std::endl;

            const auto& symbols = m_assembler.get_symbols();
            if (!symbols.empty()) {
                std::cout << "\nSymbols:" << std::endl;
                for (const auto& pair : symbols) {
                    std::cout << "  " << pair.first << ": " << Strings::format_hex(pair.second.value, 4) << std::endl;
                }
            }

            const auto& blocks = m_assembler.get_blocks();
            if (!blocks.empty()) {
                std::cout << "\nCode Blocks:" << std::endl;
                for (const auto& block : blocks) {
                    std::cout << "  Start: " << Strings::format_hex(block.start_address, 4)
                              << ", Size: " << block.size << " bytes" << std::endl;
                }
            }

            const auto& listing = m_assembler.get_listing();
            if (!listing.empty()) {
                std::cout << "\nListing:" << std::endl;
                for (const auto& line : listing) {
                    std::cout << Strings::format_hex(line.address, 4) << "  ";
                    std::string bytes_str;
                    for (uint8_t byte : line.bytes) {
                        bytes_str += Strings::format_hex(byte, 2).substr(2) + " ";
                    }
                    std::cout << std::left << std::setw(12) << bytes_str;
                    std::cout << line.source_line.content << std::endl;
                }
            }
            std::cout << std::endl;
        }

        return m_assembler.get_blocks();
    } catch (const std::exception& e) {
        std::cerr << "Assembly error: " << e.what() << std::endl;
        return {};
    }
}

LoadResult AsmFiles::load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) {
    auto asm_blocks = assemble(filename, address, false);
    if (asm_blocks.empty()) return {false, std::nullopt};
    
    uint16_t start_addr = asm_blocks.front().start_address;
    for (const auto& b : asm_blocks) {
        blocks.push_back({b.start_address, b.size, "Assembled from " + filename});
    }
    return {true, start_addr};
}

std::vector<std::string> AsmFiles::get_extensions() const {
    return { ".asm" };
}