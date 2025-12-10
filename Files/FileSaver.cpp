#include "FileSaver.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>

FileSaver::FileSaver(Tool& tool) : m_tool(tool) {}

void FileSaver::save(const std::string& outputFile, const std::string& format, const std::vector<MemoryBlock>& blocks) {
    if (outputFile.empty()) {
        return; // No output file specified
    }

    std::string lower_format = format;
    std::transform(lower_format.begin(), lower_format.end(), lower_format.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    if (lower_format == "bin" || lower_format.empty()) {
        save_bin(outputFile, blocks);
    } else {
        std::cerr << "Warning: Unknown output format '" << format << "'. File not saved." << std::endl;
    }
}

void FileSaver::save_bin(const std::string& outputFile, const std::vector<MemoryBlock>& blocks) {
    if (blocks.empty()) {
        std::cerr << "Warning: No memory blocks to save. File '" << outputFile << "' not created." << std::endl;
        return;
    }

    // For a simple .bin file, we save the first contiguous block of memory.
    const auto& first_block = blocks.front();
    std::cout << "Saving memory block to " << outputFile << " (Address: 0x" << std::hex << first_block.start_address << ", Size: " << std::dec << first_block.size << " bytes)" << std::endl;

    std::ofstream file(outputFile, std::ios::binary);
    for (uint16_t i = 0; i < first_block.size; ++i) {
        file.put(m_tool.get_memory().peek(first_block.start_address + i));
    }
}