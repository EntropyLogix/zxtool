#include "AssembleEngine.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>

AssembleEngine::AssembleEngine(VirtualMachine& vm, const Options& options)
    : m_vm(vm), m_options(options) {}

int AssembleEngine::run() {
    if (!m_options.outputFile.empty()) {
        save_output_file(m_options.outputFile, m_options.outputFormat, m_vm.get_blocks());
    }
    return 0;
}

void AssembleEngine::save_output_file(const std::string& outputFile, const std::string& format, const std::vector<VirtualMachine::Block>& blocks) {
    if (outputFile.empty()) {
        return;
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

void AssembleEngine::save_bin(const std::string& outputFile, const std::vector<VirtualMachine::Block>& blocks) {
    if (blocks.empty()) {
        std::cerr << "Warning: No memory blocks to save. File '" << outputFile << "' not created." << std::endl;
        return;
    }

    const auto& first_block = blocks.front();
    std::cout << "Saving memory block to " << outputFile << " (Address: 0x" << std::hex << first_block.start_address << ", Size: " << std::dec << first_block.size << " bytes)" << std::endl;

    std::ofstream file(outputFile, std::ios::binary);
    for (uint16_t i = 0; i < first_block.size; ++i) {
        file.put(m_vm.get_memory().peek(first_block.start_address + i));
    }
}