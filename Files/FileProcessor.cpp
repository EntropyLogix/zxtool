#include "FileProcessor.h"
#include "../Core/Tool.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <stdexcept>

FileProcessor::FileProcessor(Tool& tool) : m_tool(tool), m_bin_files(tool.get_bus()), m_asm_files(tool.get_assembler()) {}

std::vector<MemoryBlock> FileProcessor::process(const std::vector<File>& files, bool verbose) {
    std::vector<MemoryBlock> all_blocks;

    for (const auto& file_info : files) {
        try {
            std::string extension = get_file_extension(file_info.path);
            if (extension == "bin") {
                std::cout << "Loading binary file: " << file_info.path << " at address 0x" << std::hex << file_info.address << std::dec << std::endl;
                auto block = m_bin_files.load(file_info.path, file_info.address);
                all_blocks.push_back({block.start_address, block.size, "Loaded from " + file_info.path});
            } else if (extension == "asm") {
                std::cout << "Assembling file: " << file_info.path << " at address 0x" << std::hex << file_info.address << std::dec << std::endl;
                auto asm_blocks = m_asm_files.assemble(file_info.path, file_info.address, verbose);
                for (const auto& block : asm_blocks) {
                    all_blocks.push_back({block.start_address, block.size, "Assembled from " + file_info.path});
                }
            } else {
                std::cerr << "Warning: Unknown file extension for '" << file_info.path << "'. File skipped." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error processing file " << file_info.path << ": " << e.what() << std::endl;
        }
    }
    return all_blocks;
}

std::string FileProcessor::get_file_extension(const std::string& filename) {
    size_t dot_pos = filename.rfind('.');
    if (dot_pos == std::string::npos) return "";
    std::string ext = filename.substr(dot_pos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
    return ext;
}