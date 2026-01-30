#include "AssembleEngine.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <filesystem>
#include "../Utils/Strings.h"
#include "../Core/Assembler.h"

AssembleEngine::AssembleEngine(Core& core, const Options& options)
    : m_core(core), m_options(options) {}

int AssembleEngine::run() {
    if (!m_options.build.outputFile.empty()) {
        save_output_file(m_options.build.outputFile, m_options.build.outputFormat, m_core.get_blocks());
        
        std::filesystem::path outPath(m_options.build.outputFile);
        std::string mapPath = outPath.replace_extension(".map").string();
        std::string lstPath = outPath.replace_extension(".lst").string();
        
        auto& assembler = m_core.get_assembler();
        
        if (m_options.build.generateMap) {
            write_map_file(mapPath, assembler.get_symbols());
            std::cout << "Symbols written to " << mapPath << std::endl;
        }
        
        if (m_options.build.generateListing) {
            write_lst_file(lstPath, assembler.get_listing());
            std::cout << "Listing written to " << lstPath << std::endl;
        }
    }
    return 0;
}

void AssembleEngine::save_output_file(const std::string& outputFile, const std::string& format, const std::vector<Core::Block>& blocks) {
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

void AssembleEngine::save_bin(const std::string& outputFile, const std::vector<Core::Block>& blocks) {
    if (blocks.empty()) {
        std::cerr << "Warning: No memory blocks to save. File '" << outputFile << "' not created." << std::endl;
        return;
    }

    uint16_t min_addr = blocks[0].start;
    uint16_t max_addr = blocks[0].start + blocks[0].size - 1;
    
    for (const auto& block : blocks) {
        if (block.start < min_addr) min_addr = block.start;
        uint16_t end = block.start + block.size - 1;
        if (end > max_addr) max_addr = end;
    }
    
    size_t total_size = max_addr - min_addr + 1;
    std::vector<uint8_t> image(total_size, 0x00);
    
    auto& memory = m_core.get_memory();
    for (const auto& block : blocks) {
        for (uint16_t i = 0; i < block.size; ++i) {
            image[block.start - min_addr + i] = memory.peek(block.start + i);
        }
    }

    std::cout << "Saving binary to " << outputFile << " (Start: " << Strings::hex(min_addr) << ", Size: " << std::dec << total_size << ")" << std::endl;
    
    std::ofstream file(outputFile, std::ios::binary);
    file.write(reinterpret_cast<const char*>(image.data()), image.size());
}

std::string AssembleEngine::format_bytes_str(const std::vector<uint8_t>& bytes, bool hex) {
    std::stringstream ss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (hex)
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
        else
            ss << std::dec << static_cast<int>(bytes[i]);
        if (i < bytes.size() - 1)
            ss << " ";
    }
    return ss.str();
}

void AssembleEngine::write_map_file(const std::string& file_path, const std::map<std::string, ToolAssembler::SymbolInfo>& symbols) {
    std::ofstream file(file_path);
    if (!file)
        throw std::runtime_error("Cannot open map file for writing: " + file_path);
    for (const auto& symbol : symbols) {
        std::stringstream ss;
        if (symbol.second.value > 0xFFFF || symbol.second.value < -0x8000)
             ss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << static_cast<uint64_t>(symbol.second.value);
        else
             ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << static_cast<uint16_t>(symbol.second.value);
        file << ss.str()
             << " " // Add a space separator
             << std::setw(16) << std::left << std::setfill(' ') << symbol.first
             << "; " << (symbol.second.label ? "label" : "equ")
             << std::endl;
    }
}

void AssembleEngine::write_lst_file(const std::string& file_path, const std::vector<ToolAssembler::ListingLine>& listing) {
    std::ofstream file(file_path);
    if (!file)
        throw std::runtime_error("Cannot open listing file for writing: " + file_path);
    file << std::left << std::setw(ListingLayout::LineWidth) << "Line" << std::setw(ListingLayout::AddrWidth) << "Addr" << std::setw(ListingLayout::HexWidth) << "Hex Code" << "Source Code\n";
    file << std::string(80, '-') << '\n';
    for (const auto& line : listing) {
        std::string source_text = (line.source_line.original_text.empty() ? line.source_line.content : line.source_line.original_text);
        file << std::setw(ListingLayout::LineWidth - 2) << std::left << line.source_line.line_number << "  ";
        bool has_content = !line.source_line.content.empty() && !std::all_of(line.source_line.content.begin(), line.source_line.content.end(), [](unsigned char c){ return std::isspace(c); });
        bool has_address = !line.bytes.empty() || has_content;
        size_t bytes_per_line = ListingLayout::BytesPerLine;
        size_t total_bytes = line.bytes.size();
        size_t printed_bytes = 0;
        uint16_t current_addr = line.address;
        if (has_address) {
            std::stringstream addr_ss;
            addr_ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << current_addr;
            file << std::setw(ListingLayout::AddrWidth) << std::left << addr_ss.str();
        } else
            file << std::setw(ListingLayout::AddrWidth) << " ";
        if (total_bytes > 0) {
            size_t chunk_size = std::min(bytes_per_line, total_bytes);
            std::vector<uint8_t> chunk(line.bytes.begin(), line.bytes.begin() + chunk_size);
            file << std::setw(ListingLayout::HexWidth) << std::left << format_bytes_str(chunk, true);
            printed_bytes += chunk_size;
            current_addr += chunk_size;
        } else
            file << std::setw(ListingLayout::HexWidth) << " ";
        file << source_text << '\n';
        while (printed_bytes < total_bytes) {
            file << std::setw(ListingLayout::LineWidth) << " ";
            std::stringstream addr_ss;
            addr_ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << current_addr;
            file << std::setw(ListingLayout::AddrWidth) << std::left << addr_ss.str();
            size_t remaining = total_bytes - printed_bytes;
            size_t chunk_size = std::min(bytes_per_line, remaining);
            std::vector<uint8_t> chunk(line.bytes.begin() + printed_bytes, line.bytes.begin() + printed_bytes + chunk_size);
            file << std::setw(ListingLayout::HexWidth) << std::left << format_bytes_str(chunk, true);
            file << '\n';
            printed_bytes += chunk_size;
            current_addr += chunk_size;
        }
    }
}