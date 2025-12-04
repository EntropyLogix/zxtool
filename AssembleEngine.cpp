#include "AssembleEngine.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm> // For std::transform

// Include Z80 components
#include "Z80.h"

#include "Files.h"

// --- File Writers (from Z80Asm) ---

template <typename T> std::string format_hex(T value, int width) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << value;
    return ss.str();
}

void write_map_file(const std::string& file_path, const std::map<std::string, Z80Assembler<Z80DefaultBus>::SymbolInfo>& symbols) {
    std::ofstream file(file_path);
    if (!file)
        throw std::runtime_error("Cannot open map file for writing: " + file_path);
    for (const auto& symbol : symbols) {
        file << std::setw(20) << std::left << std::setfill(' ') << symbol.first
             << " EQU $" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
             << symbol.second.value << std::endl;
    }
}

void write_hex_file(const std::string& file_path, const Z80DefaultBus& bus, const std::vector<Z80Assembler<Z80DefaultBus>::BlockInfo>& blocks) {
    std::ofstream file(file_path);
    const size_t bytes_per_line = 16;
    for (const auto& block : blocks) {
        uint16_t current_addr = block.start_address;
        uint16_t remaining_len = block.size;
        while (remaining_len > 0) {
            uint8_t line_len = std::min((size_t)remaining_len, bytes_per_line);
            uint8_t checksum = 0;
            file << ":" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)line_len;
            checksum += line_len;
            file << std::setw(4) << std::setfill('0') << current_addr;
            checksum += (current_addr >> 8) & 0xFF;
            checksum += current_addr & 0xFF;
            file << "00";
            for (uint8_t i = 0; i < line_len; ++i) {
                uint8_t byte = bus.peek(current_addr + i);
                file << std::setw(2) << std::setfill('0') << (int)byte;
                checksum += byte;
            }
            file << std::setw(2) << std::setfill('0') << (int)((-checksum) & 0xFF) << std::endl;
            current_addr += line_len;
            remaining_len -= line_len;
        }
    }
    file << ":00000001FF" << std::endl;
}

void write_bin_file(const std::string& file_path, const Z80DefaultBus& bus, const std::vector<Z80Assembler<Z80DefaultBus>::BlockInfo>& blocks) {
    if (blocks.empty()) return;
    uint16_t min_addr = blocks[0].start_address;
    uint16_t max_addr = blocks[0].start_address + blocks[0].size - 1;
    for (const auto& block : blocks) {
        if (block.start_address < min_addr)
            min_addr = block.start_address;
        uint16_t block_end_addr = block.start_address + block.size - 1;
        if (block_end_addr > max_addr)
            max_addr = block_end_addr;
    }
    size_t total_size = max_addr - min_addr + 1;
    std::vector<uint8_t> image(total_size, 0x00);
    for (const auto& block : blocks) {
        for (uint16_t i = 0; i < block.size; ++i)
            image[block.start_address - min_addr + i] = bus.peek(block.start_address + i);
    }
    std::ofstream file(file_path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(image.data()), image.size());
}

AssembleEngine::AssembleEngine(Z80DefaultBus& bus, Z80<Z80DefaultBus>& cpu, Z80DefaultLabels& label_handler,
                           Z80Analyzer<Z80DefaultBus, Z80<Z80DefaultBus>, Z80DefaultLabels>& analyzer, Z80Assembler<Z80DefaultBus>& assembler,
                           const Options& options)
    : m_bus(bus), m_cpu(cpu), m_label_handler(label_handler), m_analyzer(analyzer), m_assembler(assembler), m_options(options) {}

int AssembleEngine::execute() {
    std::cout << ">>> Assemble Mode: " << m_options.inputFile << std::endl;
    
    if (!m_assembler.compile(m_options.inputFile, 0x0000)) {
         throw std::runtime_error("Assembly failed with errors.");
    }
    
    const auto& symbols = m_assembler.get_symbols();
    const auto& blocks = m_assembler.get_blocks();

    for(const auto& sym : symbols) {
        m_label_handler.add_label(sym.second.value, sym.first);
    }

    if (m_options.verbose) {
        std::cout << "\n[Calculated Symbols]\n";
        for (const auto& symbol : symbols) {
            std::cout << std::setw(20) << std::left << symbol.first << " = " << format_hex(symbol.second.value, 4) << std::endl;
        }

        std::cout << "\n[Generated Code Disassembly]\n";
        for (const auto& block : blocks) {
            uint16_t pc = block.start_address;
            uint16_t end_addr = block.start_address + block.size;
            while (pc < end_addr) {
                auto listing = m_analyzer.disassemble(pc, 1, nullptr);
                if (!listing.empty()) {
                    std::cout << listing[0] << std::endl;
                }
            }
        }
    }

    std::cout << "\n>>> Assembly successful.\n";

    size_t total_bytes = 0;
    for (const auto& block : blocks) {
        total_bytes += block.size;
    }
    std::cout << "Generated " << total_bytes << " bytes in " << blocks.size() << " code block(s).\n";

    if (!m_options.outputFile.empty()) { // Use outputFile for binary/hex output
        // Determine output format based on options.outputFormat or file extension
        // For now, assuming it's binary if not specified otherwise
        write_bin_file(m_options.outputFile, m_bus, blocks); // This needs to be smarter based on format
        std::cout << "Output file written to: " << m_options.outputFile << std::endl;
    }
    if (!m_options.mapFile.empty()) { // Use mapFile for map output
        write_map_file(m_options.mapFile, symbols);
        std::cout << "Symbol map written to: " << m_options.mapFile << std::endl;
    }

    if (!blocks.empty()) {
        m_cpu.set_PC(blocks[0].start_address);
    }
    return 0;
}