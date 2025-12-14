#include "VirtualMachine.h"
#include "../Files/BinFiles.h"
#include "../Files/AsmFiles.h"
#include "../Files/SymbolFile.h"
#include "../Files/ControlFile.h"
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace fs = std::filesystem;

VirtualMachine::VirtualMachine() 
    : m_memory()
    , m_code_map_data(0x10000, 0)
    , m_profiler(m_code_map_data, &m_memory)
    , m_cpu(&m_profiler, nullptr, &m_profiler)
    , m_assembler(&m_memory, this)
    , m_analyzer(&m_memory)
{
    m_profiler.connect(&m_cpu);
}

void VirtualMachine::load_input_files(const std::vector<std::string>& inputs) {
    for (const auto& input : inputs) {
        std::string path = input;
        uint16_t address = 0;
        
        size_t colon = input.find(':');
        if (colon != std::string::npos) {
            path = input.substr(0, colon);
            address = parse_address(input.substr(colon + 1));
        }
        
        process_file(path, address);
    }
}

void VirtualMachine::reset() {
    m_cpu.reset();
    m_blocks.clear();
    m_profiler.reset();
    m_analyzer.context.labels.clear();
    m_analyzer.context.metadata.clear();
    m_current_path_stack.clear();
}

uint16_t VirtualMachine::parse_address(const std::string& addr_str) {
    try {
        std::string s = addr_str;
        if (s.empty()) return 0;

        // Decimal prefix '#' (e.g. #100 -> 100)
        if (s[0] == '#') {
            return (uint16_t)std::stoul(s.substr(1), nullptr, 10);
        }

        // Remove 0x prefix if present
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            return (uint16_t)std::stoul(s.substr(2), nullptr, 16);
        }
        // Handle $ prefix
        if (s[0] == '$') {
            return (uint16_t)std::stoul(s.substr(1), nullptr, 16);
        }
        // Handle H suffix
        if ((s.back() == 'h' || s.back() == 'H')) {
             return (uint16_t)std::stoul(s.substr(0, s.size()-1), nullptr, 16);
        }
        
        // Default to HEX (standard for addresses)
        return (uint16_t)std::stoul(s, nullptr, 16);
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid address format '" + addr_str + "': " + e.what());
    }
}

void VirtualMachine::process_file(const std::string& path, uint16_t address) {
    if (!fs::exists(path)) {
        throw std::runtime_error("File not found: " + path);
    }

    std::string ext = fs::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == ".bin") {
        BinFiles binLoader(m_memory);
        auto block = binLoader.load(path, address);
        m_blocks.push_back({block.start_address, block.size, "Loaded from " + path});
    } else if (ext == ".asm") {
        AsmFiles asmLoader(m_assembler);
        auto blocks = asmLoader.assemble(path, address, false);
        for (const auto& b : blocks) {
            m_blocks.push_back({b.start_address, b.size, "Assembled from " + path});
        }
    } else {
        std::cerr << "Warning: Unknown file extension '" << ext << "' for file: " << path << std::endl;
    }
    
    load_sidecar_files(path);

    std::cout << "Running static analysis..." << std::endl;
    m_analyzer.parse_code(address, 0, &get_code_map(), false, true);
}

void VirtualMachine::load_sidecar_files(const std::string& path) {
    fs::path p(path);
    std::string base = p.replace_extension("").string();
    
    // Check .map
    if (fs::exists(base + ".map")) {
        std::cout << "Loading symbols from " << base << ".map" << std::endl;
        SymbolFile symLoader(m_analyzer);
        symLoader.load_map(base + ".map");
    }
    
    // Check .sym
    if (fs::exists(base + ".sym")) {
        std::cout << "Loading symbols from " << base << ".sym" << std::endl;
        SymbolFile symLoader(m_analyzer);
        symLoader.load_sym(base + ".sym");
    }
    
    // Check .ctl
    if (fs::exists(base + ".ctl")) {
        std::cout << "Loading control file " << base << ".ctl" << std::endl;
        ControlFile ctlLoader(m_analyzer);
        ctlLoader.load(base + ".ctl");
    }
    
    // Check .lst
    if (fs::exists(base + ".lst")) {
        std::cout << "Loading info from " << base << ".lst" << std::endl;
        // LST files often contain symbols in a format compatible with load_sym_file (or similar enough)
        SymbolFile symLoader(m_analyzer);
        symLoader.load_sym(base + ".lst");
    }
}

static std::filesystem::path resolve_path(const std::string& identifier, const std::vector<std::filesystem::path>& path_stack) {
    std::filesystem::path p(identifier);
    if (path_stack.empty() || p.is_absolute()) {
        return p;
    }
    return path_stack.back().parent_path() / p;
}

bool VirtualMachine::read_file(const std::string& identifier, std::vector<uint8_t>& data) {
    auto file_path = resolve_path(identifier, m_current_path_stack);

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        return false;
    }

    m_current_path_stack.push_back(file_path);

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
    }
    
    m_current_path_stack.pop_back();
    return true;
}

size_t VirtualMachine::file_size(const std::string& identifier) {
    auto file_path = resolve_path(identifier, m_current_path_stack);
    try {
        return std::filesystem::file_size(file_path);
    } catch (const std::filesystem::filesystem_error&) {
    }
    return 0;
}

bool VirtualMachine::exists(const std::string& identifier) {
    auto file_path = resolve_path(identifier, m_current_path_stack);
    return std::filesystem::exists(file_path);
}
