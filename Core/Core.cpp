#include "Core.h"
#include "../Files/BinFiles.h"
#include "../Files/AssemblyFormat.h"
#include "../Files/Z80File.h"
#include "../Files/SymbolFile.h"
#include "../Files/LstFile.h"
#include "../Files/SkoolFile.h"
#include "../Utils/Strings.h"
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <regex>

namespace fs = std::filesystem;

Core::Core() 
    : m_memory()
    , m_code_map_data(0x10000, 0)
    , m_profiler(m_code_map_data, &m_memory)
    , m_cpu(&m_profiler, nullptr, &m_profiler)
    , m_assembler(&m_memory, this)
    , m_context()
    , m_analyzer(&m_memory, &m_context)
{
    m_profiler.connect(&m_cpu);
    m_profiler.set_labels(&m_context.getSymbols());
    
    m_file_manager.register_loader(new BinaryFormat(m_memory));
    m_file_manager.register_loader(new AssemblyFormat(*this));
    m_file_manager.register_loader(new Z80Format(*this));
    m_file_manager.register_loader(new SymbolFormat(m_analyzer));
    m_file_manager.register_loader(new SkoolFormat(*this));
    m_file_manager.register_loader(new ListingFormat(*this));
}

void Core::load_input_files(const std::vector<std::pair<std::string, uint16_t>>& inputs) {
    for (const auto& input : inputs) {
        process_file(input.first, input.second);
    }

    // Configure analyzer with valid ranges from loaded blocks
    std::vector<std::pair<uint16_t, uint16_t>> ranges;
    for (const auto& block : m_blocks) {
        ranges.push_back({block.start, block.size});
    }
    m_analyzer.set_valid_ranges(ranges);
    
    if (m_blocks.empty()) {
        std::cout << "No memory blocks loaded. Skipping static analysis." << std::endl;
        return;
    }

    uint16_t pc = m_cpu.get_PC();
    std::cout << "Running static analysis from $" << Strings::hex(pc) << "..." << std::endl;
    /*m_analyzer.parse_code(pc, 0, &get_code_map(), false, true, 16, [&](uint16_t addr) {
        return m_analyzer.is_valid_address(addr);
    });*/
}

void Core::reset() {
    m_cpu.reset();
    m_blocks.clear();
    m_profiler.reset();
    m_context.getSymbols().clear();
    m_context.getComments().clear();
    m_current_path_stack.clear();
    std::fill(m_code_map_data.begin(), m_code_map_data.end(), 0);
    //m_analyzer.m_map.clear();
}

void Core::process_file(const std::string& path, uint16_t address) {
    if (!fs::exists(path)) {
        throw std::runtime_error("File not found: " + path);
    }

    // Load only binary files here
    auto result = m_file_manager.load_binary(path, m_blocks, address);
    uint16_t analysis_start = address;
    if (!result.first) {
        std::string ext = fs::path(path).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        // If FileManager failed, it might be because of unknown extension or load error.
        std::cerr << "Warning: Failed to load binary file (or unknown extension) '" << ext << "' for file: " << path << std::endl;
        return;
    } else {
        if (result.second)
            analysis_start = *result.second;
        
        if (result.second) m_cpu.set_PC(*result.second);
    }
    
    load_sidecar_files(path);

    // Merge ControlFile map (if any) into the main code map
    /*if (m_analyzer.m_map.size() == 0x10000) {
        for (size_t i = 0; i < 0x10000; ++i) {
            m_code_map_data[i] |= m_analyzer.m_map[i];
        }
    }*/

}

void Core::load_sidecar_files(const std::string& path) {
    fs::path p(path);
    std::string base = p.replace_extension("").string();
    std::vector<std::string> extensions = {".map", ".sym", ".ctl", ".lst"};
    
    for (const auto& ext : extensions) {
        std::string sidecar = base + ext;
        if (!fs::exists(sidecar)) {
            sidecar = path + ext;
        }

        if (fs::exists(sidecar)) {
            std::cout << "Loading auxiliary file " << sidecar << std::endl;
            // Try to load as auxiliary file
            if (!m_file_manager.load_metadata(sidecar)) {
            }
        }
    }
}

static std::filesystem::path resolve_path(const std::string& identifier, const std::vector<std::filesystem::path>& path_stack) {
    std::filesystem::path p(identifier);
    if (path_stack.empty() || p.is_absolute()) {
        return p;
    }
    return path_stack.back().parent_path() / p;
}

void Core::add_virtual_file(const std::string& name, const std::string& content) {
    m_virtual_files[name] = content;
}

bool Core::read_file(const std::string& identifier, std::vector<uint8_t>& data) {
    if (m_virtual_files.count(identifier)) {
        const auto& content = m_virtual_files[identifier];
        data.assign(content.begin(), content.end());
        return true;
    }

    auto file_path = resolve_path(identifier, m_current_path_stack);

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        return false;
    }
    m_current_path_stack.push_back(file_path);

    // Check if we need to strip LST formatting
    std::string ext = file_path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == ".lst") {
        std::string line;
        std::string content;
        // Regex to strip LST columns: [LineNum] [Addr] [Bytes]
        // 1. Optional Line Number: ^\s*\d+[\+]?\s+
        // 2. Address: [0-9A-Fa-f]{4}[:]?\s+
        // 3. Bytes: (?:[0-9A-Fa-f]{2}\s+)+
        static const std::regex re_linenum(R"(^\s*\d+[\+]?\s+)");
        static const std::regex re_addr(R"(^\s*[0-9A-Fa-f]{4}[:]?\s+)");
        static const std::regex re_bytes(R"(^\s*(?:[0-9A-Fa-f]{2}\s+)+)");

        while (std::getline(file, line)) {
            std::string clean = std::regex_replace(line, re_linenum, "");
            clean = std::regex_replace(clean, re_addr, "");
            clean = std::regex_replace(clean, re_bytes, "");
            content += clean + "\n";
        }
        data.assign(content.begin(), content.end());
    } else {
        std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
    }
    }
    
    m_current_path_stack.pop_back();
    return true;
}

size_t Core::file_size(const std::string& identifier) {
    if (m_virtual_files.count(identifier)) {
        return m_virtual_files[identifier].size();
    }
    auto file_path = resolve_path(identifier, m_current_path_stack);
    try {
        return std::filesystem::file_size(file_path);
    } catch (const std::filesystem::filesystem_error&) {
    }
    return 0;
}

bool Core::exists(const std::string& identifier) {
    if (m_virtual_files.count(identifier)) {
        return true;
    }
    auto file_path = resolve_path(identifier, m_current_path_stack);
    return std::filesystem::exists(file_path);
}