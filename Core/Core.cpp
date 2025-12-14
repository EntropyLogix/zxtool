#include "Core.h"
#include "../Files/BinFiles.h"
#include "../Files/AsmFiles.h"
#include "../Files/Z80File.h"
#include "../Files/SymbolFile.h"
#include "../Files/ControlFile.h"
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
    m_profiler.set_labels(&m_context);
    
    m_file_manager.register_loader(new BinFiles(m_memory));
    m_file_manager.register_loader(new AsmFiles(m_assembler));
    m_file_manager.register_loader(new Z80File(*this));
    m_file_manager.register_loader(new SymbolFile(m_analyzer));
    m_file_manager.register_loader(new ControlFile(m_analyzer));
}

void Core::load_input_files(const std::vector<std::string>& inputs) {
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

void Core::reset() {
    m_cpu.reset();
    m_blocks.clear();
    m_profiler.reset();
    m_context.labels.clear();
    m_context.metadata.clear();
    m_current_path_stack.clear();
}

void Core::print_symbols(const std::string& filter) {
    if (m_context.labels.empty()) {
        std::cout << "No symbols loaded." << std::endl;
        return;
    }

    std::regex filter_regex;
    bool use_regex = false;
    if (!filter.empty()) {
        try {
            std::string regex_str;
            for (char c : filter) {
                if (c == '*') regex_str += ".*";
                else if (c == '?') regex_str += ".";
                else if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') regex_str += c;
                else { regex_str += '\\'; regex_str += c; }
            }
            filter_regex = std::regex(regex_str, std::regex::icase);
            use_regex = true;
        } catch (...) {
            std::cout << "Invalid filter expression." << std::endl;
            return;
        }
    }

    for (const auto& [addr, label] : m_context.labels) {
        if (!use_regex || std::regex_match(label, filter_regex)) {
            std::cout << Strings::format_hex(addr, 4) << " " << label << std::endl;
        }
    }
}

uint16_t Core::parse_address(const std::string& addr_str) {
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

void Core::process_file(const std::string& path, uint16_t address) {
    if (!fs::exists(path)) {
        throw std::runtime_error("File not found: " + path);
    }

    // Load only binary files here
    auto result = m_file_manager.load_binary(path, m_blocks, address);
    if (!result.success) {
        std::string ext = fs::path(path).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        // If FileManager failed, it might be because of unknown extension or load error.
        std::cerr << "Warning: Failed to load binary file or unknown extension '" << ext << "' for file: " << path << std::endl;
    } else {
        if (result.start_address)
            m_cpu.set_PC(*result.start_address);
    }
    
    load_sidecar_files(path);

    // Merge ControlFile map (if any) into the main code map
    if (m_analyzer.m_map.size() == 0x10000) {
        for (size_t i = 0; i < 0x10000; ++i) {
            m_code_map_data[i] |= m_analyzer.m_map[i];
        }
    }

    std::cout << "Running static analysis..." << std::endl;
    m_analyzer.parse_code(address, 0, &get_code_map(), false, true);
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
            if (!m_file_manager.load_aux(sidecar)) {
                // Fallback for .lst if not registered or handled specially
                if (ext == ".lst") {
                     SymbolFile symLoader(m_analyzer);
                     symLoader.load_sym(sidecar);
                }
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

bool Core::read_file(const std::string& identifier, std::vector<uint8_t>& data) {
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

size_t Core::file_size(const std::string& identifier) {
    auto file_path = resolve_path(identifier, m_current_path_stack);
    try {
        return std::filesystem::file_size(file_path);
    } catch (const std::filesystem::filesystem_error&) {
    }
    return 0;
}

bool Core::exists(const std::string& identifier) {
    auto file_path = resolve_path(identifier, m_current_path_stack);
    return std::filesystem::exists(file_path);
}