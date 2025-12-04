#include "RunEngine.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

#include "Z80.h"

std::string get_file_extension(const std::string& filename) {
    size_t dot_pos = filename.rfind('.');
    if (dot_pos == std::string::npos)
        return "";
    std::string ext = filename.substr(dot_pos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
    return ext;
}

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

template <typename T> std::string format_hex(T value, int width) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(width) << value;
    return ss.str();
}

uint16_t resolve_address(const std::string& addr_str, const Z80<Z80DefaultBus>& cpu, Z80DefaultLabels* labels) {
    if (addr_str.empty()) throw std::runtime_error("Address argument is empty.");

    if (labels) {
        try {
            return labels->get_addr(addr_str);
        } catch (const std::exception&) {
        }
    }

    size_t plus_pos = addr_str.find('+');
    size_t minus_pos = addr_str.find('-');
    size_t operator_pos = (plus_pos != std::string::npos) ? plus_pos : minus_pos;
    if (operator_pos != std::string::npos) {
        std::string base_str = addr_str.substr(0, operator_pos);
        std::string offset_str = addr_str.substr(operator_pos + 1);
        char op = addr_str[operator_pos];
        base_str.erase(0, base_str.find_first_not_of(" \t"));
        base_str.erase(base_str.find_last_not_of(" \t") + 1);
        uint16_t base_addr = resolve_address(base_str, cpu, labels);
        int offset = std::stoi(offset_str, nullptr, 0);
        return (op == '+') ? (base_addr + offset) : (base_addr - offset);
    }

    try {
        std::string upper_str = addr_str;
        std::transform(upper_str.begin(), upper_str.end(), upper_str.begin(), ::toupper);
        if (upper_str.size() > 2 && upper_str.substr(0, 2) == "0X") {
            return std::stoul(upper_str.substr(2), nullptr, 16);
        } else if (upper_str.back() == 'H') {
            return std::stoul(upper_str.substr(0, upper_str.length() - 1), nullptr, 16);
        }
        bool is_numeric = true;
        for(char c : addr_str) {
            if (!std::isdigit(c)) {
                is_numeric = false;
                break;
            }
        }
        if (is_numeric) return std::stoul(addr_str, nullptr, 10);

    } catch (const std::invalid_argument&) { }

    std::string upper_str = addr_str;
    std::transform(upper_str.begin(), upper_str.end(), upper_str.begin(), ::toupper);
    if (upper_str == "PC") return cpu.get_PC();
    if (upper_str == "SP") return cpu.get_SP();
    if (upper_str == "HL") return cpu.get_HL();
    if (upper_str == "BC") return cpu.get_BC();
    if (upper_str == "DE") return cpu.get_DE();
    if (upper_str == "IX") return cpu.get_IX();
    if (upper_str == "IY") return cpu.get_IY();

    throw std::runtime_error("Invalid address, label, or register name: " + addr_str);
}

RunEngine::RunEngine(Z80DefaultBus& bus, Z80<Z80DefaultBus>& cpu, Z80DefaultLabels& label_handler,
                 Z80Analyzer<Z80DefaultBus, Z80<Z80DefaultBus>, Z80DefaultLabels>& analyzer,
                 const Options& options)
    : m_bus(bus), m_cpu(cpu), m_label_handler(label_handler), m_analyzer(analyzer), m_options(options) {}

int RunEngine::execute() {
    std::cout << "--- Run/Dump Mode ---\n";
    Z80DefaultFiles<Z80DefaultBus, Z80<Z80DefaultBus>> file_loader(&m_bus, &m_cpu);

    for (const auto& map_file : m_options.mapFiles) {
        std::ifstream file(map_file);
        if (!file) throw std::runtime_error("Cannot open map file: " + map_file);
        std::stringstream buffer; buffer << file.rdbuf();
        m_label_handler.load_map(buffer.str());
        std::cout << "Loaded labels from " << map_file << std::endl;
    }
    for (const auto& ctl_file : m_options.ctlFiles) {
        std::ifstream file(ctl_file);
        if (!file) throw std::runtime_error("Cannot open ctl file: " + ctl_file);
        std::stringstream buffer; buffer << file.rdbuf();
        m_label_handler.load_ctl(buffer.str());
        std::cout << "Loaded labels from " << ctl_file << std::endl;
    }

    std::string inputFile = m_options.getInputFile();
    std::string ext = get_file_extension(inputFile);
    std::cout << "Loading file: " << inputFile << " (type: " << (ext.empty() ? "bin" : ext) << ")" << std::endl;
    bool loaded = false;
    if (ext == "hex") {
        std::ifstream file(inputFile);
        if (!file) throw std::runtime_error("Could not read file: " + inputFile);
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        loaded = file_loader.load_hex_file(content);
    } else {
        std::vector<uint8_t> data = read_binary_file(inputFile);
        if (data.empty()) throw std::runtime_error("Could not read file or file is empty: " + inputFile);

        if (ext == "sna") loaded = file_loader.load_sna_file(data);
        else if (ext == "z80") loaded = file_loader.load_z80_file(data);
        else if (ext == "bin" || ext.empty()) {
            uint16_t org_addr = resolve_address(m_options.orgStr, m_cpu, nullptr);
            loaded = file_loader.load_bin_file(data, org_addr);
            m_cpu.set_PC(org_addr);
        } else {
            throw std::runtime_error("Unsupported file extension: " + ext);
        }
    }
    if (!loaded) throw std::runtime_error("Failed to load file content into emulator.");
    std::cout << "File loaded successfully.\n";
    
    uint16_t entry_point = m_cpu.get_PC();

    // --- STAGE 2: UNIFIED EXECUTION AND ANALYSIS ---
    // This block runs after the memory has been prepared by either assembling or loading.

    bool emulation_requested = (m_options.runTicks > 0 || m_options.runSteps > 0);

    if (emulation_requested) {
        std::cout << "\n--- Starting emulation ---\n";
        if (m_options.runTicks > 0) std::cout << "  Running for " << m_options.runTicks << " T-states (--ticks).\n";
        if (m_options.runSteps > 0) std::cout << "  Running for " << m_options.runSteps << " instructions (--steps).\n";

        long long initial_ticks = m_cpu.get_ticks();
        long long target_ticks = (m_options.runTicks > 0) ? (initial_ticks + m_options.runTicks) : -1; // -1 means no T-state limit
        long long steps_executed = 0;

        while (true) {
            // Check for breakpoint hit BEFORE executing the instruction
            // Check if T-state limit is reached (if set)
            if (m_options.runTicks > 0 && m_cpu.get_ticks() >= target_ticks) {
                std::cout << "\n--- T-state limit reached ---\n";
                break;
            }

            // Check if instruction step limit is reached (if set)
            if (m_options.runSteps > 0 && steps_executed >= m_options.runSteps) {
                std::cout << "\n--- Instruction step limit reached ---\n";
                break;
            }
            
            // Execute one instruction
            m_cpu.step();
            steps_executed++;
        }
        std::cout << "Emulation finished. Executed " << (m_cpu.get_ticks() - initial_ticks) << " T-states and " << steps_executed << " instructions.\n";
    }

    // Run one-shot analysis actions specified on the command line.
    // This happens after any initial emulation run.
    /*
    bool one_shot_analysis_requested = (m_options.memDumpSize > 0 || m_options.disasmLines > 0 || m_options.regDumpAction);
    if (one_shot_analysis_requested) {
        run_analysis_actions(m_options.memDumpAddrStr, m_options.memDumpSize, m_options.disasmAddrStr, m_options.disasmLines, "", m_options.regDumpAction, m_options.regDumpFormat, "");
    }
    */

    return 0;
}
