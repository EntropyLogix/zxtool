// zxtool
// verson: 0.0.1
//
// This file contains a unified command-line utility for assembling, analyzing,
// and running Z80 code.
//
// Copyright (c) 2025 Adam Szulc
// MIT License

#include "Z80Assemble.h"
#include "Z80Analyze.h"
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cctype>
#define REPLXX_IMPLEMENTATION
#include <replxx.hxx>
#include <map>

void parse_color(const std::string& s, ColorScheme::RGB& color) {
    std::stringstream ss(s);
    int r, g, b;
    char comma;
    ss >> r >> comma >> g >> comma >> b;
    if (!ss.fail()) {
        color = {r, g, b};
    }
}

void load_color_scheme(const std::string& filename, ColorScheme& scheme) {
    std::ifstream file(filename);
    if (!file) {
        // Jeśli plik nie istnieje, ustaw wszystkie kolory na czarny.
        scheme.label = {0, 0, 0};
        scheme.mnemonic = {0, 0, 0};
        scheme.address = {0, 0, 0};
        scheme.bytes = {0, 0, 0};
        scheme.ticks = {0, 0, 0};
        scheme.operand_reg = {0, 0, 0};
        scheme.operand_imm = {0, 0, 0};
        scheme.operand_addr = {0, 0, 0};
        scheme.operand_mem = {0, 0, 0};
        scheme.operand_cond = {0, 0, 0};
        return;
    }

    std::string line;
    std::string current_section;
    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (line.empty() || line[0] == ';') continue;

        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
        } else if (current_section == "disassembly") {
            size_t equals_pos = line.find('=');
            if (equals_pos != std::string::npos) {
                std::string key = line.substr(0, equals_pos);
                std::string value = line.substr(equals_pos + 1);
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));

                if (key == "label") parse_color(value, scheme.label);
                else if (key == "mnemonic") parse_color(value, scheme.mnemonic);
                else if (key == "address") parse_color(value, scheme.address);
                else if (key == "bytes") parse_color(value, scheme.bytes);
                else if (key == "ticks") parse_color(value, scheme.ticks);
                else if (key == "operand_reg") parse_color(value, scheme.operand_reg);
                else if (key == "operand_imm") parse_color(value, scheme.operand_imm);
                else if (key == "operand_addr") parse_color(value, scheme.operand_addr);
                else if (key == "operand_mem") parse_color(value, scheme.operand_mem);
                else if (key == "operand_cond") parse_color(value, scheme.operand_cond);
            }
        }
    }
    std::cout << "Color scheme loaded from " << filename << ".\n";
}

// --- Helper Functions ---

void print_usage() {
    std::cerr << "Usage: Z80Tool <command> <input_file> [options]\n"
              << "A unified tool for Z80 assembly and analysis.\n\n"
              << "COMMANDS:\n"
              << "  assemble          Assemble a Z80 source file.\n"
              << "  analyze           Analyze or run a Z80 binary/snapshot file.\n\n"
              << "GENERAL OPTIONS:\n"
              << "ASSEMBLY OPTIONS (for 'assemble' command):\n"
              << "    --out-bin <file>    Save result as a raw binary file.\n"
              << "    --out-hex <file>    Save result as an Intel HEX file.\n"
              << "    --out-map <file>    Save the symbol table to a map file.\n"
              << "\n"
              << "ANALYSIS OPTIONS (for 'analyze' command or after assembly):\n"
              << "  Loading (for 'analyze' command only):\n"
              << "    --load-addr <addr>  Specifies the loading address for .bin files (default: 0x0000).\n"
              << "    --map <file>        Load a .map symbol file (can be used multiple times).\n"
              << "    --ctl <file>        Load a .ctl symbol file (can be used multiple times).\n"
              << "  Execution & Analysis Options:\n"
              << "    --run-ticks <ticks> Run emulation for a number of T-states.\n"
              << "    --run-steps <steps> Run emulation for a number of instructions.\n"
              << "    --breakpoint <addr> Stop emulation when PC reaches this address.\n"
              << "    --disassemble <addr> <lines>  Disassemble code.\n"
              << "    --mem-dump <addr> <bytes>     Dump memory.\n"
              << "    --reg-dump [format]           Dump CPU registers.\n\n"
              << "Address format for <addr> can be a hex value (e.g., 4000, 8000h, 0x1234),\n"
              << "a register (PC, SP, HL), or an expression (e.g., PC+10, HL-20h).\n\n"
              << "INTERACTIVE MODE COMMANDS (when using --interactive):\n"
              << "  d[isassemble] [addr] [lines]   Disassemble code (default: 'd pc 1').\n"
              << "  m[em-dump] <addr> <bytes_hex>  Dump memory.\n"
              << "  r[eg-dump] [format]            Dump CPU registers.\n"
              << "  s[tep] / s[tep-into] [num]     Run for <num> instructions (steps into calls).\n"
              << "  so / step-over                 Execute one instruction (steps over calls).\n"
              << "  su / step-out                  Run until the current function returns.\n"
              << "  c[ontinue]                     Run until a breakpoint is hit.\n"
              << "  t[icks] <num>                  Run for <num> T-states.\n"
              << "  cs / callstack [depth]         Show the call stack (default depth: 16).\n"
              << "  b[reakpoint] <addr>            Set a breakpoint.\n"
              << "  b[reakpoint] clear             Clear the breakpoint.\n"
              << "  set <reg> <value>              Set a register value (e.g., 'set pc 8000h').\n"
              << "  symbol [name]                  Show all symbols or a specific one.\n"
              << "  format <type> <string>         Set default format for 'reg', 'mem', or 'disasm'.\n"
              << "  help                           Show this help message.\n"
              << "  q[uit] / exit                  Exit the interactive session.\n";
}

std::string get_file_extension(const std::string& filename) {
    size_t dot_pos = filename.rfind('.');
    if (dot_pos == std::string::npos) return "";
    std::string ext = filename.substr(dot_pos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
    return ext;
}

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
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

uint16_t resolve_address(const std::string& addr_str, const Z80<>& cpu, Z80DefaultLabels* labels) {
    if (addr_str.empty()) throw std::runtime_error("Address argument is empty.");

    // First, try to resolve as a label
    if (labels) {
        try {
            return labels->get_addr(addr_str);
        } catch (const std::exception&) {
            // Not a label, proceed to other parsing methods
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
        // Try as decimal, but catch to avoid treating labels as numbers
        bool is_numeric = true;
        for(char c : addr_str) {
            if (!std::isdigit(c)) {
                is_numeric = false;
                break;
            }
        }
        if (is_numeric) return std::stoul(addr_str, nullptr, 10);

    } catch (const std::invalid_argument&) { /* Fall through to register names */ }

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

// --- File Writers (from Z80Asm) ---

void write_map_file(const std::string& file_path, const std::map<std::string, Z80Assembler<Z80DefaultBus>::SymbolInfo>& symbols) {
    std::ofstream file(file_path);
    if (!file) throw std::runtime_error("Cannot open map file for writing: " + file_path);
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
        if (block.start_address < min_addr) min_addr = block.start_address;
        uint16_t block_end_addr = block.start_address + block.size - 1;
        if (block_end_addr > max_addr) max_addr = block_end_addr;
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

// --- Source Provider (from Z80Asm) ---

class FileSystemSourceProvider : public IFileProvider {
public:
    bool read_file(const std::string& identifier, std::vector<uint8_t>& data) override {
        std::filesystem::path file_path;
        if (m_current_path_stack.empty())
            file_path = std::filesystem::canonical(identifier);
        else
            file_path = std::filesystem::canonical(m_current_path_stack.back().parent_path() / identifier);
        m_current_path_stack.push_back(file_path);
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        if (!file) {
            m_current_path_stack.pop_back();
            return false;
        }
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        data.resize(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        m_current_path_stack.pop_back();
        return true;
    }
    size_t file_size(const std::string& identifier) override {
        try {
            return std::filesystem::file_size(identifier);
        } catch (const std::filesystem::filesystem_error&) {
            return 0;
        }
    }
    bool exists(const std::string& identifier) override { return std::filesystem::exists(identifier); }

private:
    std::vector<std::filesystem::path> m_current_path_stack;
};

// --- Main Application Logic ---

void run_analysis_actions(
    Z80<>& cpu,
    Z80Analyzer<Z80DefaultBus, Z80<>, Z80DefaultLabels>& analyzer,
    Z80DefaultLabels& label_handler,
    const std::string& mem_dump_addr_str, size_t mem_dump_size,
    const std::string& disasm_addr_str, size_t disasm_lines, const std::string& disasm_format,
    bool reg_dump_action, const std::string& reg_dump_format, const std::string& mem_dump_format
) {
    if (reg_dump_action) {
        std::string format = reg_dump_format.empty() ? "AF=%af BC=%bc DE=%de HL=%hl IX=%ix IY=%iy PC=%pc SP=%sp | %flags" : reg_dump_format;
        std::cout << "\n--- Register Dump ---\n";
        std::cout << analyzer.dump_registers(format) << std::endl;
    }

    if (mem_dump_size > 0) {
        uint16_t mem_dump_addr = resolve_address(mem_dump_addr_str, cpu, &label_handler);
        std::cout << "\n--- Memory Dump from " << format_hex(mem_dump_addr, 4) << " (" << mem_dump_size << " bytes) ---\n";
        uint16_t current_addr = mem_dump_addr;
        std::string format = mem_dump_format.empty() ? "%a: %h  %c" : mem_dump_format;
        auto dump = analyzer.dump_memory(current_addr, (mem_dump_size + 15) / 16, 16, format);
        for (const auto& line : dump) {
            std::cout << line << std::endl;
        }
    }

    if (disasm_lines > 0) {
        uint16_t disasm_addr = resolve_address(disasm_addr_str, cpu, &label_handler); // Pass label_handler
        std::cout << "\n--- Disassembly from " << format_hex(disasm_addr, 4) << " (" << disasm_lines << " lines) ---\n";
        uint16_t pc = disasm_addr;
        // Since disassemble no longer takes a format string, we call it and then iterate through the results.
        // The format is now hardcoded in Z80Analyze.h.
        // The old format string was: disasm_format.empty() ? "%L%s\n%a: %-12b %-20M" : disasm_format
        auto listing = analyzer.disassemble(pc, disasm_lines, nullptr); // No colors in non-interactive mode
        for (const auto& line : listing) {
            std::cout << line << std::endl;
        }
    }
}

// --- Command Line Options Parser ---

class CommandLineOptions {
public:
    enum class ToolMode { Assembly, Analysis, Unknown };

    CommandLineOptions(int argc, char* argv[]) {
        if (argc < 3) {
            throw std::runtime_error("Invalid arguments. Command and input file are required.");
        }
        std::string mode_str = argv[1];
        if (mode_str == "assemble") m_mode = ToolMode::Assembly;
        else if (mode_str == "analyze") m_mode = ToolMode::Analysis;
        else throw std::runtime_error("Unknown command: '" + mode_str + "'. Use 'assemble' or 'analyze'.");

        // Parse remaining arguments to find options and the input file
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg.rfind("--", 0) == 0) { // It's an option
                if (arg == "--out-bin" && i + 1 < argc) m_outputBinFile = argv[++i];
                else if (arg == "--out-hex" && i + 1 < argc) m_outputHexFile = argv[++i];
                else if (arg == "--out-map" && i + 1 < argc) m_outputMapFile = argv[++i];
                else if (arg == "--mem-dump" && i + 2 < argc) {
                    m_memDumpAddrStr = argv[++i];
                    m_memDumpSize = std::stoul(argv[++i], nullptr, 0);
                } else if (arg == "--disassemble" && i + 2 < argc) {
                    m_disasmAddrStr = argv[++i];
                    m_disasmLines = std::stoul(argv[++i], nullptr, 10);
                } else if (arg == "--load-addr" && i + 1 < argc) m_loadAddrStr = argv[++i];
                else if (arg == "--map" && i + 1 < argc) m_mapFiles.push_back(argv[++i]);
                else if (arg == "--ctl" && i + 1 < argc) m_ctlFiles.push_back(argv[++i]);
                else if (arg == "--reg-dump") {
                    m_regDumpAction = true;
                    if (i + 1 < argc && argv[i + 1][0] != '-') m_regDumpFormat = argv[++i];
                } else if (arg == "--run-ticks" && i + 1 < argc) m_runTicks = std::stoll(argv[++i], nullptr, 10);
                else if (arg == "--breakpoint" && i + 1 < argc) {
                    m_breakpointAddrStr = argv[++i];
                    m_breakpointSet = true;
                } else if (arg == "--run-steps" && i + 1 < argc) m_runSteps = std::stoll(argv[++i], nullptr, 10);
                else if (arg == "--interactive") {
                    m_interactive = true;
                }
                else if (arg == "--verbose") {
                    m_verbose = true;
                }
                else {
                    throw std::runtime_error("Unknown or incomplete argument '" + arg + "'.");
                }
            } else { // It's a positional argument, should be the input file
                if (!m_inputFile.empty()) {
                    throw std::runtime_error("Multiple input files specified: '" + m_inputFile + "' and '" + arg + "'.");
                }
                m_inputFile = arg;
            }
        }
        if (m_inputFile.empty()) {
            throw std::runtime_error("No input file specified.");
        }
    }
    
    ToolMode getMode() const { return m_mode; }
    const std::string& getInputFile() const { return m_inputFile; }
    const std::string& getOutputBinFile() const { return m_outputBinFile; }
    const std::string& getOutputHexFile() const { return m_outputHexFile; }
    const std::string& getOutputMapFile() const { return m_outputMapFile; }
    const std::string& getMemDumpAddrStr() const { return m_memDumpAddrStr; }
    size_t getMemDumpSize() const { return m_memDumpSize; }
    const std::string& getDisasmAddrStr() const { return m_disasmAddrStr; }
    size_t getDisasmLines() const { return m_disasmLines; }
    const std::string& getLoadAddrStr() const { return m_loadAddrStr; }
    const std::vector<std::string>& getMapFiles() const { return m_mapFiles; }
    const std::vector<std::string>& getCtlFiles() const { return m_ctlFiles; }
    long long getRunTicks() const { return m_runTicks; }
    long long getRunSteps() const { return m_runSteps; }
    const std::string& getBreakpointAddrStr() const { return m_breakpointAddrStr; }
    bool isBreakpointSet() const { return m_breakpointSet; }
    bool isRegDumpRequested() const { return m_regDumpAction; }
    const std::string& getRegDumpFormat() const { return m_regDumpFormat; }
    bool isInteractive() const { return m_interactive; }
    bool isVerbose() const { return m_verbose; }

private:
    ToolMode m_mode = ToolMode::Unknown;
    std::string m_inputFile, m_outputBinFile, m_outputHexFile, m_outputMapFile;
    std::string m_memDumpAddrStr, m_disasmAddrStr, m_loadAddrStr = "0x0000";
    size_t m_memDumpSize = 0, m_disasmLines = 0;
    long long m_runTicks = 0, m_runSteps = 0;
    std::vector<std::string> m_mapFiles, m_ctlFiles;
    std::string m_breakpointAddrStr;
    bool m_breakpointSet = false, m_regDumpAction = false;
    std::string m_regDumpFormat;
    bool m_verbose = false;
    bool m_interactive = false;
};

bool is_call_instruction(uint16_t addr, Z80DefaultBus* bus) {
    uint8_t opcode = bus->peek(addr);
    // CALL nn, CALL cc, nn
    if (opcode == 0xCD || (opcode & 0xC7) == 0xC4) {
        return true;
    }
    // RST p
    if ((opcode & 0xC7) == 0xC7) {
        return true;
    }
    return false;
}
void run_interactive_mode(Z80<>& cpu, Z80Analyzer<Z80DefaultBus, Z80<>, Z80DefaultLabels>& analyzer, Z80DefaultLabels& label_handler);

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    try {
        CommandLineOptions options(argc, argv);

        // --- Core Objects ---        
        Z80DefaultBus bus;
        Z80<> cpu(&bus);
        Z80DefaultLabels label_handler;
        Z80Analyzer<Z80DefaultBus, Z80<>, Z80DefaultLabels> analyzer(&bus, &cpu, &label_handler);
        uint16_t entry_point = 0;
        if (options.getMode() == CommandLineOptions::ToolMode::Assembly) { // --- MODE 1: ASSEMBLY (.asm file) ---
            std::cout << "--- Assembly Mode ---\n";
            FileSystemSourceProvider source_provider;
            Z80Assembler<Z80DefaultBus> assembler(&bus, &source_provider);

            std::cout << "Assembling source code from: " << options.getInputFile() << std::endl;
            if (!assembler.compile(options.getInputFile(), 0x0000)) {
                 throw std::runtime_error("Assembly failed with errors.");
            }

            std::cout << "\n--- Assembly Successful ---\n";
            const auto& symbols = assembler.get_symbols();
            const auto& blocks = assembler.get_blocks();

            // Populate label handler for analysis
            for(const auto& sym : symbols) {
                label_handler.add_label(sym.second.value, sym.first);
            }

            // Default action: print summary to screen
            if (options.isVerbose())
            {
                std::cout << "\n--- Calculated Symbols ---\n";
                for (const auto& symbol : symbols) {
                    std::cout << std::setw(20) << std::left << symbol.first << " = " << format_hex(symbol.second.value, 4) << std::endl;
                }

                std::cout << "\n--- Disassembly of Generated Code ---\n";
                for (const auto& block : blocks) {
                    uint16_t pc = block.start_address;
                    uint16_t end_addr = pc + block.size;
                    auto listing = analyzer.disassemble(pc, block.size, nullptr);
                    for (const auto& line : listing) {
                        std::cout << line << std::endl;
                    }
                }
            }
            if (!blocks.empty()) {
                entry_point = blocks[0].start_address;
            }
            cpu.set_PC(entry_point);

            // Write output files
            if (!options.getOutputBinFile().empty()) {
                write_bin_file(options.getOutputBinFile(), bus, blocks);
                std::cout << "Binary code written to " << options.getOutputBinFile() << std::endl;
            }
            if (!options.getOutputHexFile().empty()) {
                write_hex_file(options.getOutputHexFile(), bus, blocks);
                std::cout << "Intel HEX code written to " << options.getOutputHexFile() << std::endl;
            }
            if (!options.getOutputMapFile().empty()) {
                write_map_file(options.getOutputMapFile(), symbols);
                std::cout << "Symbols written to " << options.getOutputMapFile() << std::endl;
            }

        }
        // --- MODE 2: ANALYSIS/DUMP (other files) ---
        else {
            std::cout << "--- Analysis/Dump Mode ---\n";
            Z80DefaultFiles<Z80DefaultBus, Z80<>> file_loader(&bus, &cpu);

            // Load symbol files
            for (const auto& map_file : options.getMapFiles()) {
                std::ifstream file(map_file);
                if (!file) throw std::runtime_error("Cannot open map file: " + map_file);
                std::stringstream buffer; buffer << file.rdbuf();
                label_handler.load_map(buffer.str());
                std::cout << "Loaded labels from " << map_file << std::endl;
            }
            for (const auto& ctl_file : options.getCtlFiles()) {
                std::ifstream file(ctl_file);
                if (!file) throw std::runtime_error("Cannot open ctl file: " + ctl_file);
                std::stringstream buffer; buffer << file.rdbuf();
                label_handler.load_ctl(buffer.str());
                std::cout << "Loaded labels from " << ctl_file << std::endl;
            }

            // Load main file
            std::string inputFile = options.getInputFile();
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
                    uint16_t load_addr = resolve_address(options.getLoadAddrStr(), cpu, nullptr);
                    loaded = file_loader.load_bin_file(data, load_addr);
                    cpu.set_PC(load_addr);
                } else {
                    throw std::runtime_error("Unsupported file extension: " + ext);
                }
            }
            if (!loaded) throw std::runtime_error("Failed to load file content into emulator.");
            std::cout << "File loaded successfully.\n";
            entry_point = cpu.get_PC();

        }

        // --- STAGE 2: UNIFIED EXECUTION AND ANALYSIS ---
        // This block runs after the memory has been prepared by either assembling or loading.

        // Now that all labels are loaded (from assembly or files), resolve the breakpoint address.
        uint16_t breakpoint_address = 0;
        if (options.isBreakpointSet()) {
            breakpoint_address = resolve_address(options.getBreakpointAddrStr(), cpu, &label_handler);
        }

        // If no execution is requested, set PC to the entry point before analysis/interactive mode.
        bool execution_requested = (options.getRunTicks() > 0 || options.getRunSteps() > 0);
        if (!execution_requested) {
            cpu.set_PC(entry_point);
        }

        bool emulation_requested = (options.getRunTicks() > 0 || options.getRunSteps() > 0 || options.isBreakpointSet());

        if (emulation_requested) {
            std::cout << "\n--- Starting emulation ---\n";
            if (options.getRunTicks() > 0) std::cout << "  Running for " << options.getRunTicks() << " T-states.\n";
            if (options.getRunSteps() > 0) std::cout << "  Running for " << options.getRunSteps() << " instructions.\n";
            if (options.isBreakpointSet()) std::cout << "  Breakpoint set at " << format_hex(breakpoint_address, 4) << ".\n";

            long long initial_ticks = cpu.get_ticks();
            long long target_ticks = (options.getRunTicks() > 0) ? (initial_ticks + options.getRunTicks()) : -1; // -1 means no T-state limit
            long long steps_executed = 0;

            while (true) {
                // Check for breakpoint hit BEFORE executing the instruction
                if (options.isBreakpointSet() && cpu.get_PC() == breakpoint_address) {
                    std::cout << "\n--- Breakpoint hit at " << format_hex(breakpoint_address, 4) << " (PC: " << format_hex(cpu.get_PC(), 4) << ") ---\n";
                    break;
                }

                // Check if T-state limit is reached (if set)
                if (options.getRunTicks() > 0 && cpu.get_ticks() >= target_ticks) {
                    std::cout << "\n--- T-state limit reached ---\n";
                    break;
                }

                // Check if instruction step limit is reached (if set)
                if (options.getRunSteps() > 0 && steps_executed >= options.getRunSteps()) {
                    std::cout << "\n--- Instruction step limit reached ---\n";
                    break;
                }
                
                // Execute one instruction
                cpu.step();
                steps_executed++;
            }
            std::cout << "Emulation finished. Executed " << (cpu.get_ticks() - initial_ticks) << " T-states and " << steps_executed << " instructions.\n";
        }

        // Run one-shot analysis actions specified on the command line.
        // This happens after any initial emulation run.
        bool one_shot_analysis_requested = (options.getMemDumpSize() > 0 || options.getDisasmLines() > 0 || options.isRegDumpRequested());
        if (one_shot_analysis_requested) {
            run_analysis_actions(cpu, analyzer, label_handler, options.getMemDumpAddrStr(), options.getMemDumpSize(), options.getDisasmAddrStr(), options.getDisasmLines(), "", options.isRegDumpRequested(), options.getRegDumpFormat(), "");
        }

        // If interactive mode is requested, enter it now.
        if (options.isInteractive()) {
            run_interactive_mode(cpu, analyzer, label_handler);
        }
        // If no actions were requested at all (no emulation, no analysis, no interactive), and we are in analysis mode, dump registers by default.
        // and we are in analysis mode, dump registers by default.
        // In assembly mode, the default is already handled (printing listing).
        else if (!emulation_requested && !one_shot_analysis_requested && options.getMode() == CommandLineOptions::ToolMode::Analysis) {
            run_analysis_actions(cpu, analyzer, label_handler, "", 0, "", 0, "", true, "", "");
        }

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

void run_interactive_mode(Z80<>& cpu, Z80Analyzer<Z80DefaultBus, Z80<>, Z80DefaultLabels>& analyzer, Z80DefaultLabels& label_handler) {
    std::cout << "\n--- Entering Interactive Mode ---\n";
    std::cout << "Type 'help' for a list of commands or 'quit' to exit.\n";

    const char* history_file = ".z80tool_history.txt";

    replxx::Replxx rx;
    rx.install_window_change_handler();
    rx.history_load(history_file);

    std::string default_reg_format = "AF=%af BC=%bc DE=%de HL=%hl IX=%ix IY=%iy PC=%pc SP=%sp | %flags";
    std::string default_mem_format = "%a: %h  %c";
    std::string default_disasm_format = "%L%s%a: %-12b %-20M"; // Removed the literal \n from here

    ColorScheme color_scheme;
    load_color_scheme(".colors", color_scheme);

    while (true) {
        const char* cinput = rx.input("(z80) > ");

        if (cinput == nullptr) { // Ctrl+D or error
            break;
        }
        std::string line(cinput);

        if (line.empty()) {
            continue;
        }

        rx.history_add(line);

        std::stringstream ss(line);
        std::string command;
        ss >> command;

        if (command == "q" || command == "quit" || command == "exit") {
            break;
        } else if (command == "help") {
            print_usage();
        } else if (command == "d" || command == "disassemble") {
            std::string addr_str;
            size_t lines = 1; // Domyślnie 1 linia
            ss >> addr_str >> lines;
            if (addr_str.empty()) {
                addr_str = "pc"; // Domyślnie PC
                lines = 1; // Default to 1 line if not specified
            }
            if (lines == 0) {
                std::cerr << "Usage: d[isassemble] [addr] [lines]\n";
                continue;
            }
            // Call disassemble directly as it doesn't need the full run_analysis_actions function
            uint16_t disasm_addr = resolve_address(addr_str, cpu, &label_handler);
            auto listing = analyzer.disassemble(disasm_addr, lines, &color_scheme);
            for (const auto& line : listing) { std::cout << line << std::endl; }
        } else if (command == "m" || command == "mem-dump") { // TODO: This should also use the new format
            std::string addr_str;
            size_t bytes = 0;
            ss >> addr_str >> std::hex >> bytes; // Allow hex input for bytes
            if (addr_str.empty() || bytes == 0) {
                std::cerr << "Usage: mem-dump <addr> <bytes_hex>\n";
                continue;
            }
            run_analysis_actions(cpu, analyzer, label_handler, addr_str, bytes, "", 0, "", false, "", default_mem_format);
        } else if (command == "r" || command == "reg-dump") {
            std::string reg_format;
            std::getline(ss, reg_format);
            reg_format.erase(0, reg_format.find_first_not_of(" \t"));
            run_analysis_actions(cpu, analyzer, label_handler, "", 0, "", 0, "", true, reg_format.empty() ? default_reg_format : reg_format, "");
        } else if (command == "t" || command == "ticks") {
            long long ticks_to_run = 1;
            ss >> ticks_to_run;
            if (ticks_to_run <= 0) {
                std::cerr << "Usage: ticks <num_ticks>\n";
                continue;
            }
            std::cout << "Running for " << ticks_to_run << " T-states...\n";
            long long initial_ticks = cpu.get_ticks();
            long long target_ticks = initial_ticks + ticks_to_run;
            while (cpu.get_ticks() < target_ticks) {
                if (analyzer.is_breakpoint(cpu.get_PC())) {
                    std::cout << "Breakpoint hit at " << format_hex(cpu.get_PC(), 4) << ".\n";
                    break;
                }
                cpu.step();
            }
            std::cout << "Finished. Executed " << (cpu.get_ticks() - initial_ticks) << " T-states.\n";
        } else if (command == "s" || command == "step" || command == "si" || command == "step-into") {
            long long steps_to_run = 1;
            ss >> steps_to_run;
            if (steps_to_run <= 0) {
                // If no number is provided, default to 1 step.
                // This makes 's' or 'step' execute a single step.
                steps_to_run = 1;
            }
            std::cout << "Running for " << steps_to_run << " instructions...\n";
            for (long long i = 0; i < steps_to_run; ++i) {
                if (analyzer.is_breakpoint(cpu.get_PC())) {
                    std::cout << "Breakpoint hit at " << format_hex(cpu.get_PC(), 4) << ".\n";
                    break;
                }
                cpu.step();
            }
            std::cout << "Finished.\n";
        } else if (command == "so" || command == "step-over") {
            uint16_t current_pc = cpu.get_PC();
            if (is_call_instruction(current_pc, cpu.get_bus())) {
                uint16_t next_pc = current_pc;
                analyzer.disassemble(next_pc, 1); // This advances next_pc past the current instruction
                uint16_t step_over_breakpoint = next_pc;
                std::cout << "Stepping over call. Will stop at " << format_hex(step_over_breakpoint, 4) << ".\n";
                while (cpu.get_PC() != step_over_breakpoint) {
                    if (analyzer.is_breakpoint(cpu.get_PC())) {
                        std::cout << "Original breakpoint hit at " << format_hex(cpu.get_PC(), 4) << ".\n";
                        break;
                    }
                    cpu.step();
                }
                std::cout << "Finished step-over.\n";
            } else {
                std::cout << "Stepping one instruction.\n";
                cpu.step();
                std::cout << "Finished.\n";
            }
        } else if (command == "su" || command == "step-out") {
            uint16_t sp_on_entry = cpu.get_SP();
            std::cout << "Running until a RET instruction is executed at a higher or equal stack level...\n";
            while (true) {
                uint8_t opcode = cpu.get_bus()->peek(cpu.get_PC());
                // Check for RET, RET cc, RETI, RETN
                bool is_ret = (opcode == 0xC9 || (opcode & 0xC7) == 0xC0 || opcode == 0xED);
                if (is_ret && opcode == 0xED) {
                    uint8_t next_byte = cpu.get_bus()->peek(cpu.get_PC() + 1);
                    is_ret = (next_byte == 0x4D || next_byte == 0x45); // RETI, RETN
                }

                if (is_ret && cpu.get_SP() >= sp_on_entry) {
                    std::cout << "Stepping out with RET instruction.\n";
                    cpu.step(); // Execute the RET
                    break;
                }
                if (analyzer.is_breakpoint(cpu.get_PC())) {
                    std::cout << "Breakpoint hit at " << format_hex(cpu.get_PC(), 4) << ".\n";
                    break;
                }
                cpu.step();
            }
            std::cout << "Finished step-out.\n";
        } else if (command == "c" || command == "continue") {
            std::cout << "Continuing execution...\n";
            while (true) {
                if (analyzer.is_breakpoint(cpu.get_PC())) {
                    std::cout << "Breakpoint hit at " << format_hex(cpu.get_PC(), 4) << ".\n";
                    break;
                }
                cpu.step();
            }
        } else if (command == "cs" || command == "callstack") {
            int max_depth = 16;
            ss >> max_depth;
            if (max_depth <= 0) max_depth = 16;

            std::cout << "--- Call Stack (from SP: " << format_hex(cpu.get_SP(), 4) << ") ---\n";
            uint16_t current_sp = cpu.get_SP();
            int depth = 0;
            while (current_sp < 0xFFFF && depth < max_depth) {
                uint8_t low_byte = cpu.get_bus()->peek(current_sp);
                uint8_t high_byte = cpu.get_bus()->peek(current_sp + 1);
                uint16_t return_addr = (high_byte << 8) | low_byte;

                std::stringstream label_ss;
                uint16_t label_addr = 0;
                std::string label = label_handler.get_closest_label(return_addr, label_addr);

                if (!label.empty()) {
                    label_ss << label;
                    uint16_t offset = return_addr - label_addr;
                    // Pokaż offset tylko jeśli jest większy od zera
                    if (offset > 0)
                        label_ss << " + " << std::dec << offset;
                }

                std::string label_str = label_ss.str();

                std::cout << format_hex(current_sp, 4) << ": " << format_hex(return_addr, 4)
                          << "  " << (label_str.empty() ? "" : "(" + label_str + ")") << "\n";
                current_sp += 2;
                depth++;
            }
        } else if (command == "b" || command == "breakpoint") {
            std::string arg;
            ss >> arg;
            if (arg == "clear") {
                analyzer.remove_breakpoint(0); // Assuming we only have one for now.
                std::cout << "All breakpoints cleared.\n";
            } else if (!arg.empty()) {
                try {
                    uint16_t breakpoint_address = resolve_address(arg, cpu, &label_handler);
                    analyzer.add_breakpoint(breakpoint_address);
                    std::cout << "Breakpoint set at " << format_hex(breakpoint_address, 4) << ".\n";
                } catch (const std::exception& e) {
                    std::cerr << "Error setting breakpoint: " << e.what() << "\n";
                }
            } else {
                // This part needs to be updated if we support multiple breakpoints
                // For now, let's just say it's not fully implemented.
                // A better implementation would be to iterate through analyzer.m_breakpoints
                std::cout << "Usage: breakpoint <addr> | clear\n";
                std::cout << "(Listing active breakpoints is not yet fully supported in this view)\n";
            }
        } else if (command == "symbol") {
            std::string name;
            ss >> name;
            if (name.empty()) {
                // Show all symbols
                std::cout << "--- All Symbols ---\n";
                const auto& all_labels = label_handler.get_labels();
                if (all_labels.empty()) {
                    std::cout << "No symbols loaded.\n";
                } else {
                    for (const auto& pair : all_labels) {
                        std::cout << std::setw(20) << std::left << pair.first << " = " << format_hex(pair.second, 4) << "\n";
                    }
                }
            } else {
                // Show specific symbol
                uint16_t addr = resolve_address(name, cpu, &label_handler);
                std::cout << name << " = " << format_hex(addr, 4) << "\n";
            }
        } else if (command == "set") {
            std::string reg_str, val_str;
            ss >> reg_str >> val_str;
            if (reg_str.empty() || val_str.empty()) {
                std::cerr << "Usage: set <register> <value>\n";
                continue;
            }
            try {
                uint16_t value = resolve_address(val_str, cpu, &label_handler);
                std::transform(reg_str.begin(), reg_str.end(), reg_str.begin(), ::toupper);
                if (reg_str == "PC") cpu.set_PC(value);
                else if (reg_str == "SP") cpu.set_SP(value);
                else if (reg_str == "AF") cpu.set_AF(value);
                else if (reg_str == "BC") cpu.set_BC(value);
                else if (reg_str == "DE") cpu.set_DE(value);
                else if (reg_str == "HL") cpu.set_HL(value);
                else if (reg_str == "IX") cpu.set_IX(value);
                else if (reg_str == "IY") cpu.set_IY(value);
                else if (reg_str == "A") cpu.set_A(value);
                else if (reg_str == "B") cpu.set_B(value);
                else if (reg_str == "C") cpu.set_C(value);
                else if (reg_str == "D") cpu.set_D(value);
                else if (reg_str == "E") cpu.set_E(value);
                else if (reg_str == "H") cpu.set_H(value);
                else if (reg_str == "L") cpu.set_L(value);
                else { std::cerr << "Unknown register: " << reg_str << "\n"; }
            } catch (const std::exception& e) {
                std::cerr << "Error setting register: " << e.what() << "\n";
            }
        } else if (!command.empty()) {
            std::cerr << "Unknown command: '" << command << "'. Type 'help' for a list of commands.\n";
        }

    }
    rx.history_save(history_file);
    std::cout << "\nExiting interactive mode.\n";
}