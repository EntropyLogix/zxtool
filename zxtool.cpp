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
#include <map>

// --- Helper Functions ---

void print_usage() {
    std::cerr << "A unified tool for Z80 assembly and analysis.\n"
              << "Usage: zxtool <command> <input_file> [options]"
              << "COMMANDS:\n"
              << "  asm Assemble a Z80 source file.\n"
              << "  run Run a Z80 binary/snapshot file.\n"
              << "ASM OPTIONS:\n"
              << "    --bin <file>              Save result as a raw binary file.\n"
              << "    --hex <file>              Save result as an Intel HEX file.\n"
              << "    --map <file>              Save the symbol table to a map file.\n"
              << "    --verbose                 Show detailed assembly output (symbols, disassembly).\n"
              << "RUN OPTIONS:\n"
              << "  Loading:\n"
              << "    --org <addr>              Specifies the loading address for .bin files (default: 0x0000).\n"
              << "    --map <file>              Load a .map symbol file (can be used multiple times).\n"
              << "    --ctl <file>              Load a .ctl symbol file (can be used multiple times).\n"
              << "  Execution:\n"
              << "    --steps <steps>           Run emulation for a number of instructions.\n"
              << "    --ticks <ticks>           Run emulation for a number of T-states.\n"
              << "    --disasm <addr> <lines>   Disassemble code.\n"
              << "    --mem <addr> <bytes>      Dump memory.\n"
              << "    --reg [format]            Dump CPU registers.\n";
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
    enum class ToolMode { Asm, Run, Unknown };

    CommandLineOptions(int argc, char* argv[]) {
        if (argc < 3) {
            throw std::runtime_error("Invalid arguments. Command and input file are required.");
        }
        std::string mode_str = argv[1];
        if (mode_str == "asm") m_mode = ToolMode::Asm;
        else if (mode_str == "run") m_mode = ToolMode::Run;
        else throw std::runtime_error("Unknown command: '" + mode_str + "'. Use 'asm' or 'run'.");

        // Parse remaining arguments to find options and the input file
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg.rfind("--", 0) == 0) { // It's an option
                if (arg == "--bin" && i + 1 < argc) m_outputBinFile = argv[++i];
                else if (arg == "--hex" && i + 1 < argc) m_outputHexFile = argv[++i];
                else if (arg == "--mem" && i + 2 < argc) {
                    m_memDumpAddrStr = argv[++i];
                    m_memDumpSize = std::stoul(argv[++i], nullptr, 0);
                } else if (arg == "--disasm" && i + 2 < argc) {
                    m_disasmAddrStr = argv[++i];
                    m_disasmLines = std::stoul(argv[++i], nullptr, 10);
                } else if (arg == "--org" && i + 1 < argc) m_orgStr = argv[++i];
                else if (arg == "--map" && i + 1 < argc) {
                    if (m_mode == ToolMode::Asm) {
                        m_outputMapFile = argv[++i];
                    } else { // ToolMode::Run
                        m_mapFiles.push_back(argv[++i]);
                    }
                }
                else if (arg == "--ctl" && i + 1 < argc) m_ctlFiles.push_back(argv[++i]);
                else if (arg == "--reg") {
                    m_regDumpAction = true;
                    if (i + 1 < argc && argv[i + 1][0] != '-') m_regDumpFormat = argv[++i];
                } else if (arg == "--ticks" && i + 1 < argc) m_runTicks = std::stoll(argv[++i], nullptr, 10);
                else if (arg == "--steps" && i + 1 < argc) m_runSteps = std::stoll(argv[++i], nullptr, 10);
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
    const std::string& getOrgStr() const { return m_orgStr; }
    const std::vector<std::string>& getMapFiles() const { return m_mapFiles; }
    const std::vector<std::string>& getCtlFiles() const { return m_ctlFiles; }
    long long getRunTicks() const { return m_runTicks; }
    long long getRunSteps() const { return m_runSteps; }
    bool isRegDumpRequested() const { return m_regDumpAction; }
    const std::string& getRegDumpFormat() const { return m_regDumpFormat; }
    bool isVerbose() const { return m_verbose; }

private:
    ToolMode m_mode = ToolMode::Unknown;
    std::string m_inputFile, m_outputBinFile, m_outputHexFile, m_outputMapFile;
    std::string m_memDumpAddrStr, m_disasmAddrStr, m_orgStr = "0x0000";
    size_t m_memDumpSize = 0, m_disasmLines = 0;
    long long m_runTicks = 0, m_runSteps = 0;
    std::vector<std::string> m_mapFiles, m_ctlFiles;
    bool m_regDumpAction = false;
    std::string m_regDumpFormat;
    bool m_verbose = false;
};

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
        if (options.getMode() == CommandLineOptions::ToolMode::Asm) { // --- MODE 1: ASSEMBLY (.asm file) ---
            std::cout << "--- Asm Mode ---\n";
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
        // --- MODE 2: RUN/DUMP (other files) ---
        else {
            std::cout << "--- Run/Dump Mode ---\n";
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
                    uint16_t org_addr = resolve_address(options.getOrgStr(), cpu, nullptr);
                    loaded = file_loader.load_bin_file(data, org_addr);
                    cpu.set_PC(org_addr);
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

        // If no execution is requested, set PC to the entry point before analysis/interactive mode.
        bool execution_requested = (options.getRunTicks() > 0 || options.getRunSteps() > 0);
        if (!execution_requested) {
            cpu.set_PC(entry_point);
        }

        bool emulation_requested = (options.getRunTicks() > 0 || options.getRunSteps() > 0);

        if (emulation_requested) {
            std::cout << "\n--- Starting emulation ---\n";
            if (options.getRunTicks() > 0) std::cout << "  Running for " << options.getRunTicks() << " T-states (--ticks).\n";
            if (options.getRunSteps() > 0) std::cout << "  Running for " << options.getRunSteps() << " instructions (--steps).\n";

            long long initial_ticks = cpu.get_ticks();
            long long target_ticks = (options.getRunTicks() > 0) ? (initial_ticks + options.getRunTicks()) : -1; // -1 means no T-state limit
            long long steps_executed = 0;

            while (true) {
                // Check for breakpoint hit BEFORE executing the instruction
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

        if (!emulation_requested && !one_shot_analysis_requested && options.getMode() == CommandLineOptions::ToolMode::Run) {
            run_analysis_actions(cpu, analyzer, label_handler, "", 0, "", 0, "", true, "", "");
        }

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}