#include "CommandLine.h"
#include "Options.h"
#include <stdexcept>
#include <iostream>

CommandLine::CommandLine() {
    // Default constructor
}

bool CommandLine::parse(int argc, char* argv[], Options& options) {
    if (argc < 2) {
        print_usage();
        return false;
    }

    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") {
        print_usage();
        return false;
    }
    if (first_arg == "--version" || first_arg == "-v") {
        std::cout << "zxtool version 0.0.1" << std::endl;
        return false;
    }

    try {
        if (argc < 3) {
        throw std::runtime_error("Invalid arguments. Command and input file are required.");
    }
    std::string mode_str = argv[1];
    if (mode_str == "assemble") options.mode = Options::ToolMode::Assemble;
    else if (mode_str == "run") options.mode = Options::ToolMode::Run;
    else throw std::runtime_error("Unknown command: '" + mode_str + "'. Use 'assemble' or 'run'.");

    // Parse remaining arguments to find options and the input file
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--", 0) == 0) { // It's an option
            if (arg == "--bin" && i + 1 < argc) options.outputBinFile = argv[++i];
            else if (arg == "--hex" && i + 1 < argc) options.outputHexFile = argv[++i];
            else if (arg == "--mem" && i + 2 < argc) {
                options.memDumpAddrStr = argv[++i];
                options.memDumpSize = std::stoul(argv[++i], nullptr, 0);
            } else if (arg == "--disasm" && i + 2 < argc) {
                options.disasmAddrStr = argv[++i];
                options.disasmLines = std::stoul(argv[++i], nullptr, 10);
            } else if (arg == "--org" && i + 1 < argc) options.orgStr = argv[++i];
            else if (arg == "--map" && i + 1 < argc) {
                if (options.mode == Options::ToolMode::Assemble) {
                    options.outputMapFile = argv[++i];
                } else { // ToolMode::Run
                    options.mapFiles.push_back(argv[++i]);
                }
            }
            else if (arg == "--ctl" && i + 1 < argc) options.ctlFiles.push_back(argv[++i]);
            else if (arg == "--reg") {
                options.regDumpAction = true;
                if (i + 1 < argc && argv[i + 1][0] != '-') options.regDumpFormat = argv[++i];
            } else if (arg == "--ticks" && i + 1 < argc) options.runTicks = std::stoll(argv[++i], nullptr, 10);
            else if (arg == "--steps" && i + 1 < argc) options.runSteps = std::stoll(argv[++i], nullptr, 10);
             else if (arg == "--verbose") {
                options.verbose = true;
            }
            else {
                throw std::runtime_error("Unknown or incomplete argument '" + arg + "'.");
            }
        } else { // It's a positional argument, should be the input file
            if (!options.inputFile.empty()) {
                throw std::runtime_error("Multiple input files specified: '" + options.inputFile + "' and '" + arg + "'.");
            }
            options.inputFile = arg;
        }
    }
    if (options.inputFile.empty()) {
        throw std::runtime_error("No input file specified.");
    }
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return false;
    }

    return true;
}

void CommandLine::print_usage() const {
    std::cerr << "zxtool v0.0.1 - A unified tool for Z80 assembly and analysis.\n\n"
              << "Usage: zxtool <command> <input_file> [options]\n"
              << "       zxtool --help | --version\n\n"
              << "Commands:\n"
              << "  assemble           Assemble a Z80 source file.\n"
              << "  run                Run a Z80 binary/snapshot file.\n\n"
              << "General Options:\n"
              << "  --help, -h         Show this help message.\n"
              << "  --version, -v      Show version information.\n\n"
              << "Assemble Options (used with 'assemble' command):\n"
              << "  --bin <file>       Save result as a raw binary file.\n"
              << "  --hex <file>       Save result as an Intel HEX file.\n"
              << "  --map <file>       Save the symbol table to a map file.\n"
              << "  --verbose          Show detailed assembly output (symbols, disassembly).\n\n"
              << "RUN Options (used with 'run' command for loading files):\n"
              << "  --org <addr>       Specifies the loading address for .bin files (default: 0x0000).\n"
              << "  --map <file>       Load a .map symbol file (can be used multiple times).\n"
              << "  --ctl <file>       Load a .ctl symbol file (can be used multiple times).\n\n"
              << "Execution & Analysis Options (used with 'assemble' or 'run'):\n"
              << "  --steps <steps>    Run emulation for a number of instructions.\n"
              << "  --ticks <ticks>    Run emulation for a number of T-states.\n"
              << "  --disasm <addr> <lines>  Disassemble code at a specific address.\n"
              << "  --mem <addr> <bytes>     Dump memory content at a specific address.\n"
              << "  --reg [format]     Dump CPU registers.\n";
}