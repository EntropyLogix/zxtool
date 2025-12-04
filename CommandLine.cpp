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
    if (mode_str == "asm") options.mode = Options::ToolMode::Assemble;
    else if (mode_str == "disasm") options.mode = Options::ToolMode::Disassemble;
    else if (mode_str == "run") options.mode = Options::ToolMode::Run;
    else if (mode_str == "debug") options.mode = Options::ToolMode::Debug;
    else throw std::runtime_error("Unknown command: '" + mode_str + "'. Use 'asm', 'disasm', 'run', or 'debug'.");

    // Parse remaining arguments to find options and the input file
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg[0] == '-') { // It's an option
            // General options
            if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
                options.outputFile = argv[++i];
            } else if ((arg == "-f" || arg == "--format") && i + 1 < argc) {
                options.outputFormat = argv[++i];
            } else if ((arg == "-m" || arg == "--map") && i + 1 < argc) {
                options.mapFile = argv[++i];
            } else if (arg == "--org" && i + 1 < argc) {
                options.orgStr = argv[++i];
            } else if ((arg == "-v" || arg == "--verbose")) {
                options.verbose = true;
            }
            // 'asm' specific
            else if ((arg == "-l" || arg == "--listing") && i + 1 < argc) {
                options.listingFile = argv[++i];
            }
            // 'disasm' specific
            else if (arg == "--entry" && i + 1 < argc) {
                options.entryPointStr = argv[++i];
            } else if (arg == "--raw") {
                options.rawDisassembly = true;
            }
            // 'run' specific
            else if (arg == "--steps" && i + 1 < argc) {
                options.runSteps = std::stoll(argv[++i], nullptr, 10);
            } else if (arg == "--ticks" && i + 1 < argc) {
                options.runTicks = std::stoll(argv[++i], nullptr, 10);
            } else if (arg == "--timeout" && i + 1 < argc) {
                options.timeout = std::stoll(argv[++i], nullptr, 10);
            } else if (arg == "--dump-regs") {
                options.dumpRegs = true;
            } else if (arg == "--dump-mem" && i + 1 < argc) {
                options.dumpMemStr = argv[++i];
            }
            // 'debug' specific
            else if (arg == "--script" && i + 1 < argc) {
                options.scriptFile = argv[++i];
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

    // Post-parsing validation
    if (options.mode == Options::ToolMode::Assemble) {
        if (options.outputFile.empty()) {
            options.outputFile = "out.bin";
        }
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
              << "  asm                Build a Z80 source file.\n"
              << "  disasm             Statically analyze a binary file.\n"
              << "  run                Run code in headless mode (for tests/CI).\n"
              << "  debug              Start an interactive debugging session (REPL).\n\n"
              << "1. asm - Build Options:\n"
              << "  -o, --output <file>  Output file (default: out.bin).\n"
              << "  -f, --format <fmt>   Output format: bin, sna, tap, hex.\n"
              << "  -m, --map <file>     Generate a symbol map file.\n"
              << "  -l, --listing <file> Generate a source listing file.\n"
              << "  -v, --verbose        Show detailed assembly process.\n\n"
              << "2. disasm - Static Analysis Options:\n"
              << "  -o, --output <file>  Output file (default: stdout).\n"
              << "  --org <addr>         Start address for raw binary (default: 0x0000).\n"
              << "  --entry <addr>       Entry point for code flow tracing.\n"
              << "  --map <file>         Load a symbol file for named labels.\n"
              << "  --raw                Disassemble linearly without flow tracing.\n\n"
              << "3. run - Headless Execution Options:\n"
              << "  --steps <n>          Stop after N instructions.\n"
              << "  --ticks <n>          Stop after N T-states.\n"
              << "  --timeout <s>        Stop after S seconds.\n"
              << "  --org <addr>         Load address for raw .bin files.\n"
              << "  --dump-regs          Dump registers on exit.\n"
              << "  --dump-mem <a:l>     Dump memory on exit (e.g., 0x8000:64).\n\n"
              << "4. debug - Interactive Debugging Options:\n"
              << "  --org <addr>         Load address for raw .bin files.\n"
              << "  --script <file>      Execute debugger commands from file on start.\n"
              << "  --map <file>         Load a symbol file (for .bin files).\n";
}