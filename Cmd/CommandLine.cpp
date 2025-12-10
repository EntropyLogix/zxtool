#include "CommandLine.h"
#include "Options.h"
#include <stdexcept>
#include <iostream>

bool CommandLine::parse(int argc, char* argv[]) {
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
            throw std::runtime_error("Invalid arguments. Command and input files are required.");
    }
    std::string mode_str = argv[1];
    if (mode_str == "asm")
        options.mode = Options::ToolMode::Assemble;
    else if (mode_str == "disasm")
        options.mode = Options::ToolMode::Disassemble;
    else if (mode_str == "run")
        options.mode = Options::ToolMode::Run;
    else if (mode_str == "debug")
        options.mode = Options::ToolMode::Debug;
    else
        throw std::runtime_error("Unknown command: '" + mode_str + "'. Use 'asm', 'disasm', 'run', or 'debug'.");
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg[0] == '-') {
            // Global options
            if (arg == "-v" || arg == "--verbose") {
                options.verbose = true;
                continue;
            }

            // Mode-specific options
            if (options.mode == Options::ToolMode::Assemble) {
                if ((arg == "-o" || arg == "--output") && i + 1 < argc) options.outputFile = argv[++i];
                else if ((arg == "-f" || arg == "--format") && i + 1 < argc) options.outputFormat = argv[++i];
                else if (arg == "-m" || arg == "--map") options.generateMap = true;
                else if (arg == "-l" || arg == "--listing") options.generateListing = true;
                else throw std::runtime_error("Unknown argument '" + arg + "' for 'asm' mode.");
            } else if (options.mode == Options::ToolMode::Disassemble) {
                if ((arg == "-o" || arg == "--output") && i + 1 < argc) options.outputFile = argv[++i];
                else if (arg == "-l" || arg == "--labels") options.autoLabels = true;
                else if ((arg == "-e" || arg == "--entry") && i + 1 < argc) options.entryPointStr = argv[++i];
                else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
                    std::string disasm_mode_str = argv[++i];
                    if (disasm_mode_str == "raw") options.disasmMode = Options::DisasmMode::Raw;
                    else if (disasm_mode_str == "heuristic") options.disasmMode = Options::DisasmMode::Heuristic;
                    else if (disasm_mode_str == "execute") options.disasmMode = Options::DisasmMode::Execute;
                    else throw std::runtime_error("Invalid disassembly mode: '" + disasm_mode_str + "'. Use 'raw', 'heuristic', or 'execute'.");
                } else throw std::runtime_error("Unknown argument '" + arg + "' for 'disasm' mode.");
            } else if (options.mode == Options::ToolMode::Run) {
                if ((arg == "-e" || arg == "--entry") && i + 1 < argc) options.entryPointStr = argv[++i];
                else if ((arg == "-s" || arg == "--steps") && i + 1 < argc) options.runSteps = std::stoll(argv[++i], nullptr, 10);
                else if ((arg == "-t" || arg == "--ticks") && i + 1 < argc) options.runTicks = std::stoll(argv[++i], nullptr, 10);
                else if ((arg == "-to" || arg == "--timeout") && i + 1 < argc) options.timeout = std::stoll(argv[++i], nullptr, 10);
                else if (arg == "-dr" || arg == "--dump-regs") options.dumpRegs = true;
                else if ((arg == "-dm" || arg == "--dump-mem") && i + 1 < argc) options.dumpMemStr = argv[++i];
                else throw std::runtime_error("Unknown argument '" + arg + "' for 'run' mode.");
            } else if (options.mode == Options::ToolMode::Debug) {
                if ((arg == "-e" || arg == "--entry") && i + 1 < argc) options.entryPointStr = argv[++i];
                else if (arg == "-l" || arg == "--labels") options.autoLabels = true;
                else if ((arg == "-s" || arg == "--script") && i + 1 < argc) options.scriptFile = argv[++i];
                else throw std::runtime_error("Unknown argument '" + arg + "' for 'debug' mode.");
            } else
                throw std::runtime_error("Unknown argument '" + arg + "'.");
        } else { // It's a positional argument, should be the input file
            options.inputFiles.push_back(arg);
        }
    }
    if (options.inputFiles.empty()) {
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
              << "Usage: zxtool <command> <input_files...> [options]\n"
              << "       zxtool --help | --version\n\n"
              << "Input files can be specified with an optional load address, e.g., 'file.bin:0x8000'.\n\n"
              << "Commands:\n"
              << "  asm                Build a Z80 source file.\n"
              << "  disasm             Statically analyze a binary file.\n"
              << "  run                Run code in headless mode.\n"
              << "  debug              Start an interactive debugging session.\n\n"
              << "Options:\n"
              << "  -v, --verbose        Show detailed assembly process.\n\n"
              << "Build Options (asm command):\n"
              << "  -o, --output <file>  Output file (default: out.bin).\n"
              << "  -f, --format <fmt>   Output format: bin, sna, tap, hex.\n"
              << "  -m, --map            Generate a symbol map file.\n"
              << "  -l, --listing        Generate a source listing file.\n\n"
              << "Static Analysis Options (disasm command):\n"
              << "  -l, --labels         Auto-load symbol files.\n"
              << "  -e, --entry <addr>   Entry point for code flow tracing.\n"
              << "  -m, --mode <m>       Disassembly mode: raw, heuristic, execute.\n\n"
              << "Headless Execution Options (run command):\n"
              << "  -s, --steps <n>      Stop after N instructions.\n"
              << "  -t, --ticks <n>      Stop after N T-states.\n"
              << "  -tm, --timeout <s>   Stop after S seconds.\n"
              << "  -dr, --dump-regs     Dump registers on exit.\n"
              << "  -dm, --dump-mem <a:l> Dump memory on exit (e.g., 0x8000:64).\n\n"
              << "Interactive Debugging Options (debug command):\n"
              << "  -l, --labels         Auto-load symbol files.\n"
              << "  -s, --script <file>  Execute debugger commands from file on start.\n";
}