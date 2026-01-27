#include "CommandLine.h"
#include "Options.h"
#include "../Utils/Strings.h"
#include <stdexcept>
#include <iostream>
#include <cctype>

bool CommandLine::is_valid_address(const std::string& s) {
    size_t colon = s.find(':');
    std::string addr = (colon == std::string::npos) ? s : s.substr(0, colon);
    
    int32_t dummy;
    if (!Strings::parse_integer(addr, dummy)) return false;
    
    if (colon != std::string::npos) {
            std::string len_str = s.substr(colon + 1);
            if (!Strings::parse_integer(len_str, dummy)) return false;
    }
    return true;
}

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
    if (mode_str == "asm") {
        options.mode = Options::ToolMode::Assemble;
        options.asm_.generateListing = true;
    }
    else if (mode_str == "disasm")
        options.mode = Options::ToolMode::Disassemble;
    else if (mode_str == "run")
        options.mode = Options::ToolMode::Run;
    else if (mode_str == "debug")
        options.mode = Options::ToolMode::Debug;
    else if (mode_str == "profile")
        options.mode = Options::ToolMode::Profile;
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
                if (arg == "-o" || arg == "--output") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.asm_.outputFile = argv[++i];
                } else if (arg == "-f" || arg == "--format") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.asm_.outputFormat = argv[++i];
                } else if (arg == "-m" || arg == "--map") {
                    options.asm_.generateMap = true;
                } else if (arg == "-l" || arg == "--listing") {
                    options.asm_.generateListing = true;
                } else {
                    throw std::runtime_error("Unknown argument '" + arg + "' for 'asm' mode.");
                }
            } else if (options.mode == Options::ToolMode::Disassemble) {
                if (arg == "-o" || arg == "--output") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.disasm.outputFile = argv[++i];
                } else if (arg == "-e" || arg == "--entry") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.disasm.entryPointStr = argv[++i];
                } else if (arg == "-m" || arg == "--mode") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    std::string disasm_mode_str = argv[++i];
                    if (disasm_mode_str == "raw") options.disasm.mode = Options::Disassemble::Mode::Raw;
                    else if (disasm_mode_str == "heuristic") options.disasm.mode = Options::Disassemble::Mode::Heuristic;
                    else if (disasm_mode_str == "execute") options.disasm.mode = Options::Disassemble::Mode::Execute;
                    else throw std::runtime_error("Invalid disassembly mode: '" + disasm_mode_str + "'. Use 'raw', 'heuristic', or 'execute'.");
                } else {
                    throw std::runtime_error("Unknown argument '" + arg + "' for 'disasm' mode.");
                }
            } else if (options.mode == Options::ToolMode::Run || options.mode == Options::ToolMode::Profile) {
                Options::Run* runOpts = (options.mode == Options::ToolMode::Run) ? &options.run : &options.profile;
                if (arg == "-e" || arg == "--entry") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    std::string val = argv[++i];
                    runOpts->entryPointStr = val;
                } else if (arg == "-s" || arg == "--steps") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    runOpts->steps = std::stoll(argv[++i], nullptr, 10);
                } else if (arg == "-t" || arg == "--ticks") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    runOpts->ticks = std::stoll(argv[++i], nullptr, 10);
                } else if (arg == "-to" || arg == "--timeout") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    runOpts->timeout = std::stoll(argv[++i], nullptr, 10);
                } else if (arg == "-f" || arg == "--finish") {
                    runOpts->runUntilReturn = true;
                } else if (arg == "-dr" || arg == "--dump-regs") {
                    runOpts->dumpRegs = true;
                } else if (arg == "-dc" || arg == "--dump-code") {
                    if (i + 1 < argc) {
                        std::string next_arg = argv[i + 1];
                        if (next_arg[0] != '-' && is_valid_address(next_arg)) {
                            if (next_arg.find(':') != std::string::npos) {
                                runOpts->dumpCodeStr = argv[++i];
                            } else {
                                throw std::runtime_error("Missing length for " + arg + ". Format: address:length");
                            }
                        } else {
                            if (std::isdigit(next_arg[0]) && next_arg.find(':') != std::string::npos) {
                                throw std::runtime_error("Invalid value for " + arg + ": " + next_arg);
                            }
                            runOpts->dumpCodeStr = "ALL";
                        }
                    } else {
                        runOpts->dumpCodeStr = "ALL";
                    }
                } else if (arg == "-dm" || arg == "--dump-mem") {
                    if (i + 1 < argc) {
                        std::string next_arg = argv[i + 1];
                        if (next_arg[0] != '-' && is_valid_address(next_arg)) {
                            if (next_arg.find(':') != std::string::npos) {
                                runOpts->dumpMemStr = argv[++i];
                            } else {
                                throw std::runtime_error("Missing length for " + arg + ". Format: address:length");
                            }
                        } else {
                            if (std::isdigit(next_arg[0]) && next_arg.find(':') != std::string::npos) {
                                throw std::runtime_error("Invalid value for " + arg + ": " + next_arg);
                            }
                            runOpts->dumpMemStr = "ALL";
                        }
                    } else {
                        runOpts->dumpMemStr = "ALL";
                    }
                } else if (arg == "--hotspots") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.profile.hotspots = std::stoi(argv[++i]);
                } else if (arg == "--export") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.profile.exportFile = argv[++i];
                } else {
                    throw std::runtime_error("Unknown argument '" + arg + "'.");
                }
            } else if (options.mode == Options::ToolMode::Debug) {
                if (arg == "-e" || arg == "--entry") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.debug.entryPointStr = argv[++i];
                } else if (arg == "-s" || arg == "--script") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing argument for " + arg);
                    options.debug.scriptFile = argv[++i];
                } else {
                    throw std::runtime_error("Unknown argument '" + arg + "' for 'debug' mode.");
                }
            } else {
                throw std::runtime_error("Unknown argument '" + arg + "'.");
            }
        } else { // It's a positional argument, should be the input file
            std::string path = arg;
            uint16_t address = 0;
            size_t colon = arg.find(':');
            if (colon != std::string::npos) {
                path = arg.substr(0, colon);
                int32_t val = 0;
                Strings::parse_integer(arg.substr(colon + 1), val);
                address = (uint16_t)val;
            }
            options.inputFiles.push_back({path, address});
        }
    }
    if (options.inputFiles.empty()) {
        throw std::runtime_error("No input file specified.");
    }

    // Post-parsing validation
    if (options.mode == Options::ToolMode::Assemble) {
        if (options.asm_.outputFile.empty()) {
            options.asm_.outputFile = "out.bin";
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
              << "Input files can be specified with an optional load address, e.g., 'file.bin:0x8000'.\n"
              << "Sidecar files (.map, .sym, .ctl) are automatically loaded if present.\n\n"
              << "Commands:\n"
              << "  asm                Build a Z80 source file.\n"
              << "  disasm             Statically analyze a binary file.\n"
              << "  run                Run code in headless mode.\n"
              << "  debug              Start an interactive debugging session.\n\n"
              << "  profile            Run code and analyze performance.\n\n"
              << "Options:\n"
              << "  -v, --verbose        Show detailed assembly process.\n\n"
              << "Build Options (asm command):\n"
              << "  -o, --output <file>  Output file (default: out.bin).\n"
              << "  -f, --format <fmt>   Output format: bin, sna, tap, hex.\n"
              << "  -m, --map            Generate a symbol map file.\n"
              << "  -l, --listing        Generate a source listing file.\n\n"
              << "Static Analysis Options (disasm command):\n"
              << "  -e, --entry [a:n]    Entry point 'a' for code flow tracing (optional limit 'n').\n"
              << "  -m, --mode <m>       Disassembly mode: raw, heuristic, execute.\n\n"
              << "Execution/Profile Options (run/profile command):\n"
              << "  -e, --entry <addr>   Entry point for execution.\n"
              << "  -s, --steps <n>      Stop after N instructions.\n"
              << "  -t, --ticks <n>      Stop after N T-states.\n"
              << "  -to, --timeout <s>   Stop after S seconds.\n"
              << "  -f,  --finish         Run until return (RET) from entry point.\n"
              << "  -dr, --dump-regs       Dump registers on exit.\n"
              << "  -dc, --dump-code [a:n]  Dump n instructions from address a on exit (default: all blocks).\n"
              << "  -dm, --dump-mem [a:n]   Dump n bytes from address a on exit (default: all blocks).\n"
              << "  --hotspots <n>       Number of hotspots to show in profile report (default: 20).\n"
              << "  --export <file>      Export profile data to CSV file.\n\n"
              << "Interactive Debugging Options (debug command):\n"
              << "  -e, --entry <addr>   Entry point for execution.\n"
              << "  -s, --script <file>  Execute debugger commands from file on start.\n";
}