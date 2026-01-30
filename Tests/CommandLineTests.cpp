#include "CommandLineTests.h"
#include "../Cmd/CommandLine.h"
#include <vector>
#include <string>
#include <cassert>
#include <iostream>
#include <sstream>

// Helper to run parse with vector of strings
static bool run_parse(CommandLine& cmd, const std::vector<std::string>& args) {
    std::vector<char*> argv;
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    // Suppress stderr/stdout during tests
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    std::streambuf* old_cout = std::cout.rdbuf(null_ss.rdbuf());
    
    bool result = cmd.parse((int)argv.size(), argv.data());
    
    std::cerr.rdbuf(old_cerr);
    std::cout.rdbuf(old_cout);
    return result;
}

void test_cmd_no_args() {
    CommandLine cmd;
    std::vector<std::string> args = {"zxtool"};
    assert(run_parse(cmd, args) == false);
}

void test_cmd_help() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "--help"}) == false);
    assert(run_parse(cmd, {"zxtool", "-h"}) == false);
}

void test_cmd_version() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "--version"}) == false);
    assert(run_parse(cmd, {"zxtool", "-v"}) == false);
}

void test_cmd_unknown_command() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "xyz", "file.bin"}) == false);
}

void test_cmd_build_simple() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "input.asm"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Build);
    assert(opts.inputFiles.size() == 1);
    assert(opts.inputFiles[0].first == "input.asm");
    assert(opts.build.outputFile == "out.bin"); // Default
}

void test_cmd_build_options() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "in.asm", "-o", "rom.bin", "-f", "bin", "-m", "-l", "--verbose"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Build);
    assert(opts.build.outputFile == "rom.bin");
    assert(opts.build.outputFormat == "bin");
    assert(opts.build.generateMap == true);
    assert(opts.build.generateListing == true);
    assert(opts.verbose == true);
}

void test_cmd_asm_alias() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "asm", "in.asm"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Build);
    assert(opts.build.generateListing == true); // asm implies listing
}

void test_cmd_dasm_options() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "dasm", "rom.bin", "-o", "out.asm", "-e", "0x0000", "-m", "heuristic"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Disassemble);
    assert(opts.disasm.outputFile == "out.asm");
    assert(opts.disasm.entryPointStr == "0x0000");
    assert(opts.disasm.mode == Options::Disassemble::Mode::Heuristic);
}

void test_cmd_run_options() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "run", "game.sna", "-s", "1000", "-t", "5000", "-to", "10", "-f", "-dr", "-dc", "0x8000:16", "-dm", "0x4000:32"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Run);
    assert(opts.run.steps == 1000);
    assert(opts.run.ticks == 5000);
    assert(opts.run.timeout == 10);
    assert(opts.run.runUntilReturn == true);
    assert(opts.run.dumpRegs == true);
    assert(opts.run.dumpCodeStr == "0x8000:16");
    assert(opts.run.dumpMemStr == "0x4000:32");
}

void test_cmd_profile_options() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "profile", "test.z80", "--hotspots", "50", "--export", "prof.csv"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Profile);
    assert(opts.profile.hotspots == 50);
    assert(opts.profile.exportFile == "prof.csv");
}

void test_cmd_debug_options() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "debug", "test.z80", "-e", "0x8000", "-s", "init.scr"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Debug);
    assert(opts.debug.entryPointStr == "0x8000");
    assert(opts.debug.scriptFile == "init.scr");
}

void test_cmd_input_files() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "file1.asm", "file2.bin:0x8000", "file3.map"}));
    const auto& opts = cmd.get_options();
    assert(opts.inputFiles.size() == 3);
    assert(opts.inputFiles[0].first == "file1.asm");
    assert(opts.inputFiles[0].second == 0);
    assert(opts.inputFiles[1].first == "file2.bin");
    assert(opts.inputFiles[1].second == 0x8000);
    assert(opts.inputFiles[2].first == "file3.map");
}

void test_cmd_missing_args() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "-o"}) == false); // Missing output file
    assert(run_parse(cmd, {"zxtool", "dasm", "-m"}) == false); // Missing mode
    assert(run_parse(cmd, {"zxtool", "run", "-s"}) == false); // Missing steps
}

void test_cmd_invalid_values() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "dasm", "f.bin", "-m", "invalid"}) == false);
    assert(run_parse(cmd, {"zxtool", "run", "f.bin", "-dc", "0:invalid"}) == false); // Invalid dump code format
}

void test_cmd_build_no_input() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build"}) == false);
}

void test_cmd_unknown_option() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "in.asm", "--unknown"}) == false);
    assert(run_parse(cmd, {"zxtool", "dasm", "in.bin", "--unknown"}) == false);
    assert(run_parse(cmd, {"zxtool", "run", "in.bin", "--unknown"}) == false);
    assert(run_parse(cmd, {"zxtool", "debug", "in.bin", "--unknown"}) == false);
}

void test_cmd_run_dump_implicit_all() {
    CommandLine cmd;
    // Case 1: -dc at end
    assert(run_parse(cmd, {"zxtool", "run", "in.bin", "-dc"}));
    assert(cmd.get_options().run.dumpCodeStr == "ALL");
    
    // Case 2: -dc followed by another option
    assert(run_parse(cmd, {"zxtool", "run", "in.bin", "-dc", "-v"}));
    assert(cmd.get_options().run.dumpCodeStr == "ALL");
    assert(cmd.get_options().verbose == true);

    // Case 3: -dm at end
    assert(run_parse(cmd, {"zxtool", "run", "in.bin", "-dm"}));
    assert(cmd.get_options().run.dumpMemStr == "ALL");
}

void test_cmd_verbose_flag() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "in.asm", "-v"}));
    assert(cmd.get_options().verbose == true);
    
    CommandLine cmd2;
    assert(run_parse(cmd2, {"zxtool", "build", "in.asm", "--verbose"}));
    assert(cmd2.get_options().verbose == true);
}

void test_cmd_dasm_modes() {
    CommandLine cmd1;
    assert(run_parse(cmd1, {"zxtool", "dasm", "f.bin", "-m", "raw"}));
    assert(cmd1.get_options().disasm.mode == Options::Disassemble::Mode::Raw);

    CommandLine cmd2;
    assert(run_parse(cmd2, {"zxtool", "dasm", "f.bin", "-m", "execute"}));
    assert(cmd2.get_options().disasm.mode == Options::Disassemble::Mode::Execute);
}

void test_cmd_profile_inherited_options() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "profile", "f.bin", "-s", "100", "--hotspots", "10"}));
    const auto& opts = cmd.get_options();
    assert(opts.mode == Options::ToolMode::Profile);
    assert(opts.profile.steps == 100);
    assert(opts.profile.hotspots == 10);
}

void test_cmd_no_input_with_flags() {
    CommandLine cmd;
    // "zxtool build -v" -> argc=3. Loop finishes. inputFiles empty. Should return false.
    assert(run_parse(cmd, {"zxtool", "build", "-v"}) == false);
}

void test_cmd_input_file_invalid_addr() {
    CommandLine cmd;
    assert(run_parse(cmd, {"zxtool", "build", "file.bin:invalid"}));
    const auto& opts = cmd.get_options();
    assert(opts.inputFiles.size() == 1);
    assert(opts.inputFiles[0].first == "file.bin");
    assert(opts.inputFiles[0].second == 0); // Fallback to 0
}

void test_cmd_run_dump_formats() {
    CommandLine cmd1;
    // Address only (default length)
    assert(run_parse(cmd1, {"zxtool", "run", "f.bin", "-dc", "0x8000"}));
    assert(cmd1.get_options().run.dumpCodeStr == "0x8000");

    CommandLine cmd2;
    // Address and length
    assert(run_parse(cmd2, {"zxtool", "run", "f.bin", "-dm", "0x4000:256"}));
    assert(cmd2.get_options().run.dumpMemStr == "0x4000:256");
}

void test_cmd_numeric_parsing_errors() {
    CommandLine cmd;
    // Invalid steps
    // Note: std::stoll throws exception which is caught and returns false
    assert(run_parse(cmd, {"zxtool", "run", "f.bin", "-s", "invalid"}) == false);
    
    // Invalid ticks
    assert(run_parse(cmd, {"zxtool", "run", "f.bin", "-t", "invalid"}) == false);
    
    // Invalid timeout
    assert(run_parse(cmd, {"zxtool", "run", "f.bin", "-to", "invalid"}) == false);
}
