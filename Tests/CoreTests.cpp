#include "CoreTests.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>
#include "../Core/Core.h"

void test_core_load_explicit_metadata() {
    Core core;
    
    // Create a dummy map file
    std::string map_content = "8000 StartLabel\n";
    std::ofstream out("explicit.map");
    out << map_content;
    out.close();
    
    // Pass it as an input file
    std::vector<std::pair<std::string, uint16_t>> inputs;
    inputs.push_back({"explicit.map", 0});
    
    // Suppress stdout/stderr
    std::stringstream null_ss;
    std::streambuf* old_cout = std::cout.rdbuf(null_ss.rdbuf());
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    core.load_input_files(inputs);
    
    std::cout.rdbuf(old_cout);
    std::cerr.rdbuf(old_cerr);
    
    std::filesystem::remove("explicit.map");
    
    // Verify symbol was loaded
    auto sym = core.get_context().getSymbols().find("StartLabel");
    assert(sym != nullptr);
    assert(sym->read() == 0x8000);
}

void test_core_load_binary_and_sidecar() {
    Core core;
    
    // Create binary
    std::ofstream bin("game.bin", std::ios::binary);
    bin.put(0);
    bin.close();
    
    // Create sidecar map
    std::ofstream map("game.map");
    map << "8000 GameStart\n";
    map.close();
    
    std::vector<std::pair<std::string, uint16_t>> inputs;
    inputs.push_back({"game.bin", 0x8000});
    
    core.load_input_files(inputs);
    
    std::filesystem::remove("game.bin");
    std::filesystem::remove("game.map");
    
    // Verify binary loaded (block exists)
    assert(!core.get_blocks().empty());
    
    // Verify sidecar loaded (symbol exists)
    assert(core.get_context().getSymbols().find("GameStart") != nullptr);
}

void test_core_virtual_files() {
    Core core;
    std::string content = "Virtual Content";
    core.add_virtual_file("vfile.txt", content);
    
    assert(core.exists("vfile.txt"));
    assert(core.file_size("vfile.txt") == content.size());
    
    std::vector<uint8_t> data;
    assert(core.read_file("vfile.txt", data));
    std::string read_content(data.begin(), data.end());
    assert(read_content == content);
}

void test_core_load_multiple_binaries() {
    Core core;
    
    std::ofstream bin1("part1.bin", std::ios::binary);
    bin1.put(0xAA);
    bin1.close();
    
    std::ofstream bin2("part2.bin", std::ios::binary);
    bin2.put(0xBB);
    bin2.close();
    
    std::vector<std::pair<std::string, uint16_t>> inputs;
    inputs.push_back({"part1.bin", 0x8000});
    inputs.push_back({"part2.bin", 0x9000});
    
    core.load_input_files(inputs);
    
    std::filesystem::remove("part1.bin");
    std::filesystem::remove("part2.bin");
    
    assert(core.get_memory().peek(0x8000) == 0xAA);
    assert(core.get_memory().peek(0x9000) == 0xBB);
    assert(core.get_blocks().size() == 2);
}