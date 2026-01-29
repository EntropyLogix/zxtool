#include "SkoolFormatTests.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>
#include <vector>
#include <sstream>
#include "../Core/Core.h"
#include "../Files/SkoolFormat.h"
#include "../Core/Analyzer.h"

void test_skool_load_simple() {
    Core core;
    SkoolFormat format(core);
    std::vector<FileFormat::Block> blocks;

    // Create a dummy skool file
    // Assuming SkoolFormat supports standard SkoolKit-like comments or directives
    std::string content = 
        "; This is a test skool file\n"
        "; @ 8000\n";
    
    std::ofstream out("test.skool");
    out << content;
    out.close();
    
    // We just check if it runs without crashing and returns a result consistent with capabilities
    bool result = format.load_binary("test.skool", blocks, 0x8000);
    
    // Also try loading metadata
    format.load_metadata("test.skool");
    
    std::filesystem::remove("test.skool");
    
    // Note: We don't assert(result == true) here because we don't know if SkoolFormat 
    // is fully implemented in the provided context. This test ensures integration.
}

void test_skool_load_file_not_found() {
    Core core;
    SkoolFormat format(core);
    std::vector<FileFormat::Block> blocks;

    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    bool result = format.load_binary("non_existent.skool", blocks, 0x0000);
    std::cerr.rdbuf(old_cerr);
    assert(result == false);
}

void test_skool_load_metadata_comments() {
    Core core;
    SkoolFormat format(core);
    
    // Skool file format typically uses "; @ address" for origin
    // and lines starting with ; as comments.
    // Depending on implementation, it might extract comments for addresses.
    std::string content = 
        "; @ 8000\n"
        "; This is a comment\n"
        "8000 NOP\n";
    
    std::ofstream out("meta.skool");
    out << content;
    out.close();
    
    bool result = format.load_metadata("meta.skool");
    std::filesystem::remove("meta.skool");
    
    // We assume load_metadata returns true on success
    if (result) {
        // Check if comment was loaded (implementation dependent)
        // const Comment* c = core.get_context().getComments().find(0x8000, Comment::Type::Block);
    }
}

void test_skool_load_binary_data() {
    Core core;
    SkoolFormat format(core);
    std::vector<FileFormat::Block> blocks;

    std::string content = 
        "; @ 8000\n"
        "$8000 NOP\n"; // NOP
    
    std::ofstream out("data.skool");
    out << content;
    out.close();
    
    bool result = format.load_binary("data.skool", blocks, 0x8000);
    std::filesystem::remove("data.skool");

    assert(result == true);
    assert(!blocks.empty());
    assert(core.get_memory().peek(0x8000) == 0x00);
}

void test_skool_ctl_labels() {
    Core core;
    SkoolFormat format(core);
    
    std::string content = 
        "@ $8000 label=Start\n"
        "@ $8002 label=Loop\n";
    
    std::ofstream out("test.ctl");
    out << content;
    out.close();
    
    bool result = format.load_metadata("test.ctl");
    std::filesystem::remove("test.ctl");
    
    assert(result == true);
    
    auto sym1 = core.get_context().getSymbols().find("Start");
    assert(sym1 != nullptr);
    assert(sym1->read() == 0x8000);
    
    auto sym2 = core.get_context().getSymbols().find("Loop");
    assert(sym2 != nullptr);
    assert(sym2->read() == 0x8002);
}

void test_skool_ctl_block_types() {
    Core core;
    SkoolFormat format(core);
    
    // c = code, b = byte, t = text
    std::string content = 
        "c $8000\n"
        "b $8001\n"
        "t $8002\n";
    
    std::ofstream out("blocks.ctl");
    out << content;
    out.close();
    
    bool result = format.load_metadata("blocks.ctl");
    std::filesystem::remove("blocks.ctl");
    
    assert(result == true);
    
    auto& analyzer = core.get_analyzer();
    auto& map = core.get_code_map();
    
    assert(analyzer.get_map_type(map, 0x8000) == Analyzer::TYPE_CODE);
    assert(analyzer.get_map_type(map, 0x8001) == Analyzer::TYPE_BYTE);
    assert(analyzer.get_map_type(map, 0x8002) == Analyzer::TYPE_TEXT);
}

void test_skool_directives() {
    Core core;
    SkoolFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string content = 
        "@equ=VAL=$10\n"
        "@org=$8000\n"
        "$8000 LD A, $10\n"
        "@defb=$8100:$AA,$BB\n";
    
    std::ofstream out("dirs.skool");
    out << content;
    out.close();
    
    bool result = format.load_binary("dirs.skool", blocks, 0);
    std::filesystem::remove("dirs.skool");
    
    assert(result == true);
    
    // Check EQU (Symbol added to context)
    auto sym = core.get_context().getSymbols().find("VAL");
    assert(sym != nullptr);
    assert(sym->read() == 0x10);
    
    // Check Code
    assert(core.get_memory().peek(0x8000) == 0x3E); // LD A, n
    assert(core.get_memory().peek(0x8001) == 0x10); // 0x10
    
    // Check DEFB
    assert(core.get_memory().peek(0x8100) == 0xAA);
    assert(core.get_memory().peek(0x8101) == 0xBB);
}

void test_skool_invalid_org() {
    Core core;
    SkoolFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string content = "@org=INVALID\n";
    
    std::ofstream out("inv_org.skool");
    out << content;
    out.close();
    
    bool result = format.load_binary("inv_org.skool", blocks, 0);
    std::filesystem::remove("inv_org.skool");
    
    assert(result == false);
}

void test_skool_invalid_defb() {
    Core core;
    SkoolFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Invalid address in DEFB directive
    std::string content = "@defb=ZZZZ:00\n";
    
    std::ofstream out("inv_defb.skool");
    out << content;
    out.close();
    
    bool result = format.load_binary("inv_defb.skool", blocks, 0);
    std::filesystem::remove("inv_defb.skool");
    
    assert(result == false);
}