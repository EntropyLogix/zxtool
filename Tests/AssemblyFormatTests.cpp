#include "AssemblyFormatTests.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <sstream>
#include "../Core/Core.h"
#include "../Files/AssemblyFormat.h"

void test_load_binary_simple() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Setup virtual file
    std::string code = "ORG 0x8000\nStart: LD A, 10\n";
    core.add_virtual_file("test.asm", code);
    
    // Test load
    bool result = format.load_binary("test.asm", blocks, 0x8000);
    
    assert(result == true);
    assert(blocks.size() == 1);
    assert(blocks[0].start == 0x8000);
    assert(blocks[0].size == 2); // LD A, n is 2 bytes
    
    // Verify memory
    assert(core.get_memory().peek(0x8000) == 0x3E); // LD A, n opcode
    assert(core.get_memory().peek(0x8001) == 10);   // Operand
    
    // Verify symbols
    auto sym = core.get_context().getSymbols().find("Start");
    assert(sym != nullptr);
    assert(sym->read() == 0x8000);
}

void test_load_binary_comments() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nLD A, 10 ; Load 10 into A\n";
    core.add_virtual_file("comments.asm", code);
    
    bool result = format.load_binary("comments.asm", blocks, 0x8000);
    assert(result == true);
    
    // Verify comments
    // AssemblyFormat adds the trimmed content of the source line as an inline comment.
    // Note: Z80Assembler strips comments from 'content' if comments are enabled.
    const Comment* c = core.get_context().getComments().find(0x8000, Comment::Type::Inline);
    assert(c != nullptr);
    assert(c->getText() == "Load 10 into A"); 
}

void test_load_binary_fail() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "INVALID_INSTRUCTION\n";
    core.add_virtual_file("fail.asm", code);
    
    // Suppress stderr for this test
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    bool result = format.load_binary("fail.asm", blocks, 0x0000);
    
    std::cerr.rdbuf(old_cerr);
    
    assert(result == false);
    assert(blocks.empty());
}

void test_load_binary_file_not_found() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Suppress stderr for this test
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    // Ensure file doesn't exist
    bool result = format.load_binary("non_existent_file.asm", blocks, 0x0000);
    
    std::cerr.rdbuf(old_cerr);

    assert(result == false);
    assert(blocks.empty());
}

void test_load_binary_labels() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nLabel1: NOP\nLabel2: RET\n";
    core.add_virtual_file("labels.asm", code);
    
    bool result = format.load_binary("labels.asm", blocks, 0x8000);
    assert(result == true);
    
    auto sym1 = core.get_context().getSymbols().find("Label1");
    assert(sym1 != nullptr);
    assert(sym1->read() == 0x8000);
    
    auto sym2 = core.get_context().getSymbols().find("Label2");
    assert(sym2 != nullptr);
    assert(sym2->read() == 0x8001);
}

void test_load_binary_data_directives() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x9000\nDB 0x01, 0x02\nDW 0x1234\nDS 2, 0xFF\n";
    core.add_virtual_file("data.asm", code);
    
    bool result = format.load_binary("data.asm", blocks, 0x9000);
    assert(result == true);
    
    // DB 0x01, 0x02
    assert(core.get_memory().peek(0x9000) == 0x01);
    assert(core.get_memory().peek(0x9001) == 0x02);
    
    // DW 0x1234 (Little Endian: 34 12)
    assert(core.get_memory().peek(0x9002) == 0x34);
    assert(core.get_memory().peek(0x9003) == 0x12);
    
    // DS 2, 0xFF
    assert(core.get_memory().peek(0x9004) == 0xFF);
    assert(core.get_memory().peek(0x9005) == 0xFF);
}

void test_load_binary_constants() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "VAL EQU 10\nORG 0x8000\nLD A, VAL\n";
    core.add_virtual_file("const.asm", code);
    
    bool result = format.load_binary("const.asm", blocks, 0x8000);
    assert(result == true);
    
    // LD A, 10 -> 3E 0A
    assert(core.get_memory().peek(0x8000) == 0x3E);
    assert(core.get_memory().peek(0x8001) == 10);
    
    auto sym = core.get_context().getSymbols().find("VAL");
    assert(sym != nullptr);
    assert(sym->read() == 10);
    assert(sym->getType() == Symbol::Type::Constant);
}

void test_load_binary_multiple_org() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nNOP\nORG 0x9000\nRET\n";
    core.add_virtual_file("multi_org.asm", code);
    
    bool result = format.load_binary("multi_org.asm", blocks, 0x0000);
    assert(result == true);
    
    // Should produce two blocks (or one merged if contiguous logic isn't strict, but here they are far apart)
    // AssemblyFormat populates blocks based on assembler output blocks.
    // Z80Assembler usually produces separate blocks for non-contiguous ORGs.
    
    // Check memory content
    assert(core.get_memory().peek(0x8000) == 0x00); // NOP
    assert(core.get_memory().peek(0x9000) == 0xC9); // RET
    
    // Check blocks
    // Note: Implementation detail of Z80Assembler might merge or split blocks.
    // Assuming it produces blocks for each section.
    bool found8000 = false;
    bool found9000 = false;
    for(const auto& b : blocks) {
        if (b.start == 0x8000) found8000 = true;
        if (b.start == 0x9000) found9000 = true;
    }
    assert(found8000);
    assert(found9000);
}

void test_load_binary_syntax_error() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nLD A,\n"; // Missing operand
    core.add_virtual_file("syntax_error.asm", code);
    
    // Suppress stderr
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    bool result = format.load_binary("syntax_error.asm", blocks, 0x8000);
    
    std::cerr.rdbuf(old_cerr);
    
    assert(result == false);
    assert(blocks.empty());
}

void test_asm_load_metadata_simple() {
    Core core;
    AssemblyFormat format(core);
    
    std::string code = "ORG 0x8000\nMyLabel: EQU 0x1234\n";
    core.add_virtual_file("metadata.asm", code);
    
    // Memory should not be touched
    uint8_t mem_before = core.get_memory().peek(0x8000);

    bool result = format.load_metadata("metadata.asm");
    assert(result == true);
    
    // Verify memory is unchanged
    assert(core.get_memory().peek(0x8000) == mem_before);

    // Verify symbols
    auto sym = core.get_context().getSymbols().find("MyLabel");
    assert(sym != nullptr);
    assert(sym->read() == 0x1234);
    assert(sym->getType() == Symbol::Type::Constant);
}

void test_asm_load_binary_c_style_comments() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nLD A, 10 /* C-style comment */\n";
    core.add_virtual_file("c_comments.asm", code);
    
    bool result = format.load_binary("c_comments.asm", blocks, 0x8000);
    assert(result == true);
    
    // Verify comments
    const Comment* c = core.get_context().getComments().find(0x8000, Comment::Type::Inline);
    assert(c != nullptr);
    assert(c->getText() == "C-style comment"); 
}

void test_load_binary_unknown_mnemonic() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nUNKNOWN_INSTR A, B\n";
    core.add_virtual_file("unknown_instr.asm", code);
    
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    bool result = format.load_binary("unknown_instr.asm", blocks, 0x8000);
    
    std::cerr.rdbuf(old_cerr);
    
    assert(result == false);
}

void test_load_binary_invalid_directive() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string code = "ORG 0x8000\nINVALID_DIRECTIVE 123\n";
    core.add_virtual_file("invalid_dir.asm", code);
    
    // Note: Z80Assembler might treat unknown directives as labels if they are at the start of the line without indentation, 
    // or error if indented. Assuming standard parsing where unknown token is error or label.
    // If it's treated as a label, the next token '123' might be an error if no instruction follows.
    // Let's make it clearly invalid syntax for a label line: "  INVALID_DIRECTIVE" (indented)
    
    std::string code2 = "ORG 0x8000\n  INVALID_DIRECTIVE\n";
    core.add_virtual_file("invalid_dir2.asm", code2);

    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("invalid_dir2.asm", blocks, 0x8000);

    std::cerr.rdbuf(old_cerr);

    assert(result == false);
}

void test_asm_quotes_protection() {
    Core core;
    AssemblyFormat format(core);
    std::vector<FileFormat::Block> blocks;

    // Semicolon inside quotes should NOT be treated as comment start
    std::string content = 
        "    ORG 0x8000\n"
        "    LD A, ';'\n"  // ASCII 0x3B
        "    LD B, 0   ; Real comment\n";
    
    core.add_virtual_file("quotes.asm", content);
    bool result = format.load_binary("quotes.asm", blocks, 0);
    
    assert(result == true);
    assert(core.get_memory().peek(0x8000) == 0x3E); // LD A, n
    assert(core.get_memory().peek(0x8001) == 0x3B); // ';' literal
}