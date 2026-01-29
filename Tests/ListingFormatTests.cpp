#include "ListingFormatTests.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>
#include "../Core/Core.h"
#include "../Files/ListingFormat.h"

void test_lst_load_binary_simple() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Setup virtual file
    std::string lst_content = 
        "Line   Addr   Hex Code                Source Code\n"
        "--------------------------------------------------------------------------------\n"
        "1      8000   3E 0A                   LD A, 10\n"
        "2      8002   06 14                   LD B, 20\n";
    
    std::ofstream out("test.lst");
    out << lst_content;
    out.close();
    
    // Test load
    bool result = format.load_binary("test.lst", blocks, 0x8000);
    std::filesystem::remove("test.lst");
    
    assert(result == true);
    assert(blocks.size() == 1);
    assert(blocks[0].start == 0x8000);
    assert(blocks[0].size == 4); // 2 instructions, 2 bytes each
    
    // Verify memory
    assert(core.get_memory().peek(0x8000) == 0x3E); // LD A, n
    assert(core.get_memory().peek(0x8001) == 0x0A); // 10
    assert(core.get_memory().peek(0x8002) == 0x06); // LD B, n
    assert(core.get_memory().peek(0x8003) == 0x14); // 20
}

void test_lst_load_binary_comments() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string lst_content = 
        "Line   Addr   Hex Code                Source Code\n"
        "--------------------------------------------------------------------------------\n"
        "1      8000   3E 0A                   LD A, 10 ; Load 10 into A\n";
    
    std::ofstream out("comments.lst");
    out << lst_content;
    out.close();
    
    bool result = format.load_binary("comments.lst", blocks, 0x8000);
    std::filesystem::remove("comments.lst");
    assert(result == true);
    
    // Verify comments
    const Comment* c = core.get_context().getComments().find(0x8000, Comment::Type::Inline);
    assert(c != nullptr);
    assert(c->getText() == "Load 10 into A"); 
}

void test_lst_load_metadata() {
    Core core;
    ListingFormat format(core);
    
    std::string lst_content = 
        "Line   Addr   Hex Code                Source Code\n"
        "--------------------------------------------------------------------------------\n"
        "1      8000   3E 0A                   LD A, 10 ; Metadata comment\n";
    
    std::ofstream out("metadata.lst");
    out << lst_content;
    out.close();
    
    // Memory should not be touched by load_metadata (except maybe by side effects if it parses, but here we check comments)
    // Actually ListingFormat::load_metadata currently only extracts comments based on the implementation I added.
    
    bool result = format.load_metadata("metadata.lst");
    std::filesystem::remove("metadata.lst");
    assert(result == true);
    
    const Comment* c = core.get_context().getComments().find(0x8000, Comment::Type::Inline);
    assert(c != nullptr);
    assert(c->getText() == "Metadata comment");
}

void test_lst_parse_hex_address() {
    uint16_t addr;
    assert(ListingFormat::parse_hex_address("0000", addr) == true);
    assert(addr == 0x0000);
    
    assert(ListingFormat::parse_hex_address("FFFF", addr) == true);
    assert(addr == 0xFFFF);
    
    assert(ListingFormat::parse_hex_address("1234", addr) == true);
    assert(addr == 0x1234);
    
    assert(ListingFormat::parse_hex_address("G000", addr) == false);
    assert(ListingFormat::parse_hex_address("10000", addr) == false);
}

void test_lst_parse_line_fallback() {
    // This would require exposing parse_line_fallback or testing via load_binary with a malformed file.
    // For now, we rely on load_binary tests.
}

void test_lst_load_binary_only_comments() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string lst_content = 
        "Line   Addr   Hex Code                Source Code\n"
        "--------------------------------------------------------------------------------\n"
        "1                                     ; Just a comment\n"
        "2      8000   00                      NOP\n";
    
    std::ofstream out("only_comments.lst");
    out << lst_content;
    out.close();
    
    bool result = format.load_binary("only_comments.lst", blocks, 0x8000);
    std::filesystem::remove("only_comments.lst");
    assert(result == true);
    
    assert(core.get_memory().peek(0x8000) == 0x00);
}

void test_lst_load_binary_file_not_found() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Suppress stderr
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    bool result = format.load_binary("non_existent.lst", blocks, 0x8000);
    
    std::cerr.rdbuf(old_cerr);
    
    assert(result == false);
}

void test_lst_load_binary_garbage() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string content = "This is just random text.\nIt does not look like a listing.\n";
    std::ofstream out("garbage.lst");
    out << content;
    out.close();
    
    bool result = format.load_binary("garbage.lst", blocks, 0x8000);
    std::filesystem::remove("garbage.lst");
    
    assert(result == false);
    assert(blocks.empty());
}

void test_lst_load_binary_invalid_asm() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string content = "1 8000 00 LD A,\n";
    std::ofstream out("invalid_asm.lst");
    out << content;
    out.close();
    
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("invalid_asm.lst", blocks, 0x8000);
    
    std::cerr.rdbuf(old_cerr);
    std::filesystem::remove("invalid_asm.lst");
    
    assert(result == false);
}

void test_lst_load_binary_labels_only() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    std::string content = "1 8000 Label: EQU $\n";
    std::ofstream out("labels.lst");
    out << content;
    out.close();
    
    bool result = format.load_binary("labels.lst", blocks, 0x8000);
    std::filesystem::remove("labels.lst");
    
    assert(result == true);
    assert(blocks.empty());
    
    auto sym = core.get_context().getSymbols().find("Label");
    assert(sym != nullptr);
    assert(sym->read() == 0x8000);
}

void test_lst_load_binary_multiline_ds() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Test DS directive which generates many bytes.
    // The listing might show some bytes on continuation lines, but ListingFormat 
    // should rely on the source "DS 10, 0xAA" to regenerate them via assembler.
    std::string content = 
        "1      8000   AA AA AA AA             DS 10, 0xAA\n"
        "       8004   AA AA                   ; Continuation line in listing\n";
    
    std::ofstream out("multiline_ds.lst");
    out << content;
    out.close();
    
    bool result = format.load_binary("multiline_ds.lst", blocks, 0x8000);
    std::filesystem::remove("multiline_ds.lst");
    
    assert(result == true);
    assert(blocks.size() == 1);
    assert(blocks[0].size == 10);
    assert(core.get_memory().peek(0x8000) == 0xAA);
    assert(core.get_memory().peek(0x8009) == 0xAA);
}

void test_lst_load_binary_malformed_hex() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // "ZZ" in hex column is invalid. 
    // The parser fallback might treat "ZZ" as start of source code.
    // Reconstructed source: "ZZ 00 NOP" -> Assembler should fail (Invalid mnemonic).
    std::string content = "1      8000   ZZ 00                   NOP\n";
    std::ofstream out("malformed.lst");
    out << content;
    out.close();
    
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    bool result = format.load_binary("malformed.lst", blocks, 0x8000);
    
    std::cerr.rdbuf(old_cerr);
    std::filesystem::remove("malformed.lst");
    
    assert(result == false);
}

void test_lst_load_binary_tight_layout() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Tight layout without fixed columns (space separated)
    // Should be handled by parse_line_fallback
    std::string content = 
        "1 8000 00 NOP\n"
        "2 8001 C9 RET\n";
    std::ofstream out("tight.lst");
    out << content;
    out.close();
    
    bool result = format.load_binary("tight.lst", blocks, 0x8000);
    std::filesystem::remove("tight.lst");
    
    assert(result == true);
    assert(core.get_memory().peek(0x8000) == 0x00);
    assert(core.get_memory().peek(0x8001) == 0xC9);
}

void test_lst_load_binary_mixed_columns() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;
    
    // Line number, then something that looks like byte but is in address place?
    // 1 00 8000 NOP -> 00 parsed as address 0x0000. 8000 not hex byte. Source: "8000 NOP".
    // "8000 NOP" -> 8000 is invalid label (starts with digit). Assembler fails.
    std::string content = "1 00 8000 NOP\n";
    std::ofstream out("mixed.lst");
    out << content;
    out.close();
    
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());
    
    bool result = format.load_binary("mixed.lst", blocks, 0x8000);
    
    std::cerr.rdbuf(old_cerr);
    std::filesystem::remove("mixed.lst");
    
    assert(result == false);
}

void test_lst_include_handling() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;

    // ListingFormat should comment out INCLUDE directives to avoid re-inclusion
    // during reconstruction, assuming the bytes are already in the listing.
    std::string content = 
        "1 8000 00          INCLUDE \"lib.asm\"\n"
        "2 8001 00          NOP\n";
    
    std::ofstream out("include.lst");
    out << content;
    out.close();

    bool result = format.load_binary("include.lst", blocks, 0x8000);
    std::filesystem::remove("include.lst");

    assert(result == true);
    // If INCLUDE wasn't commented out, assembler would fail finding "lib.asm"
}

void test_lst_macro_skip() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;

    // Lines starting with + (macro expansion) should be skipped
    std::string content = 
        "1 8000 00          NOP\n"
        "  8001 00        + NOP\n"; // Should be ignored by parser
    
    std::ofstream out("macro.lst");
    out << content;
    out.close();

    bool result = format.load_binary("macro.lst", blocks, 0x8000);
    std::filesystem::remove("macro.lst");

    assert(result == true);
    // Only one NOP should be loaded if the second line is skipped
    // However, ListingFormat logic skips the *source* reconstruction for +, 
    // but might still parse bytes if they are in columns. 
    // In the implementation: if (!trimmed_source.empty() && trimmed_source[0] == '+') continue;
    // This happens after reading the line. If the line has bytes, they are read in read_lst_line.
    // But load_binary loop calls read_lst_line then checks source.
    // If it continues, it skips adding to asm_src.
}

void test_lst_hex_continuation() {
    Core core;
    ListingFormat format(core);
    std::vector<FileFormat::Block> blocks;

    std::string content = 
        "1 8000 01 02       DB 0x01, 0x02, 0x03, 0x04\n"
        "       03 04\n"; // Continuation line
    
    std::ofstream out("cont.lst");
    out << content;
    out.close();

    bool result = format.load_binary("cont.lst", blocks, 0x8000);
    std::filesystem::remove("cont.lst");

    assert(result == true);
    assert(core.get_memory().peek(0x8000) == 0x01);
    assert(core.get_memory().peek(0x8001) == 0x02);
    // These bytes come from the assembler reconstructing the source "DB ...", 
    // but the test ensures the parser didn't choke on the continuation line.
}