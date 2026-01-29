#include "Z80FormatTests.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <fstream>
#include <filesystem>
#include <sstream>
#include "../Core/Core.h"
#include "../Files/Z80Format.h"

#pragma pack(push, 1)
struct Z80Header {
    uint8_t A, F;
    uint16_t BC, HL, PC, SP;
    uint8_t I, R;
    uint8_t Flags1;
    uint16_t DE, BC_dash, DE_dash, HL_dash;
    uint8_t A_dash, F_dash;
    uint16_t IY, IX;
    uint8_t IFF1, IFF2, Flags2;
};
#pragma pack(pop)

void test_z80_load_v1_simple() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    Z80Header header = {};
    header.A = 0x11;
    header.F = 0x22;
    header.BC = 0x3344;
    header.HL = 0x5566;
    header.PC = 0x8000;
    header.SP = 0x9000;
    header.Flags1 = 0; // Uncompressed (bit 5 == 0)
    header.Flags2 = 0; // Interrupt mode 0

    std::ofstream out("test_v1.z80", std::ios::binary);
    out.write(reinterpret_cast<char*>(&header), sizeof(header));
    
    // Write some memory data starting at 16384 (0x4000)
    uint8_t data[] = { 0xAA, 0xBB, 0xCC };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    bool result = format.load_binary("test_v1.z80", blocks, 0);
    std::filesystem::remove("test_v1.z80");

    assert(result == true);
    
    auto& cpu = core.get_cpu();
    assert(cpu.get_A() == 0x11);
    assert(cpu.get_F() == 0x22);
    assert(cpu.get_BC() == 0x3344);
    assert(cpu.get_HL() == 0x5566);
    assert(cpu.get_PC() == 0x8000);
    assert(cpu.get_SP() == 0x9000);

    // Check memory at 16384 (0x4000)
    assert(core.get_memory().peek(16384) == 0xAA);
    assert(core.get_memory().peek(16385) == 0xBB);
    assert(core.get_memory().peek(16386) == 0xCC);
}

void test_z80_load_v1_compressed() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    Z80Header header = {};
    header.PC = 0x8000;
    header.Flags1 = 0x20; // Compressed (bit 5 == 1)

    std::ofstream out("test_v1_comp.z80", std::ios::binary);
    out.write(reinterpret_cast<char*>(&header), sizeof(header));
    
    // Compression: ED ED 05 AA -> 5 * AA
    uint8_t data[] = { 0xED, 0xED, 0x05, 0xAA };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    
    // End marker 00 ED ED 00
    uint8_t end_marker[] = { 0x00, 0xED, 0xED, 0x00 };
    out.write(reinterpret_cast<char*>(end_marker), sizeof(end_marker));
    out.close();

    bool result = format.load_binary("test_v1_comp.z80", blocks, 0);
    std::filesystem::remove("test_v1_comp.z80");

    assert(result == true);
    
    for(int i=0; i<5; ++i) {
        assert(core.get_memory().peek(16384 + i) == 0xAA);
    }
}

void test_z80_load_file_not_found() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("non_existent.z80", blocks, 0);

    std::cerr.rdbuf(old_cerr);

    assert(result == false);
}

void test_z80_load_too_small() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    std::ofstream out("small.z80", std::ios::binary);
    uint8_t data[] = { 0x00, 0x00 }; // Less than header size (30)
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("small.z80", blocks, 0);

    std::cerr.rdbuf(old_cerr);
    std::filesystem::remove("small.z80");

    assert(result == false);
}

void test_z80_load_v2_minimal() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    // Construct minimal V2 header
    Z80Header header = {};
    header.PC = 0; // Signals V2/V3
    
    std::ofstream out("test_v2.z80", std::ios::binary);
    out.write(reinterpret_cast<char*>(&header), sizeof(header));

    // Extended Header Length (2 bytes) - 23 bytes is standard for V2
    uint16_t ext_len = 23;
    out.write(reinterpret_cast<char*>(&ext_len), 2);

    // PC (2 bytes)
    uint16_t pc = 0x8000;
    out.write(reinterpret_cast<char*>(&pc), 2);

    // Hardware Mode (1 byte) - 0 = 48K
    uint8_t hw_mode = 0;
    out.write(reinterpret_cast<char*>(&hw_mode), 1);

    // Padding for the rest of extended header (23 - 2 - 1 = 20 bytes)
    std::vector<char> padding(20, 0);
    out.write(padding.data(), padding.size());

    // Memory Block Header
    // Length (2 bytes) - 0xFFFF for uncompressed
    uint16_t block_len = 0xFFFF;
    out.write(reinterpret_cast<char*>(&block_len), 2);
    
    // Page ID (1 byte) - 8 maps to 0x4000 in 48K mode
    uint8_t page_id = 8; 
    out.write(reinterpret_cast<char*>(&page_id), 1);

    // Data (16384 bytes for full page)
    std::vector<char> page_data(16384, 0xAA);
    out.write(page_data.data(), page_data.size());

    out.close();

    bool result = format.load_binary("test_v2.z80", blocks, 0);
    std::filesystem::remove("test_v2.z80");

    assert(result == true);
    assert(core.get_cpu().get_PC() == 0x8000);
    assert(core.get_memory().peek(0x4000) == 0xAA);
}

void test_z80_load_v2_truncated_header() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    Z80Header header = {};
    header.PC = 0; // Signals V2/V3

    std::ofstream out("test_v2_trunc.z80", std::ios::binary);
    out.write(reinterpret_cast<char*>(&header), sizeof(header));
    // No extended header length written, file ends abruptly
    out.close();

    // Suppress stderr
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("test_v2_trunc.z80", blocks, 0);

    std::cerr.rdbuf(old_cerr);
    std::filesystem::remove("test_v2_trunc.z80");

    assert(result == false);
}

void test_z80_load_v2_truncated_ext_header() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    Z80Header header = {};
    header.PC = 0; // Signals V2/V3

    std::ofstream out("test_v2_trunc_ext.z80", std::ios::binary);
    out.write(reinterpret_cast<char*>(&header), sizeof(header));
    
    uint16_t ext_len = 50;
    out.write(reinterpret_cast<char*>(&ext_len), 2);
    
    // Write fewer bytes than ext_len specifies
    uint8_t dummy = 0;
    out.write(reinterpret_cast<char*>(&dummy), 1);
    
    out.close();

    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("test_v2_trunc_ext.z80", blocks, 0);

    std::cerr.rdbuf(old_cerr);
    std::filesystem::remove("test_v2_trunc_ext.z80");

    assert(result == false);
}

void test_z80_load_v1_corrupt_compressed() {
    Core core;
    Z80Format format(core);
    std::vector<FileFormat::Block> blocks;

    Z80Header header = {};
    header.PC = 0x8000;
    header.Flags1 = 0x20; // Compressed

    std::ofstream out("test_v1_corrupt.z80", std::ios::binary);
    out.write(reinterpret_cast<char*>(&header), sizeof(header));
    
    // Corrupt compression sequence: ED ED (missing count/value)
    uint8_t data[] = { 0xED, 0xED };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    bool result = format.load_binary("test_v1_corrupt.z80", blocks, 0);
    std::filesystem::remove("test_v1_corrupt.z80");

    // Should handle gracefully (partial load or success with what was read)
    assert(result == true);
}