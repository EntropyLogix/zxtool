#include "BinaryFormatTests.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <fstream>
#include <filesystem>
#include "../Core/Memory.h"
#include "../Files/BinaryFormat.h"

void test_bin_load_simple() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    // Create a dummy binary file
    std::ofstream out("test_simple.bin", std::ios::binary);
    uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    bool result = format.load_binary("test_simple.bin", blocks, 0x8000);
    std::filesystem::remove("test_simple.bin");

    assert(result == true);
    assert(blocks.size() == 1);
    assert(blocks[0].start == 0x8000);
    assert(blocks[0].size == 4);
    
    assert(memory.peek(0x8000) == 0x01);
    assert(memory.peek(0x8001) == 0x02);
    assert(memory.peek(0x8002) == 0x03);
    assert(memory.peek(0x8003) == 0x04);
}

void test_bin_load_file_not_found() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    // Suppress stderr
    std::stringstream null_ss;
    std::streambuf* old_cerr = std::cerr.rdbuf(null_ss.rdbuf());

    bool result = format.load_binary("non_existent.bin", blocks, 0x0000);

    std::cerr.rdbuf(old_cerr);

    assert(result == false);
}

void test_bin_save_and_load() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    // Populate memory
    memory.poke(0xC000, 0xAA);
    memory.poke(0xC001, 0xBB);
    memory.poke(0xC002, 0xCC);

    // Save
    format.save("test_save.bin", 0xC000, 3);

    // Clear memory
    memory.poke(0xC000, 0x00);
    memory.poke(0xC001, 0x00);
    memory.poke(0xC002, 0x00);

    // Load back
    bool result = format.load_binary("test_save.bin", blocks, 0xC000);
    std::filesystem::remove("test_save.bin");

    assert(result == true);
    assert(memory.peek(0xC000) == 0xAA);
    assert(memory.peek(0xC001) == 0xBB);
    assert(memory.peek(0xC002) == 0xCC);
}

void test_bin_load_offset() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    std::ofstream out("test_offset.bin", std::ios::binary);
    uint8_t data[] = { 0xFF, 0xFE };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    bool result = format.load_binary("test_offset.bin", blocks, 0x4000);
    std::filesystem::remove("test_offset.bin");

    assert(result == true);
    assert(memory.peek(0x4000) == 0xFF);
    assert(memory.peek(0x4001) == 0xFE);
}

void test_bin_load_empty() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    std::ofstream out("empty.bin", std::ios::binary);
    out.close();

    bool result = format.load_binary("empty.bin", blocks, 0x8000);
    std::filesystem::remove("empty.bin");

    assert(result == true);
    assert(blocks.empty());
}

void test_bin_load_overwrite() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    // Pre-fill memory
    memory.poke(0x8000, 0xAA);
    memory.poke(0x8001, 0xBB);

    std::ofstream out("overwrite.bin", std::ios::binary);
    uint8_t data[] = { 0xCC };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    bool result = format.load_binary("overwrite.bin", blocks, 0x8000);
    std::filesystem::remove("overwrite.bin");

    assert(result == true);
    assert(memory.peek(0x8000) == 0xCC);
    assert(memory.peek(0x8001) == 0xBB);
}

void test_bin_load_wrap_around() {
    Memory memory;
    BinaryFormat format(memory);
    std::vector<FileFormat::Block> blocks;

    std::ofstream out("wrap.bin", std::ios::binary);
    uint8_t data[] = { 0x11, 0x22 };
    out.write(reinterpret_cast<char*>(data), sizeof(data));
    out.close();

    bool result = format.load_binary("wrap.bin", blocks, 0xFFFF);
    std::filesystem::remove("wrap.bin");

    assert(result == true);
    assert(memory.peek(0xFFFF) == 0x11);
    assert(memory.peek(0x0000) == 0x22);
}