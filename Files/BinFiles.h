#ifndef __BINFILES_H__
#define __BINFILES_H__

#include <string>
#include <vector>
#include <fstream>
#include <cstdint>

class Memory;

class BinFiles {
public:
    struct MemoryBlock {
        uint16_t start_address;
        uint16_t size;
    };
    BinFiles(Memory& bus) : m_bus(bus) {}
    MemoryBlock load(const std::string& path, uint16_t address);
    void save(const std::string& path, const MemoryBlock& block);
private:
    Memory& m_bus;
    std::vector<uint8_t> read_binary_file(const std::string& path, std::ifstream& file);
};

#endif//__BINFILES_H__