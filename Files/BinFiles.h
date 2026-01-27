#ifndef __BINFILES_H__
#define __BINFILES_H__

#include <string>
#include <vector>
#include <fstream>
#include <cstdint>
#include "File.h"

class Memory;
class BinaryFormat : public FileFormat {
public:
    BinaryFormat(Memory& bus) : m_bus(bus) {}
    void save(const std::string& path, uint16_t address, uint16_t size);

    // FileFormat implementation
    bool load_binary(const std::string& filename, std::vector<Block>& blocks, uint16_t address) override;
    std::vector<std::string> get_extensions() const override { return { ".bin", "*" }; }
    
    uint32_t get_capabilities() const override { return LoadBinary; }

private:
    Memory& m_bus;
};

#endif//__BINFILES_H__