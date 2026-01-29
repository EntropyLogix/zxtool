#include "BinaryFormat.h"
#include "../Core/Memory.h"
#include <fstream>
#include <stdexcept>

void BinaryFormat::save(const std::string& path, uint16_t address, uint16_t size) {
    std::ofstream file(path, std::ios::binary);
    std::vector<uint8_t> data = m_bus.peek(address, size);
    file.write((char*)(data.data()), data.size());
}

bool BinaryFormat::load_binary(const std::string& filename, std::vector<FileFormat::Block>& blocks, uint16_t address) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
        return false;
    std::streamsize size = file.tellg();
    if (size < 0)
        return false;
    if (size == 0)
        return true;
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(size);
    if (!file.read((char*)(data.data()), size))
        return false;
    m_bus.poke(address, data);
    blocks.push_back({address, static_cast<uint16_t>(data.size()), "Loaded from " + filename});
    return true;
}
