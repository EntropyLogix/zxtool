#include "BinFiles.h"
#include "../Core/Memory.h"
#include <fstream>
#include <stdexcept>

BinFiles::MemoryBlock BinFiles::load(const std::string& path, uint16_t start_address) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    std::vector<uint8_t> data = read_binary_file(path, file);
    if (data.empty()) {
        throw std::runtime_error("Could not read or file is empty: " + path);
    }

    for (size_t i = 0; i < data.size(); ++i) {
        m_bus.poke(start_address + i, data[i]);
    }

    return {start_address, static_cast<uint16_t>(data.size())};
}

void BinFiles::save(const std::string& path, const MemoryBlock& block) {
    std::ofstream file(path, std::ios::binary);
    for (uint16_t i = 0; i < block.size; ++i) {
        file.put(m_bus.peek(block.start_address + i));
    }
}

std::vector<uint8_t> BinFiles::read_binary_file(const std::string& path, std::ifstream& file) {
    if (!file) return {};
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

LoadResult BinFiles::load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) {
    try {
        auto block = load(filename, address);
        blocks.push_back({block.start_address, block.size, "Loaded from " + filename});
        return {true, block.start_address};
    } catch (...) {
        return {false, std::nullopt};
    }
}

std::vector<std::string> BinFiles::get_extensions() const {
    return { ".bin", "*" };
}