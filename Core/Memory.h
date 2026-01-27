#ifndef __MEMORY_H__
#define __MEMORY_H__

#include "CoreIncludes.h"
#include <vector>
#include <cstring>
#include <algorithm>

class Memory {
public:
    class Map {
    public:
        enum class Flags : uint8_t {
            None = 0,
            Opcode = 1 << 0,
            Operand = 1 << 1,
            Data = 1 << 2,
            Read = 1 << 3,
            Write = 1 << 4,
            Execute = 1 << 5
        };

        Map() {
            m_data.resize(0x10000, (uint8_t)Flags::None);
        }

        uint8_t& operator[](size_t address) {
            return m_data[address & 0xFFFF];
        }

        const uint8_t& operator[](size_t address) const {
            return m_data[address & 0xFFFF];
        }

        void reset() {
            std::fill(m_data.begin(), m_data.end(), (uint8_t)Flags::None);
        }

        std::vector<uint8_t>& data() { return m_data; }
        const std::vector<uint8_t>& data() const { return m_data; }

    private:
        std::vector<uint8_t> m_data;
    };

    Memory() {
        m_ram.resize(0x10000, 0);
    }
    template <typename TEvents, typename TDebugger> void connect(Z80<Memory, TEvents, TDebugger>* cpu) {
    }
    void reset() {
        std::fill(m_ram.begin(), m_ram.end(), 0);
        m_map.reset();
    }
    uint8_t read(size_t address) {
        return m_ram[address & 0xFFFF];
    }
    void write(size_t address, uint8_t value) {
        m_ram[address & 0xFFFF] = value;
    }
    uint8_t peek(size_t address) const {
        return m_ram[address & 0xFFFF];
    }
    void poke(size_t address, uint8_t value) {
        m_ram[address & 0xFFFF] = value;
    }
    void poke(size_t address, const std::vector<uint8_t>& data) {
        size_t size = data.size();
        if (size == 0) return;
        size_t current_addr = address & 0xFFFF;
        size_t offset = 0;
        while (size > 0) {
            size_t chunk = std::min(size, m_ram.size() - current_addr);
            std::memcpy(m_ram.data() + current_addr, data.data() + offset, chunk);
            size -= chunk;
            offset += chunk;
            current_addr = 0;
        }
    }
    std::vector<uint8_t> peek(size_t address, size_t size) const {
        std::vector<uint8_t> result(size);
        size_t current_addr = address & 0xFFFF;
        size_t offset = 0;
        while (size > 0) {
            size_t chunk = std::min(size, m_ram.size() - current_addr);
            std::memcpy(result.data() + offset, m_ram.data() + current_addr, chunk);
            size -= chunk;
            offset += chunk;
            current_addr = 0;
        }
        return result;
    }
    uint8_t in(uint16_t port) {
        return 0xFF;
    }
    void out(uint16_t port, uint8_t value) { 
    }

    Map& getMap() { return m_map; }
    const Map& getMap() const { return m_map; }

private:
    std::vector<uint8_t> m_ram;
    Map m_map;
};

#endif//__MEMORY_H__