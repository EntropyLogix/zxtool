#ifndef __MEMORY_H__
#define __MEMORY_H__

#define Z80_ENABLE_EXEC_API
#include "Z80.h"
class Memory {
public:
    Memory() {
        m_ram.resize(0x10000, 0);
    }
    template <typename TEvents, typename TDebugger> void connect(Z80<Memory, TEvents, TDebugger>* cpu) {
    }
    void reset() {
        std::fill(m_ram.begin(), m_ram.end(), 0);
    }
    uint8_t read(uint16_t address) {
        return m_ram[address];
    }
    void write(uint16_t address, uint8_t value) {
        m_ram[address] = value;
    }
    uint8_t peek(uint16_t address) const {
        return m_ram[address];
    }
    void poke(uint16_t address, uint8_t value) {
        m_ram[address] = value;
    }
    uint8_t in(uint16_t port) {
        return 0xFF;
    }
    void out(uint16_t port, uint8_t value) { 
    }

private:
    std::vector<uint8_t> m_ram;
};

#endif//__MEMORY_H__