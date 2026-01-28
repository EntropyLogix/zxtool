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
        
        static constexpr uint8_t FLAG_NONE = (uint8_t)Flags::None;
        static constexpr uint8_t FLAG_CODE_START = (uint8_t)Flags::Opcode;
        static constexpr uint8_t FLAG_CODE_INTERIOR = (uint8_t)Flags::Operand;
        static constexpr uint8_t FLAG_DATA_READ = (uint8_t)Flags::Read;
        static constexpr uint8_t FLAG_DATA_WRITE = (uint8_t)Flags::Write;
        static constexpr uint8_t FLAG_EXECUTED = (uint8_t)Flags::Execute;

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

        size_t size() const { return m_data.size(); }

        size_t mark_code(uint16_t address, size_t length, bool set) {
            if (m_data.empty()) return 0;
            size_t sz = m_data.size();
            if (length == 0) return 0;
            size_t changed = 0;
            for (size_t i = 0; i < length; ++i) {
                size_t idx = (address + i) % sz;
                uint8_t old_val = m_data[idx];
                uint8_t val = old_val & ~((uint8_t)Flags::Opcode | (uint8_t)Flags::Operand);
                if (set) {
                    if (i == 0) val |= (uint8_t)Flags::Opcode;
                    else val |= (uint8_t)Flags::Operand;
                }
                if (val != old_val) {
                    m_data[idx] = val;
                    changed++;
                }
            }
            changed += cleanup_orphans(address + length);
            return changed;
        }

        size_t mark_data(uint16_t address, size_t length, bool write, bool set) {
            if (m_data.empty()) return 0;
            size_t sz = m_data.size();
            uint8_t flag = write ? (uint8_t)Flags::Write : (uint8_t)Flags::Read;
            size_t changed = 0;
            for (size_t i = 0; i < length; ++i) {
                size_t idx = (address + i) % sz;
                uint8_t old_val = m_data[idx];
                uint8_t val = old_val;
                if (set) val |= flag;
                else val &= ~flag;
                if (val != old_val) {
                    m_data[idx] = val;
                    changed++;
                }
            }
            return changed;
        }

        size_t mark_executed(uint16_t address, bool set) {
            if (m_data.empty()) return 0;
            size_t sz = m_data.size();
            size_t idx = address % sz;
            uint8_t old_val = m_data[idx];
            uint8_t val = old_val;
            if (set) val |= (uint8_t)Flags::Execute;
            else val &= ~(uint8_t)Flags::Execute;
            if (val != old_val) {
                m_data[idx] = val;
                return 1;
            }
            return 0;
        }

        void invalidate_region(uint16_t start, size_t length) {
            size_t sz = m_data.size();
            for (size_t i = 0; i < length; ++i) {
                m_data[(start + i) % sz] &= ~((uint8_t)Flags::Opcode | (uint8_t)Flags::Operand);
            }
            cleanup_orphans(start + length);
        }

        void import(const std::vector<uint8_t>& source_map) {
            size_t len = std::min(m_data.size(), source_map.size());
            for (size_t i = 0; i < len; ++i) {
                if (source_map[i] != 0)
                    m_data[i] = source_map[i];
            }
        }

    private:
        std::vector<uint8_t> m_data;

        size_t cleanup_orphans(uint32_t start_index) {
            if (m_data.empty()) return 0;
            size_t sz = m_data.size();
            size_t count = 0;
            size_t changed = 0;
            while (count < sz) {
                size_t idx = start_index % sz;
                uint8_t old_val = m_data[idx];
                if ((old_val & (uint8_t)Flags::Operand) && !(old_val & (uint8_t)Flags::Opcode)) {
                    uint8_t val = old_val & ~(uint8_t)Flags::Operand;
                    if (val != old_val) {
                        m_data[idx] = val;
                        changed++;
                    }
                    start_index++;
                    count++;
                } else {
                    break;
                }
            }
            return changed;
        }
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