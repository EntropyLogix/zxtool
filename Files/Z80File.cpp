#include "Z80File.h"
#include "../Core/Core.h"
#include <fstream>
#include <vector>
#include <iostream>
#include <cstdint>
#include <iomanip>

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

Z80Format::Z80Format(Core& core) : m_core(core) {}

bool Z80Format::load_binary(const std::string& filename, std::vector<FileFormat::Block>& blocks, uint16_t address) {
    if (load(m_core, filename)) {
        uint16_t pc = m_core.get_cpu().get_PC();
        blocks.push_back({pc, 0, "Loaded Z80 snapshot: " + filename});
        return true;
    }
    return false;
}

bool Z80Format::load(Core& core, const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Error: Could not read file data." << std::endl;
        return false;
    }

    if (data.size() < sizeof(Z80Header)) {
        std::cerr << "Error: File size too small for Z80 header." << std::endl;
        return false;
    }

    const Z80Header* header = reinterpret_cast<const Z80Header*>(data.data());
    auto& cpu = core.get_cpu();
    auto& mem = core.get_memory();

    // Ustawienie rejestrów głównych
    cpu.set_A(header->A);
    cpu.set_F(header->F);
    cpu.set_BC(header->BC);
    cpu.set_HL(header->HL);
    cpu.set_PC(header->PC);
    cpu.set_SP(header->SP);
    cpu.set_I(header->I);
    cpu.set_R(header->R);
    cpu.set_DE(header->DE);
    cpu.set_IX(header->IX);
    cpu.set_IY(header->IY);

    // Ustawienie rejestrów alternatywnych
    cpu.set_BCp(header->BC_dash);
    cpu.set_DEp(header->DE_dash);
    cpu.set_HLp(header->HL_dash);
    cpu.set_AFp((static_cast<uint16_t>(header->A_dash) << 8) | header->F_dash);

    cpu.set_IFF1(header->IFF1 != 0);
    cpu.set_IFF2(header->IFF2 != 0);
    cpu.set_IRQ_mode(header->Flags2 & 0x03);

    size_t offset = sizeof(Z80Header);

    if (header->PC == 0) {
        // Wersja 2 lub 3 formatu Z80
        if (offset + 2 > data.size()) {
            std::cerr << "Error: Invalid Z80 v2/v3 header structure." << std::endl;
            return false;
        }
        uint16_t header_len = data[offset] | (data[offset+1] << 8);
        offset += 2;
        
        if (offset + header_len > data.size()) {
            std::cerr << "Error: Invalid Z80 v2/v3 extended header length." << std::endl;
            return false;
        }
        
        // PC z dodatkowego nagłówka
        if (header_len >= 2) {
            cpu.set_PC(data[offset] | (data[offset+1] << 8));
        }

        int hardware_mode = 0;
        if (header_len >= 3) {
            hardware_mode = data[offset+2];
        }
        offset += header_len;
        
        // Pętla po blokach pamięci
        while (offset < data.size()) {
            if (offset + 3 > data.size()) break;
            uint16_t block_len = data[offset] | (data[offset+1] << 8);
            offset += 2;
            
            uint8_t page_id = data[offset++];
            
            uint16_t dest_addr = 0;
            
            if (hardware_mode <= 1) { // 48K lub 48K + Interface 1
                if (page_id == 4) dest_addr = 0x8000;
                else if (page_id == 5) dest_addr = 0xC000;
                else if (page_id == 8) dest_addr = 0x4000;
            } else { // 128K i inne
                if (page_id == 8) dest_addr = 0x4000;      // Bank 5
                else if (page_id == 5) dest_addr = 0x8000; // Bank 2
                else if (page_id == 3) dest_addr = 0xC000; // Bank 0 (domyślny)
            }
            
            if (dest_addr != 0) {
                if (block_len == 0xFFFF) {
                    // Nieskompresowane
                    if (offset + 16384 > data.size()) break;
                    for (int i = 0; i < 16384; ++i) mem.write(dest_addr + i, data[offset++]);
                } else {
                    // Skompresowane
                    size_t block_end = offset + block_len;
                    if (block_end > data.size()) break;
                    
                    uint16_t current_addr = dest_addr;
                    while (offset < block_end) {
                        uint8_t byte = data[offset++];
                        if (byte == 0xED) {
                            if (offset >= block_end) { mem.write(current_addr++, byte); break; }
                            uint8_t next = data[offset++];
                            if (next == 0xED) {
                                if (offset + 1 >= block_end) break;
                                uint8_t count = data[offset++];
                                uint8_t val = data[offset++];
                                for (int i = 0; i < count; ++i) mem.write(current_addr++, val);
                            } else {
                                mem.write(current_addr++, byte);
                                mem.write(current_addr++, next);
                            }
                        } else {
                            mem.write(current_addr++, byte);
                        }
                    }
                    offset = block_end;
                }
            } else {
                // Pomiń nieobsługiwany blok
                if (block_len == 0xFFFF) offset += 16384;
                else offset += block_len;
            }
        }
    } else {
        // Wersja 1 formatu Z80
        bool compressed = (header->Flags1 & 0x20) != 0;
        uint16_t addr = 16384; // Standardowy start RAM dla 48K

        if (compressed) {
            while (offset < data.size()) {
                // Sprawdź znacznik końca 00 ED ED 00
                if (offset + 3 < data.size() && 
                    data[offset] == 0x00 && data[offset+1] == 0xED && 
                    data[offset+2] == 0xED && data[offset+3] == 0x00) {
                    break;
                }

                uint8_t byte = data[offset++];
                if (byte == 0xED) {
                    if (offset >= data.size()) { mem.write(addr++, byte); break; }
                    uint8_t nextByte = data[offset++];
                    if (nextByte == 0xED) {
                        if (offset + 1 >= data.size()) break;
                        uint8_t count = data[offset++];
                        uint8_t value = data[offset++];
                        for (int i = 0; i < count; ++i) mem.write(addr++, value);
                    } else {
                        mem.write(addr++, byte);
                        mem.write(addr++, nextByte);
                    }
                } else {
                    mem.write(addr++, byte);
                }
            }
        } else {
            // Nieskompresowane
            while (offset < data.size() && addr < 65536) {
                mem.write(addr++, data[offset++]);
            }
        }
    }

    if (cpu.get_PC() < 16384) {
        std::cerr << "Warning: PC points to ROM address (0x" << std::hex << std::setw(4) << std::setfill('0') << cpu.get_PC() << "). Ensure ROM is loaded." << std::dec << std::endl;
    }

    return true;
}

std::vector<std::string> Z80Format::get_extensions() const {
    return { ".z80" };
}