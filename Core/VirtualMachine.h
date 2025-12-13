#ifndef __VIRTUAL_MACHINE_H__
#define __VIRTUAL_MACHINE_H__

#include "Memory.h"
#include "Z80.h"
#include "Analyzer.h"
#include "Assembler.h"
#include "Z80Assemble.h"
#include <vector>
#include <string>
#include <filesystem>

class VirtualMachine : public IFileProvider {
public:
    struct Block {
        uint16_t start_address;
        uint16_t size;
        std::string description;
    };

    VirtualMachine();

    // Wczytuje pliki z listy (format "plik" lub "plik:adres")
    // Automatycznie szuka i ładuje pliki .map, .sym, .ctl, .lst
    void load_input_files(const std::vector<std::string>& inputs);
    void reset();

    Memory& get_memory() { return m_memory; }
    Z80<Memory>& get_cpu() { return m_cpu; }
    Analyzer& get_analyzer() { return m_analyzer; }
    ToolAssembler& get_assembler() { return m_assembler; }
    const std::vector<Block>& get_blocks() const { return m_blocks; }

    // IFileProvider implementation
    bool read_file(const std::string& identifier, std::vector<uint8_t>& data) override;
    size_t file_size(const std::string& identifier) override;
    bool exists(const std::string& identifier) override;

    uint16_t parse_address(const std::string& addr_str);

private:
    Memory m_memory;
    Z80<Memory> m_cpu;
    ToolAssembler m_assembler;
    Analyzer m_analyzer;
    std::vector<Block> m_blocks;
    std::vector<std::filesystem::path> m_current_path_stack;

    // Helper methods
    void process_file(const std::string& path, uint16_t address);
    void load_sidecar_files(const std::string& path);
};

#endif // __VIRTUAL_MACHINE_H__