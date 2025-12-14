#ifndef __CORE_H__
#define __CORE_H__

#include "Memory.h"
#include "Z80.h"
#include "Analyzer.h"
#include "Assembler.h"
#include "Z80Analyze.h"
#include "Z80Assemble.h"
#include "Context.h"
#include "../Files/FileManager.h"
#include <vector>
#include <string>
#include <filesystem>

class Core : public IFileProvider {
public:
    using CpuType = Z80<Z80Analyzer<Memory>::CodeMapProfiler, Z80StandardEvents, Z80Analyzer<Memory>::CodeMapProfiler>;
    
    using Block = LoadedBlock;

    Core();

    // Wczytuje pliki z listy (format "plik" lub "plik:adres")
    // Automatycznie szuka i ładuje pliki .map, .sym, .ctl, .lst
    void load_input_files(const std::vector<std::string>& inputs);
    void reset();
    void print_symbols(const std::string& filter = "");

    Memory& get_memory() { return m_memory; }
    CpuType& get_cpu() { return m_cpu; }
    Z80Analyzer<Memory>::CodeMap& get_code_map() { return m_code_map_data; }
    Z80Analyzer<Memory>::CodeMapProfiler& get_profiler() { return m_profiler; }

    Analyzer& get_analyzer() { return m_analyzer; }
    Context& get_context() { return m_context; }
    ToolAssembler& get_assembler() { return m_assembler; }
    const std::vector<Block>& get_blocks() const { return m_blocks; }

    // IFileProvider implementation
    bool read_file(const std::string& identifier, std::vector<uint8_t>& data) override;
    size_t file_size(const std::string& identifier) override;
    bool exists(const std::string& identifier) override;

    uint16_t parse_address(const std::string& addr_str);

private:
    Memory m_memory;
    Z80Analyzer<Memory>::CodeMap m_code_map_data;
    Z80Analyzer<Memory>::CodeMapProfiler m_profiler;
    CpuType m_cpu;
    ToolAssembler m_assembler;
    Context m_context;
    Analyzer m_analyzer;
    std::vector<Block> m_blocks;
    std::vector<std::filesystem::path> m_current_path_stack;
    FileManager m_file_manager;

    // Helper methods
    void process_file(const std::string& path, uint16_t address);
    void load_sidecar_files(const std::string& path);
};

#endif // __CORE_H__