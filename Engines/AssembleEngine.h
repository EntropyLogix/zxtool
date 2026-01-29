#ifndef __ASSEMBLEENGINE_H__
#define __ASSEMBLEENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"
#include "../Core/Assembler.h"

class AssembleEngine : public Engine {
public:
    AssembleEngine(Core& core, const Options& options);
    int run() override;

private:
    void save_output_file(const std::string& outputFile, const std::string& format, const std::vector<Core::Block>& blocks);
    void save_bin(const std::string& outputFile, const std::vector<Core::Block>& blocks);
    
    std::string format_bytes_str(const std::vector<uint8_t>& bytes, bool hex);
    void write_map_file(const std::string& file_path, const std::map<std::string, ToolAssembler::SymbolInfo>& symbols);
    void write_lst_file(const std::string& file_path, const std::vector<ToolAssembler::ListingLine>& listing);

    Core& m_core;
    const Options& m_options;
};

#endif // __ASSEMBLEENGINE_H__