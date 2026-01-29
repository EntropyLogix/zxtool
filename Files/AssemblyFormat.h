#ifndef __ASSEMBLYFORMAT__
#define __ASSEMBLYFORMAT__

#include <string>
#include "FileFormat.h"

class Core;

class AssemblyFormat : public FileFormat {
public:
    AssemblyFormat(Core& core);

    bool load_binary(const std::string& filename, std::vector<Block>& blocks, uint16_t address) override;    
    bool load_metadata(const std::string& filename) override;
    uint32_t get_capabilities() const override { return LoadBinary | LoadMetadata; }
    std::vector<std::string> get_extensions() const override { return { ".asm" }; } 

private:
    void extract_comment(const std::string& source, std::string& comment);
    Core& m_core;
};

#endif//__ASSEMBLYFORMAT__