#ifndef __ASSEMBLY_FORMAT__
#define __ASSEMBLY_FORMAT__

#include <string>
#include "File.h"

class Core;

class AssemblyFormat : public FileFormat {
public:
    AssemblyFormat(Core& core);

    bool load_binary(const std::string& filename, std::vector<Block>& blocks, uint16_t address) override;    
    uint32_t get_capabilities() const override { return LoadBinary; }
    std::vector<std::string> get_extensions() const override { return { ".asm" }; } 

private:
    Core& m_core;
};

#endif//__ASSEMBLY_FORMAT__