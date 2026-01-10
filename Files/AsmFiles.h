#ifndef __ASMFILES_H__
#define __ASMFILES_H__

#include <string>
#include "../Core/Assembler.h"
#include "../Core/Memory.h"
#include "File.h"

class AsmFiles : public IBinaryFile {
public:
    AsmFiles(ToolAssembler& assembler);
    std::vector<typename ToolAssembler::BlockInfo> assemble(const std::string& path, uint16_t address, bool verbose);

    // IFile implementation
    LoadResult load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) override;
    std::vector<std::string> get_extensions() const override;

private:
    ToolAssembler& m_assembler;
};

#endif//__ASMFILES_H__