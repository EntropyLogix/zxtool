#ifndef __ASMFILES_H__
#define __ASMFILES_H__

#include <string>
#include "../Core/Assembler.h"
#include "../Core/Memory.h"

class AsmFiles {
public:
    AsmFiles(ToolAssembler& assembler);
    std::vector<typename ToolAssembler::BlockInfo> assemble(const std::string& path, uint16_t address, bool verbose);

private:
    ToolAssembler& m_assembler;
};

#endif//__ASMFILES_H__