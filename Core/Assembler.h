#ifndef __ASSEMBLER_H__
#define __ASSEMBLER_H__

#include "Z80Assemble.h"
#include "Memory.h"


class ToolAssembler : public Z80Assembler<Memory>
{
public:
    ToolAssembler(Memory* memory, IFileProvider* source_provider, const typename Z80Assembler<Memory>::Options& options = Z80Assembler<Memory>::get_default_options())
        : Z80Assembler<Memory>(memory, source_provider, options) {}
};

#endif//__ASSEMBLER_H__