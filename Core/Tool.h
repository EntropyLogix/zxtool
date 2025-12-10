#ifndef __TOOL_H__
#define __TOOL_H__

#include <string>
#include <algorithm>
#include <cctype>
#include <stdexcept>

#include "Z80.h"
#include "Z80Analyze.h"
#include "Z80Assemble.h"

#include "Memory.h"
#include "Assembler.h"
#include "../Files/FileProvider.h"

class CommandLine;

struct MemoryBlock {
    uint16_t start_address;
    uint16_t size;
    std::string description;
};

class Tool {
public:
    Tool();
    ~Tool() = default;

    int run(CommandLine& commands);

    Z80<Memory>& get_cpu() { return m_cpu; }
    Memory& get_memory() { return m_memory; }
    Z80Analyzer<Memory>& get_analyzer() { return m_analyzer; }
    ToolAssembler& get_assembler() { return m_assembler; }
    Memory& get_bus() { return m_memory; }

private:
    uint16_t resolve_address(const std::string& addr_str);
    Memory m_memory;
    Z80<Memory> m_cpu;
    Z80Analyzer<Memory> m_analyzer;
    ToolAssembler m_assembler;
    FileProvider m_file_provider;
    std::vector<MemoryBlock> m_blocks;
};

#endif//__TOOL_H__