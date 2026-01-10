#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#include <string>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <vector>

#include "Core.h"

class CommandLine;
struct Options;

using MemoryBlock = Core::Block;

class Application {
public:
    Application();
    ~Application() = default;

    int run(CommandLine& commands);

    auto& get_cpu() {  return m_core.get_cpu(); }
    Memory& get_memory() { return m_core.get_memory(); }
    Analyzer& get_analyzer() { return m_core.get_analyzer(); }
    ToolAssembler& get_assembler() { return m_core.get_assembler(); }
    Memory& get_bus() { return m_core.get_memory(); }
    Core& get_core() { return m_core; }

private:
    void load_input_files();

    Core m_core;
    const Options* m_options = nullptr;
};

#endif//__APPLICATION_H__