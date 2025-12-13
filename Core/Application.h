#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#include <string>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <vector>

#include "VirtualMachine.h"

class CommandLine;
struct Options;

using MemoryBlock = VirtualMachine::Block;

class Application {
public:
    Application();
    ~Application() = default;

    int run(CommandLine& commands);

    Z80<Memory>& get_cpu() { return m_vm.get_cpu(); }
    Memory& get_memory() { return m_vm.get_memory(); }
    Analyzer& get_analyzer() { return m_vm.get_analyzer(); }
    ToolAssembler& get_assembler() { return m_vm.get_assembler(); }
    Memory& get_bus() { return m_vm.get_memory(); }
    VirtualMachine& get_vm() { return m_vm; }

private:
    void load_input_files();

    VirtualMachine m_vm;
    const Options* m_options = nullptr;
};

#endif//__APPLICATION_H__