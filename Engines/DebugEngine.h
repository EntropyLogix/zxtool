#ifndef __DEBUGENGINE_H__
#define __DEBUGENGINE_H__

#include "Engine.h"
#include "../Core/VirtualMachine.h"
#include "../Cmd/Options.h"
#include <replxx.hxx>

class DebugEngine : public Engine {
public:
    DebugEngine(VirtualMachine& vm, const Options& options);
    virtual ~DebugEngine() = default;
    
    int run() override;

private:
    VirtualMachine& m_vm;
    const Options& m_options;
    replxx::Replxx m_repl;

    void print_registers();
    void print_instruction(uint16_t pc);
    void print_memory(uint16_t address, uint16_t len);
};

#endif // __DEBUGENGINE_H__