#ifndef __DISASSEMBLE_ENGINE_H__
#define __DISASSEMBLE_ENGINE_H__

#include "Engine.h"
#include "../Core/VirtualMachine.h"
#include "../Cmd/Options.h"

class DisassembleEngine : public Engine {
public:
    DisassembleEngine(VirtualMachine& vm, const Options& options);
    virtual ~DisassembleEngine() = default;
    
    int run() override;

private:
    VirtualMachine& m_vm;
    const Options& m_options;
};

#endif // __DISASSEMBLE_ENGINE_H__