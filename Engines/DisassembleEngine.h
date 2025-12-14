#ifndef __DISASSEMBLE_ENGINE_H__
#define __DISASSEMBLE_ENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"
#include "../Cmd/Options.h"

class DisassembleEngine : public Engine {
public:
    DisassembleEngine(Core& core, const Options& options);
    virtual ~DisassembleEngine() = default;
    
    int run() override;

private:
    Core& m_core;
    const Options& m_options;
};

#endif // __DISASSEMBLE_ENGINE_H__