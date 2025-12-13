#ifndef __RUNENGINE_H__
#define __RUNENGINE_H__

#include "Engine.h"

class RunEngine : public Engine {
public:
    RunEngine(VirtualMachine& vm, const Options& options);
    int run() override;

private:
    VirtualMachine& m_vm;
    const Options& m_options;
};

#endif // __RUNENGINE_H__