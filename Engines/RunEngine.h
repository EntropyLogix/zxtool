#ifndef __RUNENGINE_H__
#define __RUNENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"

class RunEngine : public Engine {
public:
    RunEngine(Core& core, const Options& options);
    int run() override;

private:
    Core& m_core;
    const Options& m_options;
};

#endif // __RUNENGINE_H__