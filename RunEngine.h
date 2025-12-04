#ifndef __RUNENGINE_H__
#define __RUNENGINE_H__

#include <string>
#include <vector>
#include <cstdint>

#include "Z80Analyze.h"
#include "Z80.h"
#include "Options.h"

// Forward declarations for Z80 components
class Z80DefaultBus;
class Z80DefaultLabels;

class RunEngine {
public:
    RunEngine(Z80DefaultBus& bus, Z80<Z80DefaultBus>& cpu, Z80DefaultLabels& label_handler,
              Z80Analyzer<Z80DefaultBus, Z80<Z80DefaultBus>, Z80DefaultLabels>& analyzer,
              const Options& options);

    int execute();

private:
    Z80DefaultBus& m_bus;
    Z80<Z80DefaultBus>& m_cpu;
    Z80DefaultLabels& m_label_handler;
    Z80Analyzer<Z80DefaultBus, Z80<Z80DefaultBus>, Z80DefaultLabels>& m_analyzer;
    const Options& m_options;
};

#endif // __RUNENGINE_H__