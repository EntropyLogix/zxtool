#ifndef __ASSEMBLEENGINE_H__
#define __ASSEMBLEENGINE_H__

#include <string>
#include <vector>
#include <cstdint>
#include <map>

#include "Z80Assemble.h"
#include "Z80Analyze.h"
#include "Z80.h"
#include "Options.h"

// Forward declarations for Z80 components
class Z80DefaultBus;
class Z80DefaultLabels;

class AssembleEngine {
public:
    AssembleEngine(Z80DefaultBus& bus, Z80<Z80DefaultBus>& cpu, Z80DefaultLabels& label_handler,
                 Z80Analyzer<Z80DefaultBus, Z80<Z80DefaultBus>, Z80DefaultLabels>& analyzer,
                 Z80Assembler<Z80DefaultBus>& assembler,
                 const Options& options);

    int execute();

private:
    Z80DefaultBus& m_bus;
    Z80<Z80DefaultBus>& m_cpu;
    Z80DefaultLabels& m_label_handler;
    Z80Analyzer<Z80DefaultBus, Z80<Z80DefaultBus>, Z80DefaultLabels>& m_analyzer;
    Z80Assembler<Z80DefaultBus>& m_assembler;
    const Options& m_options;
};

#endif // __ASSEMBLEENGINE_H__