#ifndef __PROFILEENGINE_H__
#define __PROFILEENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"
#include "../Cmd/Options.h"
#include <vector>
#include <cstdint>
#include <map>

class ProfileEngine : public Engine {
public:
    ProfileEngine(Core& core, const Options& options);
    virtual ~ProfileEngine() = default;
    
    int run() override;
private:
    Core& m_core;
    const Options& m_options;
    
    std::vector<uint64_t> m_hits;
    std::vector<uint64_t> m_cycles;

    struct BranchStat {
        uint64_t taken = 0;
        uint64_t not_taken = 0;
    };
    std::map<uint16_t, BranchStat> m_branch_stats;

    struct FunctionStat {
        uint64_t inclusive_cycles = 0;
        uint64_t call_count = 0;
    };
    std::map<uint16_t, FunctionStat> m_function_stats;

    struct StackFrame {
        uint16_t func_addr;
        uint64_t start_ticks;
    };
    std::vector<StackFrame> m_call_stack;
    uint64_t m_idle_cycles = 0;
};

#endif // __PROFILEENGINE_H__