#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

#include <vector>
#include <functional>
#include <string>
#include <cstdint>

#include "../Core/Core.h"
#include "../Cmd/Options.h"

class Debugger {
public:
    using Logger = std::function<void(const std::string&)>;
    struct Breakpoint
    {
        uint16_t addr;
        bool enabled;
    };

    Debugger(Core& core, const Options& options);
    ~Debugger() = default;

    void set_logger(Logger logger) { m_logger = logger; }
    Core& get_core() { return m_core; }
    const Options& get_options() const { return m_options; }
    const std::vector<Breakpoint>& get_breakpoints() const { return m_breakpoints; }
    const std::vector<std::string>& get_watches() const { return m_watches; }
    uint16_t get_last_pc() const { return m_last_pc; }
    bool has_history() const { return m_has_history; }
    bool pc_moved() const { return m_pc_moved; }
    uint64_t get_tstates() const { return m_core.get_cpu().get_ticks(); }
    const Core::CpuType::State& get_prev_state() const { return m_prev_state; }

    void add_breakpoint(uint16_t addr);
    void remove_breakpoint(uint16_t addr);
    void remove_breakpoint_by_index(size_t index);
    void enable_breakpoint(size_t index);
    void enable_breakpoint(uint16_t addr);
    void disable_breakpoint(size_t index);
    void disable_breakpoint(uint16_t addr);
    void enable_all_breakpoints();
    void disable_all_breakpoints();
    void clear_breakpoints();
    void add_watch(const std::string& expr);
    void remove_watch(size_t index);
    void clear_watches();
    bool check_breakpoints(uint16_t pc);
    bool has_breakpoint(uint16_t addr) const;
    void step(int n);
    void next();
    void over();
    void skip();
    void run_until(uint16_t target_pc);
    void analyze();
    void set_interrupt_callback(std::function<bool()> cb);
    
    bool is_traced(uint16_t pc) const;

private:
    Core& m_core;
    const Options& m_options;
    Logger m_logger;
    std::vector<Breakpoint> m_breakpoints;
    std::vector<std::string> m_watches;
    uint16_t m_last_pc = 0;
    bool m_has_history = false;
    bool m_pc_moved = false;
    Core::CpuType::State m_prev_state;
    
    std::vector<uint16_t> m_trace;
    size_t m_trace_head = 0;
    bool m_trace_wrapped = false;

    void log(const std::string& msg);
    void record_trace(uint16_t pc);
};

#endif // __DEBUGGER_H__