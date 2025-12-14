#ifndef __DEBUGENGINE_H__
#define __DEBUGENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"
#include "../Cmd/Options.h"
#include "../Utils/Terminal.h"
#include <replxx.hxx>
#include <vector>
#include <string>
#include <functional>
#include <deque>
#include <sstream>
#include <algorithm>
#include <iostream>

class DebugView {
public:
    DebugView(Core& core, bool has_focus) : m_core(core), m_has_focus(has_focus) {}
    virtual ~DebugView() = default;
    virtual std::vector<std::string> render() = 0;

protected:
    std::string format_header(const std::string& title, const std::string& extra = "") const;

    Core& m_core;
    bool m_has_focus;
};

class MemoryView : public DebugView {
public:
    MemoryView(Core& core, uint16_t start_addr, int rows, bool has_focus) 
        : DebugView(core, has_focus), m_start_addr(start_addr), m_rows(rows) {}
    std::vector<std::string> render() override;
private:
    uint16_t m_start_addr;
    int m_rows;
};

class RegisterView : public DebugView {
public:
    RegisterView(Core& core, const Core::CpuType::State& prev, bool has_focus, uint64_t tstates) 
        : DebugView(core, has_focus), m_prev(prev), m_tstates(tstates) {}
    std::vector<std::string> render() override;
private:
    std::string format_flags(uint8_t f, uint8_t prev_f);
    const Core::CpuType::State& m_prev;
    uint64_t m_tstates;
};

class StackView : public DebugView {
public:
    StackView(Core& core, uint16_t view_addr, bool has_focus) 
        : DebugView(core, has_focus), m_view_addr(view_addr) {}
    std::vector<std::string> render() override;
private:
    uint16_t m_view_addr;
};

class CodeView : public DebugView {
public:
    CodeView(Core& core, uint16_t start_addr, int rows, uint16_t pc, int width, bool has_focus, uint16_t last_pc, bool has_history, bool pc_moved) 
        : DebugView(core, has_focus), m_start_addr(start_addr), m_rows(rows), m_pc(pc), m_width(width), m_last_pc(last_pc), m_has_history(has_history), m_pc_moved(pc_moved) {}
    std::vector<std::string> render() override;
private:
    uint16_t m_start_addr;
    int m_rows;
    uint16_t m_pc;
    int m_width;
    uint16_t m_last_pc;
    bool m_has_history;
    bool m_pc_moved;
};

class Debugger {
public:
    using Logger = std::function<void(const std::string&)>;
    struct Breakpoint
    {
        uint16_t addr;
        bool enabled;
    };
    struct HistoryItem {
        uint16_t pc;
    };

    Debugger(Core& core) : m_core(core) { m_prev_state = m_core.get_cpu().save_state(); }
    ~Debugger() = default;

    void set_logger(Logger logger) { m_logger = logger; }
    Core& get_core() { return m_core; }
    const std::vector<Breakpoint>& get_breakpoints() const { return m_breakpoints; }
    const std::vector<uint16_t>& get_watches() const { return m_watches; }
    const std::deque<HistoryItem>& get_execution_history() const { return m_execution_history; }
    uint16_t get_last_pc() const { return m_last_pc; }
    bool has_history() const { return m_has_history; }
    bool pc_moved() const { return m_pc_moved; }
    uint64_t get_tstates() const { return m_core.get_cpu().get_ticks(); }
    const Core::CpuType::State& get_prev_state() const { return m_prev_state; }

    void add_breakpoint(uint16_t addr) { m_breakpoints.push_back({addr, true}); }
    void remove_breakpoint(uint16_t addr) {
        m_breakpoints.erase(std::remove_if(m_breakpoints.begin(), m_breakpoints.end(), 
            [addr](const Breakpoint& b){ return b.addr == addr; }), m_breakpoints.end());
    }
    void add_watch(uint16_t addr) { m_watches.push_back(addr); }
    void remove_watch(uint16_t addr) {
        m_watches.erase(std::remove(m_watches.begin(), m_watches.end(), addr), m_watches.end());
    }
    bool check_breakpoints(uint16_t pc);
    void step(int n);
    void next();
    void cont();

private:
    Core& m_core;
    Logger m_logger;
    std::vector<Breakpoint> m_breakpoints;
    std::vector<uint16_t> m_watches;
    std::deque<HistoryItem> m_execution_history;
    uint16_t m_last_pc = 0;
    bool m_has_history = false;
    bool m_pc_moved = false;
    Core::CpuType::State m_prev_state;

    void record_history(uint16_t pc);
    void log(const std::string& msg) { if (m_logger) m_logger(msg); }
};

class Dashboard {
public:
    Dashboard(Debugger& debugger, replxx::Replxx& repl) : m_debugger(debugger), m_repl(repl) {
        m_debugger.set_logger([this](const std::string& msg){ log(msg); });
    }
    void run();

private:    
    enum Focus { FOCUS_MEMORY, FOCUS_REGS, FOCUS_STACK, FOCUS_CODE, FOCUS_WATCH, FOCUS_BREAKPOINTS, FOCUS_COUNT };
    Focus m_focus = FOCUS_CODE;

    Debugger& m_debugger;
    replxx::Replxx& m_repl;
    std::string m_last_command;
    bool m_running = true;
    std::stringstream m_output_buffer;
    int m_code_rows = 15;
    int m_stack_rows = 4;
    int m_mem_rows = 4;
    uint16_t m_mem_view_addr = 0;
    uint16_t m_code_view_addr = 0;
    uint16_t m_stack_view_addr = 0;
    bool m_show_mem = true;
    bool m_show_regs = true;
    bool m_show_code = true;
    bool m_show_stack = true;
    bool m_show_watch = false;
    bool m_show_breakpoints = false;
    bool m_auto_follow = true;
    
    void validate_focus();
    void handle_command(const std::string& input);
    void setup_replxx();
    void print_help();
    void print_separator() { std::cout << Terminal::GRAY << std::string(80, '-') << Terminal::RESET << "\n"; }
    void print_dashboard();
    void print_footer();
    void print_columns(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width);
    void print_output_buffer();
    void log(const std::string& msg) { m_output_buffer << msg << "\n"; }
    uint16_t find_prev_instruction_pc(uint16_t target_addr);
    uint16_t get_pc_window_start(uint16_t pc, int lines);
    void update_code_view();
};

class DebugEngine : public Engine {
public:
    DebugEngine(Core& core, const Options& options) : m_core(core), m_options(options) {}
    virtual ~DebugEngine() = default;
    
    int run() override;

private:
    Core& m_core;
    const Options& m_options;
    replxx::Replxx m_repl;
};

#endif // __DEBUGENGINE_H__