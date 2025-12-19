#ifndef __DEBUGENGINE_H__
#define __DEBUGENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"
#include "../Core/CodeMap.h"
#include "../Cmd/Options.h"
#include "../Utils/Terminal.h"
#include <replxx.hxx>
#include <vector>
#include <string>
#include <functional>
#include <sstream>
#include <algorithm>
#include <iostream>

struct Theme {
    std::string header_focus = Terminal::rgb_fg(255, 255, 10);
    std::string header_blur = Terminal::rgb_fg(109, 222, 111);
    std::string separator = Terminal::rgb_fg(137, 137, 137);
    std::string address = Terminal::rgb_fg(20, 208, 255);
    std::string value = Terminal::rgb_fg(64, 64, 64);
    std::string value_dim = Terminal::rgb_fg(255, 255, 255 );
    std::string highlight = Terminal::rgb_fg(255, 241, 107);
    std::string label = Terminal::rgb_fg(193, 24, 193);
    std::string mnemonic = Terminal::rgb_fg(72, 127, 188);
    std::string operand_num = Terminal::rgb_fg(142, 144, 63);
    std::string reg = Terminal::rgb_fg(20, 208, 255);
    std::string comment = Terminal::rgb_fg(78, 155, 156);
    std::string pc_fg = Terminal::rgb_fg(220, 220, 220);
    std::string pc_bg = Terminal::rgb_bg(102, 102, 102);
    std::string error = Terminal::rgb_fg(255, 0, 0);
};

class DebugView {
public:
    DebugView(Core& core, const Theme& theme) : m_core(core), m_theme(theme) {}
    virtual ~DebugView() = default;
    virtual std::vector<std::string> render() = 0;
    void set_focus(bool focus) { m_has_focus = focus; }
    void set_rows(int rows) { m_rows = rows; }
    int get_rows() const { return m_rows; }

protected:
    std::string format_header(const std::string& title, const std::string& extra = "") const;

    Core& m_core;
    const Theme& m_theme;
    bool m_has_focus = false;
    int m_rows = 0;
};

class MemoryView : public DebugView {
public:
    MemoryView(Core& core, int rows, const Theme& theme) : DebugView(core, theme) { m_rows = rows; }
    std::vector<std::string> render() override;
    void set_address(uint16_t addr) { m_start_addr = addr; }
    uint16_t get_address() const { return m_start_addr; }
    void scroll(int delta) { m_start_addr += delta; }
private:
    uint16_t m_start_addr = 0;
};

class RegisterView : public DebugView {
public:
    RegisterView(Core& core, const Theme& theme) : DebugView(core, theme) {}
    std::vector<std::string> render() override;
    void set_state(const Core::CpuType::State& prev, uint64_t tstates) { m_prev = prev; m_tstates = tstates; }
private:
    std::string format_flags(uint8_t f, uint8_t prev_f);
    Core::CpuType::State m_prev;
    uint64_t m_tstates = 0;
};

class StackView : public DebugView {
public:
    StackView(Core& core, int rows, const Theme& theme) : DebugView(core, theme) { m_rows = rows; }
    std::vector<std::string> render() override;
    void set_address(uint16_t addr) { m_view_addr = addr; }
    uint16_t get_address() const { return m_view_addr; }
    void scroll(int delta) { m_view_addr += delta; }
private:
    uint16_t m_view_addr = 0;
};

class CodeView : public DebugView {
public:
    CodeView(Core& core, int rows, const Theme& theme) : DebugView(core, theme) { m_rows = rows; }
    std::vector<std::string> render() override;
    void set_address(uint16_t addr) { m_start_addr = addr; }
    uint16_t get_address() const { return m_start_addr; }
    void scroll(int delta);
    void set_state(uint16_t pc, int width, uint16_t last_pc, bool has_history, bool pc_moved) {
        m_pc = pc; m_width = width; m_last_pc = last_pc; m_has_history = has_history; m_pc_moved = pc_moved;
    }
private:
    void format_operands(const Z80Analyzer<Memory>::CodeLine& line, std::ostream& os, const std::string& color_num, const std::string& color_rst);
    uint16_t m_start_addr = 0;
    uint16_t m_pc = 0;
    int m_width = 80;
    uint16_t m_last_pc = 0;
    bool m_has_history = false;
    bool m_pc_moved = false;
};

class Debugger {
public:
    using Logger = std::function<void(const std::string&)>;
    struct Breakpoint
    {
        uint16_t addr;
        bool enabled;
    };

    Debugger(Core& core) : m_core(core) { m_prev_state = m_core.get_cpu().save_state(); }
    ~Debugger() = default;

    void set_logger(Logger logger) { m_logger = logger; }
    Core& get_core() { return m_core; }
    const std::vector<Breakpoint>& get_breakpoints() const { return m_breakpoints; }
    const std::vector<uint16_t>& get_watches() const { return m_watches; }
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

private:
    Core& m_core;
    Logger m_logger;
    std::vector<Breakpoint> m_breakpoints;
    std::vector<uint16_t> m_watches;
    uint16_t m_last_pc = 0;
    bool m_has_history = false;
    bool m_pc_moved = false;
    Core::CpuType::State m_prev_state;

    void log(const std::string& msg) { if (m_logger) m_logger(msg); }
};

class Dashboard {
public:
    Dashboard(Debugger& debugger, replxx::Replxx& repl) 
        : m_debugger(debugger), m_repl(repl)
        , m_memory_view(debugger.get_core(), 4, m_theme)
        , m_register_view(debugger.get_core(), m_theme)
        , m_stack_view(debugger.get_core(), 4, m_theme)
        , m_code_view(debugger.get_core(), 15, m_theme)
    {
        m_debugger.set_logger([this](const std::string& msg){ log(msg); });
    }
    void run();

private:    
    enum Focus { FOCUS_MEMORY, FOCUS_REGS, FOCUS_STACK, FOCUS_CODE, FOCUS_WATCH, FOCUS_BREAKPOINTS, FOCUS_COUNT };
    Focus m_focus = FOCUS_CODE;

    Debugger& m_debugger;
    replxx::Replxx& m_repl;
    Theme m_theme;
    bool m_running = true;
    std::stringstream m_output_buffer;
    MemoryView m_memory_view;
    RegisterView m_register_view;
    StackView m_stack_view;
    CodeView m_code_view;
    bool m_show_mem = true;
    bool m_show_regs = true;
    bool m_show_code = true;
    bool m_show_stack = true;
    bool m_show_watch = false;
    bool m_show_breakpoints = false;
    bool m_auto_follow = true;
    
    void validate_focus();
    void handle_command(const std::string& input);
    void init();
    void print_separator() { std::cout << m_theme.separator << std::string(80, '-') << Terminal::RESET << "\n"; }
    void print_dashboard();
    void print_footer();
    void print_columns(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width);
    void print_output_buffer();
    void log(const std::string& msg) { m_output_buffer << msg << "\n"; }
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