#include "Debugger.h"
#include "TraceModule.h"
#include "../Utils/Strings.h"
#include <algorithm>
#include <functional>
#include <sstream>
#include <vector>
#include <iomanip>

TraceModule g_trace_module;
static std::function<bool()> g_dbg_interrupt_callback;

Debugger::Debugger(Core& core, const Options& options) : m_core(core), m_options(options) { 
    m_prev_state = m_core.get_cpu().save_state(); 
    m_trace.resize(64);

    // Disable label generation during debugging
    m_core.get_profiler().set_generate_labels(false);
}

void Debugger::add_breakpoint(uint16_t addr) {
    m_breakpoints.push_back({addr, true});
}

void Debugger::remove_breakpoint(uint16_t addr) {
    m_breakpoints.erase(std::remove_if(m_breakpoints.begin(), m_breakpoints.end(), 
        [addr](const Breakpoint& b){ return b.addr == addr; }), m_breakpoints.end());
}

void Debugger::remove_breakpoint_by_index(size_t index) {
    if (index < m_breakpoints.size()) m_breakpoints.erase(m_breakpoints.begin() + index);
}

void Debugger::enable_breakpoint(size_t index) {
    if (index < m_breakpoints.size()) m_breakpoints[index].enabled = true;
}

void Debugger::enable_breakpoint(uint16_t addr) {
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [addr](const Breakpoint& b){ return b.addr == addr; });
    if (it != m_breakpoints.end()) it->enabled = true;
}

void Debugger::disable_breakpoint(size_t index) {
    if (index < m_breakpoints.size()) m_breakpoints[index].enabled = false;
}

void Debugger::disable_breakpoint(uint16_t addr) {
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [addr](const Breakpoint& b){ return b.addr == addr; });
    if (it != m_breakpoints.end()) it->enabled = false;
}

void Debugger::enable_all_breakpoints() {
    for (auto& bp : m_breakpoints) bp.enabled = true;
}

void Debugger::disable_all_breakpoints() {
    for (auto& bp : m_breakpoints) bp.enabled = false;
}

void Debugger::clear_breakpoints() {
    m_breakpoints.clear();
}

void Debugger::add_watch(const std::string& expr) {
    m_watches.push_back(expr);
}

void Debugger::remove_watch(size_t index) {
    if (index < m_watches.size()) m_watches.erase(m_watches.begin() + index);
}

void Debugger::clear_watches() {
    m_watches.clear();
}

bool Debugger::check_breakpoints(uint16_t pc) {
    for (const auto& bp : m_breakpoints)
        if (bp.enabled && bp.addr == pc)
            return true;
    return false;
}

bool Debugger::has_breakpoint(uint16_t addr) const {
    for (const auto& bp : m_breakpoints)
        if (bp.addr == addr)
            return true;
    return false;
}

void Debugger::step(int n) {
    m_prev_state = m_core.get_cpu().save_state();
    for (int i = 0; i < n; ++i) {
        if (i > 0 && check_breakpoints(m_core.get_cpu().get_PC()))
            break;
        uint16_t pc_before = m_core.get_cpu().get_PC();
        if (g_trace_module.is_recording()) {
            auto line = m_core.get_analyzer().parse_instruction(pc_before);
            g_trace_module.push(pc_before, line.bytes);
        }
        record_trace(pc_before);
        m_core.get_cpu().step();
        uint16_t pc_after = m_core.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
    }
}

void Debugger::next() {
    m_prev_state = m_core.get_cpu().save_state();
    uint16_t pc_before = m_core.get_cpu().get_PC();
    uint16_t temp_pc = pc_before;
    auto line = m_core.get_analyzer().parse_instruction(temp_pc);
        
    if (line.mnemonic.empty()) { 
        record_trace(pc_before);
        if (g_trace_module.is_recording()) {
            g_trace_module.push(pc_before, line.bytes);
        }
        m_core.get_cpu().step(); 
    }
    else {
        using Type = Z80Analyzer<Memory>::CodeLine::Type;
        bool is_call = line.has_flag(Type::CALL);
        bool is_block = line.has_flag(Type::BLOCK);
        bool is_djnz = (line.mnemonic == "DJNZ");

        if (is_call || is_block || is_djnz) {
            uint16_t next_pc = temp_pc + (uint16_t)line.bytes.size();
            
            record_trace(pc_before);
            if (g_trace_module.is_recording()) {
                g_trace_module.push(pc_before, line.bytes);
            }
            m_core.get_cpu().step();

            if (m_core.get_cpu().get_PC() != next_pc)
                run_until(next_pc);
        } else {
            record_trace(pc_before);
            if (g_trace_module.is_recording()) {
                g_trace_module.push(pc_before, line.bytes);
            }
            m_core.get_cpu().step();
        }
    }
    uint16_t pc_after = m_core.get_cpu().get_PC();
    m_last_pc = pc_before;
    m_has_history = true;
    m_pc_moved = (pc_before != pc_after);
}

void Debugger::over() {
    m_prev_state = m_core.get_cpu().save_state();
    uint16_t pc = m_core.get_cpu().get_PC();
    auto line = m_core.get_analyzer().parse_instruction(pc);
    uint16_t next_pc = pc + (uint16_t)line.bytes.size();
    
    record_trace(pc);
    if (g_trace_module.is_recording()) {
        g_trace_module.push(pc, line.bytes);
    }
    m_core.get_cpu().step();
    
    if (m_core.get_cpu().get_PC() != next_pc)
        run_until(next_pc);
    
    uint16_t pc_after = m_core.get_cpu().get_PC();
    m_last_pc = pc;
    m_has_history = true;
    m_pc_moved = (pc != pc_after);
}

void Debugger::skip() {
    m_prev_state = m_core.get_cpu().save_state();
    uint16_t pc = m_core.get_cpu().get_PC();
    auto line = m_core.get_analyzer().parse_instruction(pc);
    uint16_t next_pc = pc + (uint16_t)line.bytes.size();
    
    m_core.get_cpu().set_PC(next_pc);
    
    m_last_pc = pc;
    m_has_history = true;
    m_pc_moved = true;
    log("Skipped instruction. PC: " + Strings::hex(pc) + " -> " + Strings::hex(next_pc));
}

void Debugger::run_until(uint16_t target_pc) {
    log("Running until " + Strings::hex(target_pc) + "...");
    int batch = 0;
    while (m_core.get_cpu().get_PC() != target_pc) {
        if (check_breakpoints(m_core.get_cpu().get_PC()))
            break;
        
        if (++batch >= 4096) {
            batch = 0;
            if (g_dbg_interrupt_callback && g_dbg_interrupt_callback()) {
                log("Interrupted by user.");
                break;
            }
        }

        if (g_trace_module.is_recording()) {
            auto l = m_core.get_analyzer().parse_instruction(m_core.get_cpu().get_PC());
            g_trace_module.push(m_core.get_cpu().get_PC(), l.bytes);
        }
        record_trace(m_core.get_cpu().get_PC());
        m_core.get_cpu().step();
    }
}

void Debugger::analyze() {
    uint16_t pc = m_core.get_cpu().get_PC();
    auto& map = m_core.get_code_map();
    
    // Run heuristic analysis from current PC
    m_core.get_analyzer().parse_code(pc, 0, &map, false, true);

    // Re-apply CTL data to ensure user overrides are preserved
    const auto& ctl_map = m_core.get_analyzer().m_map;
    if (ctl_map.size() == map.size()) {
        for (size_t i = 0; i < map.size(); ++i) {
            if (ctl_map[i] != Z80Analyzer<Memory>::CodeMap::FLAG_NONE) {
                map[i] = ctl_map[i];
            }
        }
    }
    log("Manual code analysis triggered from PC: " + Strings::hex(pc));
}

void Debugger::set_interrupt_callback(std::function<bool()> cb) {
    g_dbg_interrupt_callback = cb;
}

void Debugger::log(const std::string& msg) {
    if (m_logger)
        m_logger(msg);
}

void Debugger::record_trace(uint16_t pc) {
    m_trace[m_trace_head] = pc;
    m_trace_head = (m_trace_head + 1) % m_trace.size();
    if (m_trace_head == 0) m_trace_wrapped = true;
}

bool Debugger::is_traced(uint16_t pc) const {
    size_t limit = m_trace_wrapped ? m_trace.size() : m_trace_head;
    for (size_t i = 0; i < limit; ++i) {
        if (m_trace[i] == pc) return true;
    }
    return false;
}