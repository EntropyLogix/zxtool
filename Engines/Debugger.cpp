#include "Debugger.h"
#include "../Utils/Strings.h"
#include <algorithm>

Debugger::Debugger(Core& core, const Options& options) : m_core(core), m_options(options) { 
    m_prev_state = m_core.get_cpu().save_state(); 
    m_trace.resize(64);
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
    record_trace(pc_before);
        
    uint16_t temp_pc = pc_before;
    auto line = m_core.get_analyzer().parse_instruction(temp_pc);
        
    if (line.mnemonic.empty()) { 
        m_core.get_cpu().step(); 
    }
    else {
        using Type = Z80Analyzer<Memory>::CodeLine::Type;
        bool is_call = line.has_flag(Type::CALL);
        bool is_block = line.has_flag(Type::BLOCK);

        if (is_call || is_block) {
            uint16_t next_pc = temp_pc + line.bytes.size();
            log("Stepping over... (Target: " + Strings::hex(next_pc) + ")");
            while (m_core.get_cpu().get_PC() != next_pc) {
                if (check_breakpoints(m_core.get_cpu().get_PC()))
                    break;
                record_trace(m_core.get_cpu().get_PC());
                m_core.get_cpu().step();
            }
        } else
            m_core.get_cpu().step();
    }
    uint16_t pc_after = m_core.get_cpu().get_PC();
    m_last_pc = pc_before;
    m_has_history = true;
    m_pc_moved = (pc_before != pc_after);
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