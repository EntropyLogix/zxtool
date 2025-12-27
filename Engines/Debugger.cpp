#include "Debugger.h"
#include "../Utils/Strings.h"
#include <algorithm>

Debugger::Debugger(Core& core, const Options& options) : m_core(core), m_options(options) { 
    m_prev_state = m_core.get_cpu().save_state(); 
}

void Debugger::add_breakpoint(uint16_t addr) {
    m_breakpoints.push_back({addr, true});
}

void Debugger::remove_breakpoint(uint16_t addr) {
    m_breakpoints.erase(std::remove_if(m_breakpoints.begin(), m_breakpoints.end(), 
        [addr](const Breakpoint& b){ return b.addr == addr; }), m_breakpoints.end());
}

void Debugger::add_watch(uint16_t addr) {
    m_watches.push_back(addr);
}

void Debugger::remove_watch(uint16_t addr) {
    m_watches.erase(std::remove(m_watches.begin(), m_watches.end(), addr), m_watches.end());
}

bool Debugger::check_breakpoints(uint16_t pc) {
    for (const auto& bp : m_breakpoints)
        if (bp.enabled && bp.addr == pc)
            return true;
    return false;
}

void Debugger::step(int n) {
    m_prev_state = m_core.get_cpu().save_state();
    for (int i = 0; i < n; ++i) {
        if (i > 0 && check_breakpoints(m_core.get_cpu().get_PC()))
            break;
        uint16_t pc_before = m_core.get_cpu().get_PC();
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
        m_core.get_cpu().step(); 
    }
    else {
        using Type = Z80Analyzer<Memory>::CodeLine::Type;
        bool is_call = line.has_flag(Type::CALL);
        bool is_block = line.has_flag(Type::BLOCK);

        if (is_call || is_block) {
            uint16_t next_pc = temp_pc;
            log("Stepping over... (Target: " + Strings::hex(next_pc) + ")");
            while (m_core.get_cpu().get_PC() != next_pc) {
                if (check_breakpoints(m_core.get_cpu().get_PC()))
                    break;
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