#include "ProfileEngine.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <chrono>
#include "../Utils/Strings.h"
#include "../Core/Expression.h"

ProfileEngine::ProfileEngine(Core& core, const Options& options) : m_core(core), m_options(options) {}

int ProfileEngine::run() {
    auto& cpu = m_core.get_cpu();
    
    // Initialize buffers
    m_hits.assign(0x10000, 0);
    m_cycles.assign(0x10000, 0);
    m_branch_stats.clear();
    m_function_stats.clear();
    m_call_stack.clear();
    m_idle_cycles = 0;

    // Setup Entry Point
    if (!m_options.profile.entryPointStr.empty()) {
        try {
            Expression eval(m_core);
            uint16_t val = (uint16_t)eval.evaluate(m_options.profile.entryPointStr).get_scalar(m_core);
            cpu.set_PC(val);
        } catch (const std::exception& e) {
            std::cerr << "Error evaluating entry point: " << e.what() << "\n";
            return 1;
        }
    }

    std::cout << "Starting Profiler...\n";
    std::cout << "Entry Point: $" << Strings::hex(cpu.get_PC()) << "\n";
    
    auto start_time = std::chrono::steady_clock::now();
    uint64_t start_ticks = cpu.get_ticks();
    
    // Run Loop
    bool running = true;
    long long max_steps = m_options.profile.steps;
    long long steps = 0;
    long long timeout_ms = m_options.profile.timeout * 1000;
    if (timeout_ms == 0 && max_steps == 0) timeout_ms = 5000; // Default 5s

    while (running) {
        uint16_t pc = cpu.get_PC();
        auto line = m_core.get_analyzer().parse_instruction(pc);
        uint16_t next_seq_pc = pc + (uint16_t)line.bytes.size();
        
        uint64_t t0 = cpu.get_ticks();
        
        cpu.step();
        
        uint16_t new_pc = cpu.get_PC();
        bool taken = (new_pc != next_seq_pc);

        // 1. Idle Time Detection
        if (line.mnemonic == "HALT") {
            m_idle_cycles += (cpu.get_ticks() - t0);
        }

        // 2. Branch Prediction Stats
        bool is_cond = false;
        if (!line.operands.empty() && line.operands[0].type == Analyzer::CodeLine::Operand::CONDITION) is_cond = true;
        if (line.mnemonic == "DJNZ") is_cond = true;

        if (is_cond && (line.has_flag(Analyzer::CodeLine::Type::JUMP) || line.has_flag(Analyzer::CodeLine::Type::CALL) || line.has_flag(Analyzer::CodeLine::Type::RETURN))) {
            if (taken) m_branch_stats[pc].taken++;
            else m_branch_stats[pc].not_taken++;
        }

        // 3. Call Graph / Inclusive Time
        if (line.has_flag(Analyzer::CodeLine::Type::CALL) && taken) {
            m_call_stack.push_back({new_pc, t0});
            m_function_stats[new_pc].call_count++;
        } else if (line.has_flag(Analyzer::CodeLine::Type::RETURN) && taken) {
            if (!m_call_stack.empty()) {
                auto frame = m_call_stack.back();
                m_call_stack.pop_back();
                // Only attribute time if we returned from the function we thought we were in
                // (Simple heuristic, ignores stack manipulation)
                uint64_t duration = cpu.get_ticks() - frame.start_ticks;
                m_function_stats[frame.func_addr].inclusive_cycles += duration;
            }
        }

        uint64_t t1 = cpu.get_ticks();
        uint64_t delta = t1 - t0;

        // Collect data
        m_hits[pc]++;
        m_cycles[pc] += delta;

        steps++;

        if (max_steps > 0 && steps >= max_steps) running = false;
        else if (timeout_ms > 0) {
            if (steps % 10000 == 0) {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count() >= timeout_ms)
                    running = false;
            }
        }
        if (cpu.is_halted()) running = false;
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    uint64_t total_ticks = cpu.get_ticks() - start_ticks;

    // Report Generation
    struct Stat {
        uint16_t addr;
        uint64_t hits;
        uint64_t cycles;
    };
    std::vector<Stat> stats;
    uint64_t total_hits = 0;
    uint64_t total_cycles_recorded = 0;
    size_t covered_bytes = 0;

    for (size_t i = 0; i < 0x10000; ++i) {
        if (m_hits[i] > 0) {
            stats.push_back({(uint16_t)i, m_hits[i], m_cycles[i]});
            total_hits += m_hits[i];
            total_cycles_recorded += m_cycles[i];
            
            auto line = m_core.get_analyzer().parse_instruction((uint16_t)i);
            covered_bytes += line.bytes.size();
        }
    }

    std::cout << "\n=== PROFILER REPORT ===\n";
    std::cout << "Duration:   " << duration_ms << " ms\n";
    std::cout << "T-States:   " << total_ticks << "\n";
    std::cout << "Idle Time:  " << m_idle_cycles << " T-States (" << std::fixed << std::setprecision(2) << ((double)m_idle_cycles * 100.0 / total_ticks) << "%)\n";
    uint64_t active_ticks = total_ticks - m_idle_cycles;
    std::cout << "Active:     " << active_ticks << " T-States\n";

    if (duration_ms > 0) {
        double mhz = (double)total_ticks / (double)duration_ms / 1000.0;
        std::cout << "Avg Speed:  " << std::fixed << std::setprecision(3) << mhz << " MHz\n";
    }
    std::cout << "Coverage:   " << covered_bytes << " bytes executed (" << std::fixed << std::setprecision(1) << (covered_bytes * 100.0 / 65536.0) << "% of 64K)\n";
    std::cout << "Unique PCs: " << stats.size() << "\n\n";

    // Top Hotspots by Time (Cycles)
    std::sort(stats.begin(), stats.end(), [](const Stat& a, const Stat& b){ return a.cycles > b.cycles; });

    int limit = m_options.profile.hotspots;
    if (limit < 0) limit = 20;
    std::cout << "\n--- TOP " << limit << " HOTSPOTS (By CPU Time) ---\n";
    std::cout << " #   ADDR    HITS       CYCLES     % TIME  INSTRUCTION\n";
    std::cout << "------------------------------------------------------------\n";
    
    for (size_t i = 0; i < std::min((size_t)limit, stats.size()); ++i) {
        const auto& s = stats[i];
        double pct = (total_cycles_recorded > 0) ? (double)s.cycles * 100.0 / (double)total_cycles_recorded : 0.0;
        
        auto line = m_core.get_analyzer().parse_instruction(s.addr);
        std::string disasm = line.mnemonic;
        if (!line.operands.empty()) {
            disasm += " ";
            for (size_t j = 0; j < line.operands.size(); ++j) {
                if (j > 0) disasm += ", ";
                const auto& op = line.operands[j];
                switch (op.type) {
                    case Analyzer::CodeLine::Operand::REG8:
                    case Analyzer::CodeLine::Operand::REG16:
                    case Analyzer::CodeLine::Operand::CONDITION:
                        disasm += op.s_val;
                        break;
                    case Analyzer::CodeLine::Operand::IMM8:
                        disasm += "$" + Strings::hex((uint8_t)op.num_val);
                        break;
                    case Analyzer::CodeLine::Operand::IMM16: {
                        auto sym = m_core.get_context().getSymbols().find((uint16_t)op.num_val);
                        if (sym) disasm += sym->getName();
                        else disasm += "$" + Strings::hex((uint16_t)op.num_val);
                        break;
                    }
                    case Analyzer::CodeLine::Operand::MEM_IMM16: {
                        auto sym = m_core.get_context().getSymbols().find((uint16_t)op.num_val);
                        if (sym) disasm += "(" + sym->getName() + ")";
                        else disasm += "($" + Strings::hex((uint16_t)op.num_val) + ")";
                        break;
                    }
                    case Analyzer::CodeLine::Operand::MEM_REG16:
                        disasm += "(" + op.s_val + ")";
                        break;
                    case Analyzer::CodeLine::Operand::MEM_INDEXED:
                        disasm += "(" + op.base_reg + (op.offset >= 0 ? "+" : "") + std::to_string((int)op.offset) + ")";
                        break;
                    case Analyzer::CodeLine::Operand::PORT_IMM8:
                        disasm += "($" + Strings::hex((uint8_t)op.num_val) + ")";
                        break;
                    case Analyzer::CodeLine::Operand::STRING:
                        disasm += "\"" + op.s_val + "\"";
                        break;
                    case Analyzer::CodeLine::Operand::CHAR_LITERAL:
                        disasm += "'";
                        disasm += (char)op.num_val;
                        disasm += "'";
                        break;
                    default:
                        break;
                }
            }
        }

        std::cout << std::right << std::setw(2) << (i + 1) << "   $" << Strings::hex(s.addr) << "   " 
                  << std::left << std::setw(10) << s.hits 
                  << std::setw(10) << s.cycles 
                  << std::fixed << std::setprecision(2) << std::setw(6) << pct << "% " << disasm << "\n";
    }
    std::cout << "------------------------------------------------------------\n";

    // Top Functions (Inclusive Time)
    if (!m_function_stats.empty()) {
        struct FuncInfo { uint16_t addr; uint64_t cycles; uint64_t count; };
        std::vector<FuncInfo> funcs;
        for (const auto& pair : m_function_stats) funcs.push_back({pair.first, pair.second.inclusive_cycles, pair.second.call_count});
        std::sort(funcs.begin(), funcs.end(), [](const FuncInfo& a, const FuncInfo& b){ return a.cycles > b.cycles; });

        std::cout << "\n--- TOP FUNCTIONS (Inclusive Time) ---\n";
        std::cout << "ADDR    CALLS      INCL. CYCLES  % TOTAL  LABEL\n";
        std::cout << "------------------------------------------------------------\n";
        for (size_t i = 0; i < std::min((size_t)limit, funcs.size()); ++i) {
            const auto& f = funcs[i];
            double pct = (total_ticks > 0) ? (double)f.cycles * 100.0 / (double)total_ticks : 0.0;
            std::string label = m_core.get_context().getSymbols().get_label(f.addr);
            if (label.empty()) label = "-";
            
            std::cout << "$" << Strings::hex(f.addr) << "   " 
                      << std::left << std::setw(10) << f.count 
                      << std::setw(13) << f.cycles 
                      << std::fixed << std::setprecision(2) << std::setw(6) << pct << "%  " << label << "\n";
        }
        std::cout << "------------------------------------------------------------\n";
    }

    // Branch Statistics
    if (!m_branch_stats.empty()) {
        std::cout << "\n--- BRANCH PREDICTION STATS ---\n";
        std::cout << "ADDR    TAKEN      NOT TAKEN  % TAKEN  INSTRUCTION\n";
        std::cout << "------------------------------------------------------------\n";
        int count = 0;
        for (const auto& pair : m_branch_stats) {
            if (count++ >= limit) break;
            uint64_t total = pair.second.taken + pair.second.not_taken;
            double pct = (total > 0) ? (double)pair.second.taken * 100.0 / (double)total : 0.0;
            auto line = m_core.get_analyzer().parse_instruction(pair.first);
            std::cout << "$" << Strings::hex(pair.first) << "   " << std::left << std::setw(10) << pair.second.taken << std::setw(10) << pair.second.not_taken << std::fixed << std::setprecision(1) << std::setw(6) << pct << "%  " << line.mnemonic << "\n";
        }
        std::cout << "------------------------------------------------------------\n";
    }

    // CSV Export
    if (!m_options.profile.exportFile.empty()) {
        std::ofstream file(m_options.profile.exportFile);
        if (!file) {
            std::cerr << "Error: Could not open file " << m_options.profile.exportFile << " for writing.\n";
        } else {
            file << "Address,Hits,Cycles,Instruction,Operands,BranchTaken,BranchNotTaken\n";
            // Sort by address for CSV usually makes more sense for static analysis, 
            // but let's stick to the collected stats order or re-sort. 
            // Let's re-sort by address for the file to make it readable as a listing.
            std::sort(stats.begin(), stats.end(), [](const Stat& a, const Stat& b){ return a.addr < b.addr; });

            for (const auto& s : stats) {
                auto line = m_core.get_analyzer().parse_instruction(s.addr);
                std::string operands;
                if (!line.operands.empty()) {
                    // Reconstruct operands string simply
                    // Note: We could reuse a formatter, but simple is fine for CSV
                    for (const auto& op : line.operands) {
                        if (!operands.empty()) operands += " ";
                        if (op.type == Analyzer::CodeLine::Operand::IMM16 || op.type == Analyzer::CodeLine::Operand::IMM8) 
                            operands += "$" + Strings::hex((uint16_t)op.num_val); // Simplified
                        else operands += op.s_val;
                    }
                }
                uint64_t bt = 0, bnt = 0;
                if (m_branch_stats.count(s.addr)) { bt = m_branch_stats[s.addr].taken; bnt = m_branch_stats[s.addr].not_taken; }
                
                file << "$" << Strings::hex(s.addr) << "," << s.hits << "," << s.cycles << "," << line.mnemonic << ",\"" << operands << "\"," << bt << "," << bnt << "\n";
            }
            std::cout << "Profile data exported to " << m_options.profile.exportFile << "\n";
        }
    }

    return 0;
}