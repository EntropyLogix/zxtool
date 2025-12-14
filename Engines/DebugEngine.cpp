#include "DebugEngine.h"
#include <replxx.hxx>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cctype>
#include <algorithm>
#include <regex>
#ifdef _WIN32
    #include <windows.h>
#else
#endif
#include "../Utils/Strings.h"
#include "../Utils/Terminal.h"

std::string DebugView::format_header(const std::string& title, const std::string& extra) const {
    std::stringstream ss;
    if (m_has_focus) ss << Terminal::YELLOW << "[" << title << "]" << Terminal::RESET;
    else ss << Terminal::GREEN << "[" << title << "]" << Terminal::RESET;
    if (!extra.empty()) ss << extra;
    return ss.str();
}

std::vector<std::string> MemoryView::render() {
    std::vector<std::string> lines;
    std::string sep = Terminal::GRAY + std::string(80, '-') + Terminal::RESET;
    lines.push_back(sep);
    std::stringstream extra;
    extra << Terminal::CYAN << " View: " << Terminal::HI_WHITE << Strings::hex16(m_start_addr) << Terminal::RESET;
    lines.push_back(format_header("MEMORY", extra.str()));
    lines.push_back(sep);
    auto& mem = m_vm.get_memory();
    for (size_t i = 0; i < m_rows * 16; i += 16) {
        std::stringstream ss;
        uint16_t addr = m_start_addr + i;
        ss << Terminal::CYAN << Strings::hex16(addr) << Terminal::RESET << ": ";
        for (size_t j = 0; j < 16; ++j) {
            uint8_t b = mem.read(addr + j);
            if (b == 0)
                ss << Terminal::GRAY << "00" << Terminal::RESET;
            else
                ss << Strings::hex8(b);
            if (j == 7)
                ss << "  ";
            else if (j == 15)
                ss << "  ";
            else
                ss << " ";
        }
        ss << Terminal::GRAY << "|" << Terminal::RESET << " ";
        for (size_t j = 0; j < 16; ++j) {
            uint8_t val = mem.read(addr + j);
            if (std::isprint(val))
                ss << Terminal::HI_YELLOW << (char)val << Terminal::RESET;
            else
                ss << Terminal::GRAY << "." << Terminal::RESET;
        }
        lines.push_back(ss.str());
    }
    return lines;
}

std::vector<std::string> RegisterView::render() {
    std::vector<std::string> lines;
    long long delta = (long long)m_tstates - m_prev.m_ticks;
    std::stringstream extra;
    extra << Terminal::GRAY << " T: " << Terminal::RESET << m_tstates;
    if (delta > 0)
        extra << Terminal::RED << " (+" << delta << ")" << Terminal::RESET;
    lines.push_back(format_header("REGS", extra.str()));

    auto& cpu = m_vm.get_cpu();
    auto fmt_reg16 = [&](const std::string& l, uint16_t v, uint16_t pv) -> std::string {
        std::stringstream ss;
        ss << Terminal::CYAN << std::setw(3) << std::left << l << Terminal::RESET << ": " 
            << (v != pv ? Terminal::HI_YELLOW : Terminal::GRAY) << Strings::hex16(v) << Terminal::RESET;
        return ss.str();
    };
    auto fmt_reg8 = [&](const std::string& l, uint8_t v, uint8_t pv) -> std::string {
        std::stringstream ss;
        ss << Terminal::CYAN << std::setw(3) << std::left << l << Terminal::RESET << ": " 
            << (v != pv ? Terminal::HI_YELLOW : Terminal::GRAY) << Strings::hex8(v) << Terminal::RESET;
        return ss.str();
    };
    std::stringstream ss;
    ss << "  " << fmt_reg16("AF", cpu.get_AF(), m_prev.m_AF.w) << "   " << fmt_reg16("AF'", cpu.get_AFp(), m_prev.m_AFp.w) << "   " << fmt_reg8("I", cpu.get_I(), m_prev.m_I);
    lines.push_back(ss.str());
    ss.str(""); ss << "  " << fmt_reg16("BC", cpu.get_BC(), m_prev.m_BC.w) << "   " << fmt_reg16("BC'", cpu.get_BCp(), m_prev.m_BCp.w) << "   " << fmt_reg8("R", cpu.get_R(), m_prev.m_R);
    lines.push_back(ss.str());
    ss.str(""); ss << "  " << fmt_reg16("DE", cpu.get_DE(), m_prev.m_DE.w) << "   " << fmt_reg16("DE'", cpu.get_DEp(), m_prev.m_DEp.w) << "   "
        << Terminal::CYAN << std::setw(3) << std::left << "IM" << Terminal::RESET << ": " 
        << (cpu.get_IRQ_mode() != m_prev.m_IRQ_mode ? Terminal::HI_YELLOW : Terminal::GRAY) << (int)cpu.get_IRQ_mode() << Terminal::RESET;
    lines.push_back(ss.str());
    ss.str(""); ss << "  " << fmt_reg16("HL", cpu.get_HL(), m_prev.m_HL.w) << "   " << fmt_reg16("HL'", cpu.get_HLp(), m_prev.m_HLp.w) << "   "
        << Terminal::CYAN << std::setw(3) << std::left << "IFF" << Terminal::RESET << ": " 
        << (cpu.get_IFF1() ? (Terminal::HI_GREEN + "ON ") : (Terminal::GRAY + "OFF")) << Terminal::RESET;
    lines.push_back(ss.str());
    ss.str(""); ss << "  " << fmt_reg16("IX", cpu.get_IX(), m_prev.m_IX.w) << "   " << fmt_reg16("IY", cpu.get_IY(), m_prev.m_IY.w) << "   "
        << Terminal::CYAN << std::setw(3) << std::left << "F" << Terminal::RESET << ": " << format_flags(cpu.get_AF() & 0xFF, m_prev.m_AF.w & 0xFF);
    lines.push_back(ss.str());
    return lines;
}

std::string RegisterView::format_flags(uint8_t f, uint8_t prev_f) {
    std::stringstream ss;
    const char* syms = "SZ5H3PNC";
    for (int i = 7; i >= 0; --i) {
        bool bit = (f >> i) & 1;
        bool prev_bit = (prev_f >> i) & 1;
        char c = bit ? syms[7-i] : '-';
        if (bit != prev_bit)
            ss << Terminal::HI_YELLOW << Terminal::BOLD << c << Terminal::RESET;
        else if (bit)
            ss << Terminal::HI_WHITE << c << Terminal::RESET;
        else
            ss << Terminal::GRAY << c << Terminal::RESET;
    }
    return ss.str();
}

std::vector<std::string> StackView::render() {
    std::vector<std::string> lines;
    std::stringstream extra;
    extra << Terminal::CYAN << " (SP=" << Terminal::HI_WHITE << Strings::hex16(m_vm.get_cpu().get_SP()) << Terminal::CYAN << ")" << Terminal::RESET;
    lines.push_back(format_header("STACK", extra.str()));

    for (int i=0; i<5; ++i) {
        uint16_t addr = m_view_addr + i*2;
        uint8_t l = m_vm.get_memory().read(addr);
        uint8_t h = m_vm.get_memory().read(addr + 1);
        uint16_t val = l | (h << 8);
        std::stringstream ss;
        ss << "  " << Terminal::GRAY << Strings::hex16(addr) << Terminal::RESET << ": " << Terminal::HI_WHITE << Strings::hex16(val) << Terminal::RESET;
        auto code_lines = m_vm.get_analyzer().parse_code(val, 1);
        if (!code_lines.empty() && !code_lines[0].label.empty())
            ss << Terminal::HI_YELLOW << " (" << code_lines[0].label << ")" << Terminal::RESET;
        lines.push_back(ss.str());
    }
    return lines;
}

std::vector<std::string> CodeView::render() {
    std::vector<std::string> lines_out;
    lines_out.push_back(format_header("CODE"));
    if (m_has_history && m_start_addr == m_pc && (m_last_pc != m_pc || !m_pc_moved)) {
        uint16_t hist_addr = m_last_pc;
        auto hist_lines = m_vm.get_analyzer().parse_code(hist_addr, 1);
        if (!hist_lines.empty()) {
            const auto& line = hist_lines[0];
            std::stringstream ss;
            ss << "  " << Terminal::GRAY << Strings::hex16((uint16_t)line.address) << ": ";
            for(size_t i=0; i<std::min((size_t)4, line.bytes.size()); ++i)
                ss << Strings::hex8(line.bytes[i]) << " ";
            for(size_t i=line.bytes.size(); i<4; ++i) ss << "   ";
            ss << " ";

            ss << std::left << std::setw(5) << line.mnemonic << " ";
            
            if (!line.operands.empty()) {
                using Operand = typename std::decay_t<decltype(line)>::Operand;
                for (size_t i = 0; i < line.operands.size(); ++i) {
                    if (i > 0) ss << ", ";
                    const auto& op = line.operands[i];
                    switch (op.type) {
                        case Operand::REG8: case Operand::REG16: case Operand::CONDITION: ss << op.s_val; break;
                        case Operand::IMM8: ss << "$" << Strings::hex8(op.num_val); break;
                        case Operand::IMM16: ss << "$" << Strings::hex16(op.num_val); break;
                        case Operand::MEM_IMM16: ss << "($" << Strings::hex16(op.num_val) << ")"; break;
                        case Operand::MEM_REG16: ss << "(" << op.s_val << ")"; break;
                        case Operand::MEM_INDEXED: ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                        case Operand::STRING: ss << "\"" << op.s_val << "\""; break;
                        default: break;
                    }
                }
            }
            ss << Terminal::RESET;
            lines_out.push_back(ss.str());
        }
    }
    uint16_t temp_pc_iter = m_start_addr;
    auto lines = m_vm.get_analyzer().parse_code(temp_pc_iter, m_rows);   
    for (const auto& line : lines) {
        std::stringstream ss;
        bool is_pc = ((uint16_t)line.address == m_pc);
        std::string bg = is_pc ? Terminal::BG_DARK_GRAY : "";
        std::string rst = is_pc ? (Terminal::RESET + bg) : Terminal::RESET;
        if (is_pc)
            ss << bg << Terminal::HI_GREEN << Terminal::BOLD << "> " << rst;
        else
            ss << "  ";
        if (is_pc)
            ss << Terminal::HI_WHITE << Terminal::BOLD << Strings::hex16((uint16_t)line.address) << rst << ": ";
        else
            ss << Terminal::GRAY << Strings::hex16((uint16_t)line.address) << rst << ": ";
        ss << Terminal::GRAY;
        for(size_t i=0; i<std::min((size_t)4, line.bytes.size()); ++i)
            ss << Strings::hex8(line.bytes[i]) << " ";
        for(size_t i=line.bytes.size(); i<4; ++i)
            ss << "   ";
        ss << rst << " ";
        if (is_pc)
            ss << Terminal::BOLD << Terminal::WHITE;
        else
            ss << Terminal::BLUE;
        ss << std::left << std::setw(5) << line.mnemonic << rst << " ";
        if (!line.operands.empty()) {
            using Operand = typename std::decay_t<decltype(line)>::Operand;
            for (size_t i = 0; i < line.operands.size(); ++i) {
                if (i > 0)
                    ss << ", ";
                const auto& op = line.operands[i];
                bool is_num = (op.type == Operand::IMM8 || op.type == Operand::IMM16 || op.type == Operand::MEM_IMM16);
                if (is_num)
                    ss << Terminal::YELLOW;
                switch (op.type) {
                    case Operand::REG8:
                    case Operand::REG16:
                    case Operand::CONDITION:
                        ss << op.s_val;
                        break;
                    case Operand::IMM8:
                        ss << "$" << Strings::hex8(op.num_val);
                        break;
                    case Operand::IMM16:
                        ss << "$" << Strings::hex16(op.num_val);
                        break;
                    case Operand::MEM_IMM16:
                        ss << "($" << Strings::hex16(op.num_val) << ")";
                        break;
                    case Operand::MEM_REG16:
                        ss << "(" << op.s_val << ")";
                        break;
                    case Operand::MEM_INDEXED:
                        ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")";
                        break;
                    case Operand::STRING:
                        ss << "\"" << op.s_val << "\"";
                        break;
                    default:
                        break;
                }
                if (is_num)
                    ss << rst;
            }
        }
        if (m_width > 0) {
            std::string s = ss.str();
            size_t len = Strings::ansi_len(s);
            int pad = m_width - (int)len;
            if (pad > 0)
                s += std::string(pad, ' ');
            s += Terminal::RESET; 
            lines_out.push_back(s);
        } else
            lines_out.push_back(ss.str());
    }
    return lines_out;
}

bool Debugger::check_breakpoints(uint16_t pc) {
    for (const auto& bp : m_breakpoints) {
        if (bp.enabled && bp.addr == pc)
            return true;
    }
    return false;
}

void Debugger::step(int n) {
    m_prev_state = m_vm.get_cpu().save_state();
    for (int i = 0; i < n; ++i) {
        if (i > 0 && check_breakpoints(m_vm.get_cpu().get_PC()))
            break;
        uint16_t pc_before = m_vm.get_cpu().get_PC();
        m_vm.get_cpu().step();
        uint16_t pc_after = m_vm.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
    }
}

void Debugger::next() {
        m_prev_state = m_vm.get_cpu().save_state();
        uint16_t pc_before = m_vm.get_cpu().get_PC();

        auto lines = m_vm.get_analyzer().parse_code(pc_before, 2);
        if (lines.empty()) { m_vm.get_cpu().step(); }
        else {

        std::string mnemonic = lines[0].mnemonic;
        bool is_subroutine = (mnemonic.find("CALL") == 0) || (mnemonic.find("RST") == 0) || (mnemonic.find("LDIR") == 0) || (mnemonic.find("LDDR") == 0);

        if (is_subroutine) {
            uint16_t next_pc = (lines.size() > 1) ? lines[1].address : pc_before + lines[0].bytes.size();
            log("Stepping over... (Target: " + Strings::hex16(next_pc) + ")");
            while (m_vm.get_cpu().get_PC() != next_pc) {
                if (check_breakpoints(m_vm.get_cpu().get_PC())) break;
                m_vm.get_cpu().step();
            }
        } else {
            m_vm.get_cpu().step();
        }
        }
        uint16_t pc_after = m_vm.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
}

void Debugger::cont() {
    m_prev_state = m_vm.get_cpu().save_state();
    while (true) {
        if (check_breakpoints(m_vm.get_cpu().get_PC())) {
            log("Breakpoint hit!");
            return;
        }
        uint16_t pc_before = m_vm.get_cpu().get_PC();
        m_vm.get_cpu().step();
        uint16_t pc_after = m_vm.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
    }
}

void Dashboard::run() {
    setup_replxx();
    m_repl.history_load("zxtool_history.txt");
    m_code_view_addr = m_debugger.get_vm().get_cpu().get_PC();
    m_mem_view_addr = m_debugger.get_vm().get_cpu().get_PC();
    m_stack_view_addr = m_debugger.get_vm().get_cpu().get_SP();
    validate_focus();
    while (m_running) {
        print_dashboard();
        const char* input_cstr = m_repl.input("> ");
        if (input_cstr == nullptr)
            break;
        std::string input(input_cstr);
        if (input.empty()) {
            if (m_last_command.empty())
                continue;
            input = m_last_command;
        } else {
            m_last_command = input;
            m_repl.history_add(input);
        }
        handle_command(input);
    }
    m_repl.history_save("zxtool_history.txt");
}


void Dashboard::validate_focus() {
    int attempts = 0;
    while (attempts < FOCUS_COUNT && (
        (m_focus == FOCUS_MEMORY && !m_show_mem) ||
            (m_focus == FOCUS_REGS && !m_show_regs) ||
            (m_focus == FOCUS_STACK && !m_show_stack) ||
            (m_focus == FOCUS_CODE && !m_show_code) ||
            (m_focus == FOCUS_WATCH && !m_show_watch) ||
            (m_focus == FOCUS_BREAKPOINTS && !m_show_breakpoints)
        )) {
            m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
            attempts++;
        }
}

void Dashboard::handle_command(const std::string& input) {
        std::stringstream ss(input);
        std::string cmd;
        ss >> cmd;

        if (cmd == "s" || cmd == "step") { 
            int n=1; ss >> n; if(ss.fail()) n=1; 
            m_debugger.step(n); 
            m_code_view_addr = m_debugger.get_vm().get_cpu().get_PC(); 
        }
        else if (cmd == "n" || cmd == "next") { 
            m_debugger.next(); 
            m_code_view_addr = m_debugger.get_vm().get_cpu().get_PC(); 
        }
        else if (cmd == "c" || cmd == "continue") { 
            log("Running...");
            print_dashboard();
            m_debugger.cont(); 
        }
        else if (cmd == "q" || cmd == "quit") { m_running = false; }
        else if (cmd == "h" || cmd == "help") { print_help(); }
        else if (cmd == "lines") {
            std::string type; int n;
            if (ss >> type >> n && n > 0) {
                if (type == "code") m_code_rows = n;
                else if (type == "mem") m_mem_rows = n;
                else if (type == "stack") m_stack_rows = n;
                else log("Usage: lines <code|mem|stack> <n>");
            } else log("Usage: lines <code|mem|stack> <n>");
        }
        else if (cmd == "toggle") {
            std::string panel;
            if (ss >> panel) {
                if (panel == "mem" || panel == "memory") m_show_mem = !m_show_mem;
                else if (panel == "regs" || panel == "registers") m_show_regs = !m_show_regs;
                else if (panel == "code") m_show_code = !m_show_code;
                else if (panel == "stack") m_show_stack = !m_show_stack;
                else if (panel == "watch" || panel == "w") m_show_watch = !m_show_watch;
                else if (panel == "breakpoints" || panel == "bp") m_show_breakpoints = !m_show_breakpoints;
                else log("Usage: toggle <mem|regs|code|stack|watch|breakpoints>");
            } else log("Usage: toggle <mem|regs|code|stack|watch|breakpoints>");
        }
        else if (cmd == "b" || cmd == "break") {
            std::string arg; 
            if(ss>>arg) { 
                try { m_debugger.add_breakpoint(m_debugger.get_vm().parse_address(arg)); log("Breakpoint set."); }
                catch(...) { log("Invalid address."); }
            }
        }
        else if (cmd == "d" || cmd == "delete") {
            std::string arg; 
            if(ss>>arg) { 
                try { m_debugger.remove_breakpoint(m_debugger.get_vm().parse_address(arg)); }
                catch(...) { log("Invalid address."); }
            }
        }
        else if (cmd == "w" || cmd == "watch") {
            std::string arg; 
            if(ss>>arg) { 
                try { m_debugger.add_watch(m_debugger.get_vm().parse_address(arg)); }
                catch(...) { log("Invalid address."); }
            }
        }
        else if (cmd == "u" || cmd == "unwatch") {
            std::string arg; 
            if(ss>>arg) { 
                try { m_debugger.remove_watch(m_debugger.get_vm().parse_address(arg)); }
                catch(...) { log("Invalid address."); }
            }
        }
        else { log("Unknown command."); }
}

void Dashboard::setup_replxx() {
        m_repl.install_window_change_handler();
        
        auto bind_scroll = [&](char32_t key, int mem_delta, int code_delta, int stack_delta) {
            m_repl.bind_key(key, [this, mem_delta, code_delta, stack_delta](char32_t code) {
                if (m_focus == FOCUS_MEMORY) m_mem_view_addr += mem_delta;
                else if (m_focus == FOCUS_CODE) m_code_view_addr += code_delta;
                else if (m_focus == FOCUS_STACK) m_stack_view_addr += stack_delta;
                print_dashboard();
                m_repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
                return replxx::Replxx::ACTION_RESULT::CONTINUE;
            });
        };

        bind_scroll(replxx::Replxx::KEY::UP, -16, -1, -2);
        bind_scroll(replxx::Replxx::KEY::DOWN, 16, 1, 2);

        auto tab_handler = [this](char32_t code) {
            validate_focus();
            print_dashboard();
            m_repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
            return replxx::Replxx::ACTION_RESULT::CONTINUE;
        };
        
        m_repl.bind_key(replxx::Replxx::KEY::TAB, tab_handler);
        m_repl.bind_key(9, tab_handler);
}

void Dashboard::print_help() {
        m_output_buffer << "\nAvailable Commands:\n";
        m_output_buffer << " [EXECUTION]\n";
        m_output_buffer << "   s, step [n]            Execute instructions (default 1)\n";
        m_output_buffer << "   n, next                Step over subroutine\n";
        m_output_buffer << "   c, continue            Continue execution\n\n";
        m_output_buffer << " [SYSTEM]\n";
        m_output_buffer << "   h, help                Show this message\n";
        m_output_buffer << "   lines <type> <n>       Set lines (code/mem/stack)\n";
        m_output_buffer << "   toggle <panel>         Toggle panel visibility\n";
        m_output_buffer << "   b, break <addr>        Set breakpoint\n";
        m_output_buffer << "   d, delete <addr>       Delete breakpoint\n";
        m_output_buffer << "   w, watch <addr>        Add watch address\n";
        m_output_buffer << "   u, unwatch <addr>      Remove watch\n";
        m_output_buffer << "   q, quit                Exit debugger\n";
}


void Dashboard::print_dashboard() {
        Terminal::clear();
        auto& vm = m_debugger.get_vm();
        auto& cpu = vm.get_cpu();
        uint16_t pc = cpu.get_PC();
        const int terminal_width = 80;
        if (m_show_mem) {
            MemoryView view(vm, m_mem_view_addr, m_mem_rows, m_focus == FOCUS_MEMORY);
            auto lines = view.render();
            for (const auto& line : lines)
                std::cout << line << "\n";
        }
        std::cout << std::setfill(' ') << std::right << std::dec;
        std::vector<std::string> left_lines;
        std::vector<std::string> right_lines;
        if (m_show_regs) {
            RegisterView view(vm, m_debugger.get_prev_state(), m_focus == FOCUS_REGS, m_debugger.get_tstates());
            auto regs_lines = view.render();
            left_lines.insert(left_lines.end(), regs_lines.begin(), regs_lines.end());
        }
        if (m_show_stack) {
            StackView view(vm, m_stack_view_addr, m_focus == FOCUS_STACK);
            auto stack_lines = view.render();
            right_lines.insert(right_lines.end(), stack_lines.begin(), stack_lines.end());
        }
        print_separator();
        print_columns(left_lines, right_lines, 40);
        print_separator();
        left_lines.clear();
        right_lines.clear();
        if (m_show_code) {
            int width = (m_show_watch || m_show_breakpoints) ? 0 : terminal_width;
            
            uint16_t view_pc = m_code_view_addr;
            uint16_t highlight_pc = pc;
            if (cpu.is_halted()) {
                highlight_pc = pc - 1;
                if (view_pc == pc) view_pc = highlight_pc;
            }

            CodeView view(vm, view_pc, m_code_rows, highlight_pc, width, m_focus == FOCUS_CODE, m_debugger.get_last_pc(), m_debugger.has_history(), m_debugger.pc_moved());
            auto code_lines = view.render();
            left_lines.insert(left_lines.end(), code_lines.begin(), code_lines.end());
        }
        if (m_show_watch || m_show_breakpoints) {
            // [WATCH]
            if (m_show_watch) {
                if (m_focus == FOCUS_WATCH) right_lines.push_back(Terminal::YELLOW + "[WATCH]" + Terminal::RESET);
                else right_lines.push_back(Terminal::GREEN + "[WATCH]" + Terminal::RESET);
                
                const auto& watches = m_debugger.get_watches();
                for (uint16_t addr : watches) {
                    uint8_t val = vm.get_memory().read(addr);
                    std::stringstream ss;
                    ss << "  " << Strings::hex16(addr) << ": " << Terminal::HI_WHITE << Strings::hex8(val) << Terminal::RESET;
                    if (std::isprint(val)) ss << " (" << Terminal::HI_YELLOW << (char)val << Terminal::RESET << ")";
                    right_lines.push_back(ss.str());
                }
                if (watches.empty()) {
                    right_lines.push_back(Terminal::GRAY + "  No items." + Terminal::RESET);
                    right_lines.push_back(Terminal::GRAY + "  Use 'w <addr>'" + Terminal::RESET);
                }
                right_lines.push_back("");
            }
            
            // [BREAKPOINTS]
            if (m_show_breakpoints) {
                if (m_focus == FOCUS_BREAKPOINTS) right_lines.push_back(Terminal::YELLOW + "[BREAKPOINTS]" + Terminal::RESET);
                else right_lines.push_back(Terminal::GREEN + "[BREAKPOINTS]" + Terminal::RESET);
                int i = 1;
                const auto& breakpoints = m_debugger.get_breakpoints();
                for (const auto& bp : breakpoints) {
                    std::stringstream ss;
                    ss << "  " << i++ << ". " << Strings::hex16(bp.addr);
                    if (!bp.enabled) ss << Terminal::GRAY << " [Disabled]" << Terminal::RESET;
                    right_lines.push_back(ss.str());
                }
                if (breakpoints.empty()) {
                    right_lines.push_back(Terminal::GRAY + "  No items." + Terminal::RESET);
                    right_lines.push_back(Terminal::GRAY + "  Use 'b <addr>'" + Terminal::RESET);
                }
            }
            print_columns(left_lines, right_lines, 40);
        } else 
            for (const auto& l : left_lines)
                std::cout << l << "\n";
        print_output_buffer();
        print_separator();
        print_footer();
        std::cout << std::flush;
}

void Dashboard::print_output_buffer() {
    if (m_output_buffer.tellp() > 0) {
        std::cout << Terminal::yellow("[OUTPUT]") << "\n";
        std::cout << m_output_buffer.str();
        m_output_buffer.str("");
        m_output_buffer.clear();
    }
}

void Dashboard::print_footer() {
        const struct { const char* k; const char* n; } cmds[] = {
            {"s", "tep"}, {"n", "ext"}, {"c", "ontinue"},
            {"b", "reak"}, {"w", "atch"}, {"h", "elp"}, {"q", "uit"}
        };
        for (const auto& c : cmds) {
            std::cout << Terminal::GRAY << "[" << Terminal::HI_WHITE << Terminal::BOLD << c.k << Terminal::RESET << Terminal::GRAY << "]" << c.n << " " << Terminal::RESET;
        }
        std::cout << "\n";
}

void Dashboard::print_columns(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width) {
        size_t rows = std::max(left.size(), right.size());
        static const std::regex ansi_regex("\x1B\\[[0-9;]*[mK]");

        for (size_t i = 0; i < rows; ++i) {
            std::string l = (i < left.size()) ? left[i] : "";
            
            std::string plain = std::regex_replace(l, ansi_regex, "");
            size_t len = plain.length();
            
            int padding = (int)left_width - (int)len;
            if (padding < 0) padding = 0;

            bool has_bg = (l.find("[100m") != std::string::npos);

            std::cout << l;
            if (has_bg) std::cout << Terminal::BG_DARK_GRAY;
            std::cout << std::string(padding, ' ');
            if (has_bg) std::cout << Terminal::RESET;

            std::cout << Terminal::GRAY << " | " << Terminal::RESET;

            if (i < right.size()) {
                std::cout << " " << right[i];
            }
            std::cout << "\n";
        }
}


int DebugEngine::run() {
    if (!m_options.entryPointStr.empty()) {
        try {
            std::string ep = m_options.entryPointStr;
            size_t colon = ep.find(':');
            if (colon != std::string::npos) {
                ep = ep.substr(0, colon);
            }
            uint16_t pc = m_vm.parse_address(ep);
            m_vm.get_cpu().set_PC(pc);
        } catch (const std::exception& e) {
            std::cerr << "Error parsing entry point: " << e.what() << "\n";
        }
    }

    Debugger debugger(m_vm);
    Dashboard dashboard(debugger, m_repl);
    dashboard.run();
    
    return 0;
}
