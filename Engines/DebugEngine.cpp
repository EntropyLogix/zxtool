#include "DebugEngine.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cctype>
#include <algorithm>
#include <replxx.hxx>
#include <utility>

#include "../Utils/Strings.h"
#include "../Utils/Terminal.h"
#include "../Core/Expression.h"

static constexpr const char* HISTORY_FILE = ".zxtool_history";

std::string DebugView::format_header(const std::string& title, const std::string& extra) const {
    std::stringstream ss;
    if (m_has_focus)
        ss << m_theme.header_focus << "[" << title << "]" << Terminal::RESET;
    else
        ss << m_theme.header_blur << "[" << title << "]" << Terminal::RESET;
    if (!extra.empty())
        ss << extra;
    return ss.str();
}

std::vector<std::string> MemoryView::render() {
    std::vector<std::string> lines;
    std::string sep = m_theme.separator + std::string(80, '-') + Terminal::RESET;
    lines.push_back(sep);
    std::stringstream extra;
    extra << m_theme.value_dim << " View: " << m_theme.value_dim << Strings::hex(m_start_addr) << Terminal::RESET;
    lines.push_back(format_header("MEMORY", extra.str()));
    lines.push_back(sep);
    auto& mem = m_core.get_memory();
    for (int row = 0; row < m_rows; ++row) {
        std::stringstream ss;
        uint16_t addr = m_start_addr + (row * 16);
        ss << m_theme.address << Strings::hex(addr) << Terminal::RESET << ": ";
        for (size_t j = 0; j < 16; ++j) {
            uint8_t b = mem.peek(addr + j);
            if (b == 0)
                ss << m_theme.value_dim << "00" << Terminal::RESET;
            else
                ss << Strings::hex(b);
            if (j == 7)
                ss << "  ";
            else if (j == 15)
                ss << "  ";
            else
                ss << " ";
        }
        ss << m_theme.separator << "|" << Terminal::RESET << " ";
        for (size_t j = 0; j < 16; ++j) {
            uint8_t val = mem.peek(addr + j);
            if (std::isprint(val))
                ss << m_theme.highlight << (char)val << Terminal::RESET;
            else
                ss << m_theme.value_dim << "." << Terminal::RESET;
        }
        lines.push_back(ss.str());
    }
    return lines;
}

std::vector<std::string> RegisterView::render() {
    std::vector<std::string> lines;
    long long delta = (long long)m_tstates - m_prev.m_ticks;
    std::stringstream extra;
    extra << m_theme.value_dim << " T: " << Terminal::RESET << m_tstates;
    if (delta > 0)
        extra << m_theme.error << " (+" << delta << ")" << Terminal::RESET;
    lines.push_back(format_header("REGS", extra.str()));
    auto& cpu = m_core.get_cpu();
    auto fmt_reg16 = [&](const std::string& l, uint16_t v, uint16_t pv) -> std::string {
        std::stringstream ss;
        ss << m_theme.reg << std::setw(3) << std::left << l << Terminal::RESET << ": " 
            << (v != pv ? m_theme.highlight : m_theme.value_dim) << Strings::hex(v) << Terminal::RESET;
        return ss.str();
    };
    auto fmt_reg8_compact = [&](const std::string& l, uint8_t v, uint8_t pv) -> std::string {
        std::stringstream ss;
        ss << m_theme.reg << l << Terminal::RESET << ":" 
            << (v != pv ? m_theme.highlight : m_theme.value_dim) << Strings::hex(v) << Terminal::RESET;
        return ss.str();
    };
    std::stringstream ss;
    ss << "  " << fmt_reg16("AF", cpu.get_AF(), m_prev.m_AF.w)  << "   " << fmt_reg16("AF'", cpu.get_AFp(), m_prev.m_AFp.w) << "   " << fmt_reg16("PC", cpu.get_PC(), m_prev.m_PC.w);
    lines.push_back(ss.str());
    ss.str("");
    ss << "  " << fmt_reg16("BC", cpu.get_BC(), m_prev.m_BC.w)  << "   " << fmt_reg16("BC'", cpu.get_BCp(), m_prev.m_BCp.w)  << "   " << fmt_reg16("SP", cpu.get_SP(), m_prev.m_SP.w);
    lines.push_back(ss.str());
    ss.str(""); 
    ss << "  " << fmt_reg16("DE", cpu.get_DE(), m_prev.m_DE.w)  << "   " << fmt_reg16("DE'", cpu.get_DEp(), m_prev.m_DEp.w)  << "   " << fmt_reg8_compact("I", cpu.get_I(), m_prev.m_I)  << " " << fmt_reg8_compact("R", cpu.get_R(), m_prev.m_R);
    lines.push_back(ss.str());
    ss.str(""); 
    ss << "  " << fmt_reg16("HL", cpu.get_HL(), m_prev.m_HL.w)  << "   " << fmt_reg16("HL'", cpu.get_HLp(), m_prev.m_HLp.w)  << "   " << m_theme.reg << "IM" << Terminal::RESET << ":"  << (cpu.get_IRQ_mode() != m_prev.m_IRQ_mode ? m_theme.highlight : m_theme.value_dim) << (int)cpu.get_IRQ_mode() << Terminal::RESET << " " << (cpu.get_IFF1() ? (m_theme.header_blur + "EI") : (m_theme.value_dim + "DI")) << Terminal::RESET;
    lines.push_back(ss.str());
    ss.str(""); 
    ss << "  " << fmt_reg16("IX", cpu.get_IX(), m_prev.m_IX.w)  << "   " << fmt_reg16("IY", cpu.get_IY(), m_prev.m_IY.w) << "   " << m_theme.reg << std::setw(3) << std::left << "F" << Terminal::RESET << ": " << format_flags(cpu.get_AF() & 0xFF, m_prev.m_AF.w & 0xFF);
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
            ss << m_theme.highlight << Terminal::BOLD << c << Terminal::RESET;
        else if (bit)
            ss << m_theme.value << c << Terminal::RESET;
        else
            ss << m_theme.value_dim << c << Terminal::RESET;
    }
    return ss.str();
}

std::vector<std::string> StackView::render() {
    std::vector<std::string> lines;
    std::stringstream extra;
    extra << m_theme.reg << " (SP=" << m_theme.value_dim << Strings::hex(m_core.get_cpu().get_SP()) << m_theme.reg << ")" << Terminal::RESET;
    lines.push_back(format_header("STACK", extra.str()));
    for (int row=0; row<m_rows; ++row) {
        uint16_t addr = m_view_addr + row*2;
        uint8_t l = m_core.get_memory().peek(addr);
        uint8_t h = m_core.get_memory().peek(addr + 1);
        uint16_t val = l | (h << 8);
        std::stringstream ss;
        ss << "  " << m_theme.value_dim << Strings::hex(addr) << Terminal::RESET << ": " << m_theme.value_dim << Strings::hex(val) << Terminal::RESET;
        uint16_t temp_val = val;
        auto line = m_core.get_analyzer().parse_instruction(temp_val);
        if (!line.label.empty())
            ss << m_theme.highlight << " (" << line.label << ")" << Terminal::RESET;
        lines.push_back(ss.str());
    }
    return lines;
}

void CodeView::format_operands(const Z80Analyzer<Memory>::CodeLine& line, std::ostream& os, const std::string& color_num, const std::string& color_rst) {
    if (line.operands.empty()) return;
    using Operand = Z80Analyzer<Memory>::CodeLine::Operand;
    for (size_t i = 0; i < line.operands.size(); ++i) {
        if (i > 0) os << ", ";
        const auto& op = line.operands[i];
        bool is_num = (op.type == Operand::IMM8 || op.type == Operand::IMM16 || op.type == Operand::MEM_IMM16);
        if (is_num) os << color_num;
        switch (op.type) {
            case Operand::REG8: case Operand::REG16: case Operand::CONDITION: os << op.s_val; break;
            case Operand::IMM8: os << "$" << Strings::hex((uint8_t)op.num_val); break;
            case Operand::IMM16: os << "$" << Strings::hex((uint16_t)op.num_val); break;
            case Operand::MEM_IMM16: os << "($" << Strings::hex((uint16_t)op.num_val) << ")"; break;
            case Operand::PORT_IMM8: os << "($" << Strings::hex((uint8_t)op.num_val) << ")"; break;
            case Operand::MEM_REG16: os << "(" << op.s_val << ")"; break;
            case Operand::MEM_INDEXED: os << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
            case Operand::STRING: os << "\"" << op.s_val << "\""; break;
            case Operand::CHAR_LITERAL: os << "'" << (char)op.num_val << "'"; break;
            default: break;
        }
        if (is_num) os << color_rst;
    }
}

std::vector<std::string> CodeView::render() {
    std::vector<std::string> lines_out;
    lines_out.push_back(format_header("CODE"));

    if (m_has_history && m_start_addr == m_pc && (m_last_pc != m_pc || !m_pc_moved)) {
        uint16_t hist_addr = m_last_pc;
        uint16_t temp_hist = hist_addr;
        auto line = m_core.get_analyzer().parse_instruction(temp_hist);
        if (!line.mnemonic.empty()) {
            std::stringstream ss;
            ss << "  " << m_theme.value_dim << Strings::hex((uint16_t)line.address) << ": ";
            for(size_t i=0; i<std::min((size_t)4, line.bytes.size()); ++i)
                ss << Strings::hex(line.bytes[i]) << " ";
            for(size_t i=line.bytes.size(); i<4; ++i) ss << "   ";
            ss << " ";
            ss << std::left << std::setw(5) << line.mnemonic << " ";
            format_operands(line, ss, "", "");
            ss << Terminal::RESET;
            lines_out.push_back(ss.str());
        }
    }
    uint16_t temp_pc_iter = m_start_addr;
    auto* code_map = &m_core.get_code_map();
    bool first_line = true;
    int lines_count = 0;
    while (lines_count < m_rows) {
        auto lines = m_core.get_analyzer().parse_code(temp_pc_iter, 1, code_map);
        if (lines.empty())
            break;
        const auto& line = lines[0];
        auto& ctx = m_core.get_analyzer().context;
        const Comment* block_cmt = ctx.getComments().find((uint16_t)line.address, Comment::Type::Block);
        bool has_block_desc = block_cmt && !block_cmt->getText().empty();
        bool has_label = !line.label.empty();
        if (!first_line && (has_label || has_block_desc)) {
            lines_out.push_back("");
            lines_count++;
        }
        if (block_cmt) {
             const auto& desc = block_cmt->getText();
             if (!desc.empty()) {
                 std::stringstream desc_ss(desc);
                 std::string segment;
                 while(lines_count < m_rows && std::getline(desc_ss, segment, '\n')) {
                     lines_out.push_back(m_theme.value_dim + segment + Terminal::RESET);
                     lines_count++;
                 }
             }
        }
        if (!line.label.empty() && lines_count < m_rows) {
            lines_out.push_back(m_theme.label + line.label + ":" + Terminal::RESET);
            lines_count++;
        }
        std::stringstream ss;
        bool is_pc = ((uint16_t)line.address == m_pc);
        std::string bg = is_pc ? m_theme.pc_bg : "";
        std::string rst = is_pc ? (Terminal::RESET + bg) : Terminal::RESET;
        if (is_pc) 
            ss << bg << m_theme.header_blur << Terminal::BOLD << ">  " << rst;
        else
            ss << "   ";
        if (is_pc)
            ss << m_theme.pc_fg << Terminal::BOLD << Strings::hex((uint16_t)line.address) << rst << ": ";
        else
            ss << m_theme.address << Strings::hex((uint16_t)line.address) << rst << ": ";
        std::stringstream hex_ss;
        if (line.bytes.size() > 3)
            hex_ss << Strings::hex(line.bytes[0]) << " " << Strings::hex(line.bytes[1]) << " ..";
        else {
            for(size_t i=0; i<line.bytes.size(); ++i) {
                if (i > 0)
                    hex_ss << " ";
                hex_ss << Strings::hex(line.bytes[i]);
            }
        }
        std::string hex_str = hex_ss.str();
        ss << m_theme.value_dim << hex_str << rst;
        int hex_len = (int)hex_str.length();
        int hex_pad = 9 - hex_len;
        if (hex_pad > 0)
            ss << std::string(hex_pad, ' ');
        ss << "  ";
        std::stringstream mn_ss;
        if (is_pc)
            mn_ss << Terminal::BOLD << m_theme.pc_fg;
        else
            mn_ss << m_theme.mnemonic;
        mn_ss << line.mnemonic << rst;
        if (!line.operands.empty()) {
            mn_ss << " ";
            format_operands(line, mn_ss, m_theme.operand_num, rst);
        }
        std::string mn_str = mn_ss.str();
        ss << Strings::padding(Strings::truncate(mn_str, 15), 15);
        const Comment* inline_cmt = ctx.getComments().find((uint16_t)line.address, Comment::Type::Inline);
        if (inline_cmt) {
             const auto& comment = inline_cmt->getText();
             if (!comment.empty()) {
                 std::string cmt_full = "; " + comment;
                 if (cmt_full.length() > 45)
                     cmt_full = cmt_full.substr(0, 42) + "...";
                 ss << m_theme.comment << cmt_full << Terminal::RESET;
             }
        }
        if (m_width > 0) {
            std::string s = ss.str();
            if (is_pc)
                s += m_theme.pc_bg;
            s = Strings::padding(s, m_width);
            s += Terminal::RESET; 
            if (lines_count < m_rows) {
                lines_out.push_back(s);
                lines_count++;
            }
        } else
            if (lines_count < m_rows) {
                lines_out.push_back(ss.str());
                lines_count++;
            }
        first_line = false;
    }
    return lines_out;
}

void CodeView::scroll(int delta) {
    if (delta < 0) {
        m_start_addr += delta;
    } else {
        uint16_t temp = m_start_addr;
        m_core.get_analyzer().parse_instruction(temp);
        m_start_addr = temp;
    }
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
                if (check_breakpoints(m_core.get_cpu().get_PC())) break;
                m_core.get_cpu().step();
            }
        } else {
            m_core.get_cpu().step();
        }
        }
        uint16_t pc_after = m_core.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
}

void Dashboard::run() {
    init();
    m_repl.history_load(HISTORY_FILE);
    update_code_view();
    m_memory_view.set_address(m_debugger.get_core().get_cpu().get_PC());
    m_stack_view.set_address(m_debugger.get_core().get_cpu().get_SP());
    validate_focus();
    const std::string prompt_str = "[COMMAND] ";
    std::string last_command;
    while (m_running) {
        print_dashboard();
        std::string prompt = (m_focus == FOCUS_CMD) ? (m_theme.header_focus + prompt_str + Terminal::RESET) : (Terminal::RESET + m_theme.header_blur + prompt_str + Terminal::RESET);
        Focus start_focus = m_focus;
        const char* input_cstr = m_repl.input(prompt.c_str());
        if (input_cstr == nullptr)
            break;
        if (m_focus != start_focus) {
            std::string buf = input_cstr;
            if (!buf.empty()) {
                m_repl.history_add(buf);
                m_repl.invoke(replxx::Replxx::ACTION::HISTORY_LAST, 0);
            }
            continue;
        }
        std::string input(input_cstr);
        if (input.empty()) {
            if (last_command.empty())
                continue;
            input = last_command;
        } else {
            last_command = input;
            m_repl.history_add(input);
        }
        m_output_buffer << input << "\n";
        handle_command(input);
    }
    m_repl.history_save(HISTORY_FILE);
}

void Dashboard::validate_focus() {
    int attempts = 0;
    while (attempts < FOCUS_COUNT && ((m_focus == FOCUS_MEMORY && !m_show_mem) || (m_focus == FOCUS_REGS && !m_show_regs) || (m_focus == FOCUS_STACK && !m_show_stack) ||
                                      (m_focus == FOCUS_CODE && !m_show_code) || (m_focus == FOCUS_WATCH && !m_show_watch) || (m_focus == FOCUS_BREAKPOINTS && !m_show_watch))) {
        m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
        attempts++;
    }
}

void Dashboard::cmd_eval(const std::string& expr) {
    try {
        if (is_assignment(expr)) {
            cmd_set(expr);
            return;
        }
        Expression eval(m_debugger.get_core());
        Expression::Value val = eval.evaluate(expr);

        std::string prefix = "";
        if (!expr.empty() && expr[0] == '@') {
            std::string var_name = expr.substr(1);
            bool is_var_name = true;
            for(char c : var_name)
                if(!isalnum(c) && c != '_') is_var_name = false;
            if (is_var_name)
                prefix = expr + " = ";
        }
        if (val.is_register()) {
            std::string name = val.reg().getName();
            uint16_t v = val.reg().read(m_debugger.get_core().get_cpu());
            if (val.reg().is_16bit())
                m_output_buffer << prefix << name << "=$" << Strings::hex(v) << " (" << v << ")\n";
            else
                m_output_buffer << prefix << name << "=$" << Strings::hex((uint8_t)v) << " (" << v << ")\n";
        } else if (val.is_symbol()) {
            uint16_t v = val.symbol().read();
            m_output_buffer << prefix << val.symbol().getName() << " ($" << Strings::hex(v) << ")\n";
        } else
            m_output_buffer << prefix << format(val) << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::cmd_quit(const std::string&) {
    m_running = false;
}

void Dashboard::cmd_set(const std::string& args_str) {
    std::string args = Strings::trim(args_str);
    if (args.empty()) {
        m_output_buffer << "Error: Missing arguments for set command.\n";
        return;
    }
    std::string lhs_str, rhs_str;
    std::pair<std::string, std::string> parts;
    if (args.find('=') != std::string::npos)
        parts = Strings::split_once(args, '=');
    else
        parts = Strings::split_once_any(args, " \t");
    lhs_str = Strings::trim(parts.first);
    rhs_str = Strings::trim(parts.second);
    if (lhs_str.empty() || rhs_str.empty()) {
        m_output_buffer << "Error: Invalid syntax for set. Use: set <target> [=] <value>\n";
        return;
    }
    try {
        Expression eval(m_debugger.get_core());
        Expression::Value val = eval.evaluate(rhs_str);
        eval.assign(lhs_str, val);
        m_output_buffer << lhs_str << " = " << format(val) << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::cmd_undef(const std::string& args_str) {
    std::string name = Strings::trim(args_str);
    if (name.empty()) {
        m_output_buffer << "Error: Missing symbol name.\n";
        return;
    }
    if (m_debugger.get_core().get_context().getSymbols().remove(name))
        m_output_buffer << "Symbol '" << name << "' removed.\n";
    else
        m_output_buffer << "Error: Symbol '" << name << "' not found.\n";
}

void Dashboard::handle_command(const std::string& input) {
    std::string clean_input = Strings::trim(input);
    if (clean_input.empty())
        return;
    auto parts = Strings::split(clean_input);
    if (parts.empty())
        return;
    std::string cmd = parts[0];
    std::string args;
    for (size_t i = 1; i < parts.size(); ++i)
        args += (i > 1 ? " " : "") + parts[i];
    if (cmd == "?") {
        cmd_eval(args);
        return;
    }
    auto it = m_commands.find(cmd);
    if (it != m_commands.end())
        (this->*(it->second))(args);
    else
        m_output_buffer << "Unknown command: " << cmd << "\n";
}

void Dashboard::init() {
    m_repl.install_window_change_handler();    
    auto bind_scroll = [&](char32_t key, int mem_delta, int code_delta, int stack_delta) {
        m_repl.bind_key(key, [this, mem_delta, code_delta, stack_delta](char32_t code) {
        if (m_focus == FOCUS_CMD) {
            if (code == replxx::Replxx::KEY::UP)
                return m_repl.invoke(replxx::Replxx::ACTION::HISTORY_PREVIOUS, code);
            if (code == replxx::Replxx::KEY::DOWN)
                return m_repl.invoke(replxx::Replxx::ACTION::HISTORY_NEXT, code);
            return replxx::Replxx::ACTION_RESULT::CONTINUE;
        }
        if (m_focus == FOCUS_MEMORY)
            m_memory_view.scroll(mem_delta);
        else if (m_focus == FOCUS_CODE) {
            m_auto_follow = false;
            m_code_view.scroll(code_delta);
        }
        else if (m_focus == FOCUS_STACK) m_stack_view.scroll(stack_delta);
            print_dashboard();
            m_repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
            return replxx::Replxx::ACTION_RESULT::CONTINUE;
        });
    };
    bind_scroll(replxx::Replxx::KEY::UP, -16, -1, -2);
    bind_scroll(replxx::Replxx::KEY::DOWN, 16, 1, 2);

    auto tab_handler = [this](char32_t code) {
        m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
        validate_focus();
        print_dashboard();
        return replxx::Replxx::ACTION_RESULT::RETURN;
    };
    m_repl.bind_key(replxx::Replxx::KEY::TAB, tab_handler);
}

void Dashboard::print_dashboard() {
    std::cout << Terminal::CLEAR;
    auto& core = m_debugger.get_core();
    auto& cpu = core.get_cpu();
    uint16_t pc = cpu.get_PC();
    const int terminal_width = 80;
    if (m_show_mem) {
        m_memory_view.set_focus(m_focus == FOCUS_MEMORY);
        auto lines = m_memory_view.render();
        for (const auto& line : lines)
            std::cout << line << "\n";
    }
    std::cout << std::setfill(' ') << std::right << std::dec;
    std::vector<std::string> left_lines;
    std::vector<std::string> right_lines;
    if (m_show_regs) {
        m_register_view.set_focus(m_focus == FOCUS_REGS);
        m_register_view.set_state(m_debugger.get_prev_state(), m_debugger.get_tstates());
        auto regs_lines = m_register_view.render();
        left_lines.insert(left_lines.end(), regs_lines.begin(), regs_lines.end());
    }
    if (m_show_stack) {
        m_stack_view.set_focus(m_focus == FOCUS_STACK);
        auto stack_lines = m_stack_view.render();
        right_lines.insert(right_lines.end(), stack_lines.begin(), stack_lines.end());
    }
    print_separator();
    print_columns(left_lines, right_lines, 40);
    print_separator();
    left_lines.clear();
    right_lines.clear();
    if (m_show_code) {
        int width = terminal_width;    
        uint16_t view_pc = m_code_view.get_address();
        uint16_t highlight_pc = pc;
        if (cpu.is_halted()) {
            highlight_pc = pc - 1;
            if (view_pc == pc)
                view_pc = highlight_pc;
        }
        m_code_view.set_focus(m_focus == FOCUS_CODE);
        m_code_view.set_state(highlight_pc, width, m_debugger.get_last_pc(), m_debugger.has_history(), m_debugger.pc_moved());
        auto code_lines = m_code_view.render();
        for (const auto& l : code_lines)
            std::cout << l << "\n";
    }
    if (m_show_watch) {
        print_separator();
        std::cout << (m_focus == FOCUS_WATCH || m_focus == FOCUS_BREAKPOINTS ? m_theme.header_focus : m_theme.header_blur) << "[STATUS]" << Terminal::RESET << "\n";
        std::stringstream ss;
        std::string label = " WATCH: ";
        ss << m_theme.label << label << Terminal::RESET;
        const auto& watches = m_debugger.get_watches();
        std::vector<std::string> items;
        for (uint16_t addr : watches) {
            uint8_t val = core.get_memory().peek(addr);
            std::stringstream item_ss;
            auto pair = core.get_context().getSymbols().find_nearest(addr);
            if (!pair.first.empty() && pair.second == addr)
                item_ss << pair.first;
            else item_ss << Strings::hex(addr);
                item_ss << "=" << (int)val;
            items.push_back(item_ss.str());
        }    
        int max_len = 80;
        int current_len = (int)label.length();
        bool first = true;
        for (size_t i = 0; i < items.size(); ++i) {
            std::string sep = first ? "" : ", ";
            if (current_len + sep.length() + items[i].length() > (size_t)(max_len - 10)) {
                ss << m_theme.value_dim << "... (+" << (items.size() - i) << ")" << Terminal::RESET;
                break;
            }
            ss << m_theme.value << sep << items[i] << Terminal::RESET;
            current_len += sep.length() + items[i].length();
            first = false;
        }
        if (items.empty())
            ss << m_theme.value_dim << "No items." << Terminal::RESET;
        std::cout << ss.str() << "\n";
        ss.str(""); ss.clear();
        label = " BREAK: ";
        ss << m_theme.error << label << Terminal::RESET;
        const auto& breakpoints = m_debugger.get_breakpoints();
        items.clear();
        for (const auto& bp : breakpoints) {
            std::stringstream item_ss;
            item_ss << (bp.enabled ? "*" : "o") << Strings::hex(bp.addr);
            auto pair = core.get_context().getSymbols().find_nearest(bp.addr);
            if (!pair.first.empty() && pair.second == bp.addr)
                item_ss << " (" << pair.first << ")";
            items.push_back(item_ss.str());
        }    
        max_len = 80;
        current_len = (int)label.length();
        first = true;
        for (size_t i = 0; i < items.size(); ++i) {
            std::string sep = first ? "" : ", ";
            if (current_len + sep.length() + items[i].length() > (size_t)(max_len - 10)) {
                ss << m_theme.value_dim << "... (+" << (items.size() - i) << ")" << Terminal::RESET;
                break;
            }
            ss << m_theme.value << sep << items[i] << Terminal::RESET;
            current_len += sep.length() + items[i].length();
            first = false;
        }
        if (items.empty())
            ss << m_theme.value_dim << "No items." << Terminal::RESET;
        std::cout << ss.str() << "\n";
        print_separator();
    }
    bool has_output = (m_output_buffer.tellp() > 0);
    print_output_buffer();
    if (has_output || !m_show_watch)
        print_separator();
    print_footer();
    std::cout << std::flush;
}

void Dashboard::print_output_buffer() {
    if (m_output_buffer.tellp() > 0) {
        std::cout << m_theme.header_blur << "[OUTPUT]" << Terminal::RESET << "\n";
        std::cout << m_output_buffer.str();
        m_output_buffer.str("");
        m_output_buffer.clear();
    }
}

void Dashboard::print_footer() {
    const struct { const char* k; const char* n; } cmds[] = {
        {"c", "omment"}, {"g", "o"}, {"s", "tep"}, {"n", "ext"},
        {"r", "eset"}, {"h", "eader"}, {"q", "uit"}
    };
    for (const auto& c : cmds)
        std::cout << m_theme.value << "[" << c.k << "]" << c.n << " " << Terminal::RESET;
    std::cout << "\n";
}

void Dashboard::update_code_view() {
    if (!m_auto_follow)
        return;
    m_code_view.set_address(m_debugger.get_core().get_cpu().get_PC());
}

void Dashboard::print_columns(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width) {
    size_t rows = std::max(left.size(), right.size());
    for (size_t row = 0; row < rows; ++row) {
        std::string l = (row < left.size()) ? left[row] : "";
        bool has_bg = (l.find("[100m") != std::string::npos);
        if (!right.empty()) {
            std::string l_padded = l;
            if (has_bg)
                l_padded += m_theme.pc_bg;
            std::cout << Strings::padding(l_padded, left_width);
            if (has_bg)
                std::cout << Terminal::RESET;
            std::cout << m_theme.separator << " | " << Terminal::RESET;
            if (row < right.size())
                std::cout << " " << right[row];
        } else {
            std::cout << l;
            if (has_bg)
                std::cout << m_theme.pc_bg << Terminal::RESET;
        }
        std::cout << "\n";
    }
}

int DebugEngine::run() {
    if (!m_options.entryPointStr.empty()) {
        try {
            std::string ep = m_options.entryPointStr;
            auto parts = Strings::split(ep, ':');
            if (!parts.empty()) ep = parts[0];
            
            int32_t val = 0;
            if (Strings::parse_integer(ep, val))
                m_core.get_cpu().set_PC((uint16_t)val);
            else
                throw std::runtime_error("Invalid address format");
        } catch (const std::exception& e) {
            std::cerr << "Error parsing entry point: " << e.what() << "\n";
        }
    }
    Debugger debugger(m_core);
    Dashboard dashboard(debugger, m_repl);
    dashboard.run();
    return 0;
}

// Helper to format sequences with collapsing logic
template <typename T>
std::string Dashboard::format_sequence(const std::vector<T>& data, 
                                   const std::string& prefix, 
                                   const std::string& suffix, 
                                   const std::string& separator,
                                   bool use_hex_prefix,
                                   bool allow_step_gt_1) {
    std::stringstream ss;
    ss << prefix;
    for (size_t i = 0; i < data.size(); ) {
        if (i > 0) ss << separator;
        
        size_t best_len = 1;
        int64_t best_step = 0;

        if (i + 1 < data.size()) {
            int64_t diff = (int64_t)data[i+1] - (int64_t)data[i];
            bool valid_step = (std::abs(diff) == 1) || (allow_step_gt_1 && diff != 0);
            
            if (valid_step) {
                size_t j = i + 1;
                while (j + 1 < data.size()) {
                    if ((int64_t)data[j+1] - (int64_t)data[j] != diff) break;
                    j++;
                }
                size_t len = j - i + 1;
                // Collapse rule: Only collapse if sequence length > 5
                if (len > 5) { best_len = len; best_step = diff; }
            }
        }

        auto fmt_item = [&](T v) {
            if (use_hex_prefix) ss << "$";
            ss << Strings::hex(v);
        };

        if (best_len > 1) {
            fmt_item(data[i]);
            ss << "..";
            fmt_item(data[i + best_len - 1]);
            if (std::abs(best_step) != 1) {
                ss << ":";
                ss << std::dec << std::abs(best_step);
            }
            i += best_len;
        } else {
            fmt_item(data[i]);
            i++;
        }
    }
    ss << suffix;
    return ss.str();
}

std::string Dashboard::format(const Expression::Value& val, bool detailed) {
    std::stringstream ss;
    
    if (detailed) {
        switch (val.type()) {
            case Expression::Value::Type::Number: ss << "Number: "; break;
            case Expression::Value::Type::Register: ss << "Register: "; break;
            case Expression::Value::Type::Symbol: ss << "Symbol: "; break;
            case Expression::Value::Type::String: ss << "String(" << val.string().length() << "): "; break;
            case Expression::Value::Type::Bytes: ss << "Bytes(" << val.bytes().size() << "): "; break;
            case Expression::Value::Type::Words: ss << "Words(" << val.words().size() << "): "; break;
            case Expression::Value::Type::Address: ss << "Address(" << val.address().size() << "): "; break;
        }
    }

    switch (val.type()) {
        case Expression::Value::Type::Number: {
            double d = val.number();
            if (d == (int64_t)d) {
                int64_t i = (int64_t)d;
                if (i >= 0 && i <= 255) {
                    ss << "$" << Strings::hex((uint8_t)i) << " (" << i << ")";
                } else if (i >= -32768 && i <= 65535) {
                    ss << "$" << Strings::hex((uint16_t)i) << " (" << i << ")";
                } else {
                    std::stringstream temp_ss;
                    temp_ss << std::hex << std::uppercase << i;
                    ss << "$" << temp_ss.str() << " (" << i << ")";
                }
            } else {
                ss << d;
            }
            break;
        }
        case Expression::Value::Type::String:
            ss << "\"" << val.string() << "\"";
            break;
        case Expression::Value::Type::Bytes:
            ss << format_sequence(val.bytes(), "{", "}", " ", true, true);
            break;
        case Expression::Value::Type::Words:
            ss << format_sequence(val.words(), "W{", "}", " ", true, true);
            break;
        case Expression::Value::Type::Address:
            ss << format_sequence(val.address(), "[", "]", ", ", true, true);
            break;
        case Expression::Value::Type::Register:
            ss << val.reg().getName();
            break;
        case Expression::Value::Type::Symbol:
            ss << val.symbol().getName();
            break;
    }
    return ss.str();
}

bool Dashboard::is_assignment(const std::string& expr) {
    int depth = 0;
    bool in_string = false;
    char quote_char = 0;

    for (size_t i = 0; i < expr.length(); ++i) {
        char c = expr[i];
        if (in_string) {
            if (c == quote_char)
                in_string = false;
            continue;
        }
        if (c == '"' || c == '\'') {
            in_string = true;
            quote_char = c;
            continue;
        }
        if (c == '(' || c == '[' || c == '{') {
            depth++;
        } else if (c == ')' || c == ']' || c == '}') {
            depth--;
        } else if (c == '=' && depth == 0) {
            bool is_cmp = false;
            if (i > 0) {
                char prev = expr[i-1];
                if (prev == '!' || prev == '<' || prev == '>' || prev == '=')
                    is_cmp = true;
            }
            if (i + 1 < expr.length()) {
                char next = expr[i+1];
                if (next == '=')
                    is_cmp = true;
            }
            if (!is_cmp) {
                return true;
            }
        }
    }
    return false;
}
