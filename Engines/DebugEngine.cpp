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
#include "../Utils/Checksum.h"
#include "../Core/Expression.h"
#include "../Core/Variables.h"
#include <numeric>
#include <limits>
#include <bitset>

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
    const char* syms = "SZYHXPNC";
    for (int i = 7; i >= 0; --i) {
        bool bit = (f >> i) & 1;
        bool prev_bit = (prev_f >> i) & 1;
        char c = bit ? syms[7-i] : '.';
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

void Dashboard::perform_evaluate(const std::string& expr, bool detailed) {
    try {
        Expression eval(m_debugger.get_core());
        Expression::Value val = eval.evaluate(expr);
        
        if (detailed && !expr.empty() && expr[0] == '@') {
            bool is_var = true;
            for (size_t i = 1; i < expr.length(); ++i) {
                if (!isalnum(expr[i]) && expr[i] != '_') {
                    is_var = false;
                    break;
                }
            }
            if (is_var) {
                m_output_buffer << "VARIABLE: " << expr << "\n";
                std::string type_name = "Unknown";
                if (val.is_address()) type_name = "Address (Pointer)";
                else if (val.is_number()) type_name = "Number";
                else if (val.is_bytes()) type_name = "Bytes (Array)";
                else if (val.is_words()) type_name = "Words (Array)";
                else if (val.is_string()) type_name = "String";
                else if (val.is_register()) type_name = "Register";
                m_output_buffer << "Type:     " << type_name << "\n";
                m_output_buffer << "------------------------------------------------------------\n";
            }
        }
        m_output_buffer << format(val, detailed) << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::perform_set(const std::string& args_str, bool detailed) {
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
        parts = Strings::split_once(args, " \t");
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
        m_output_buffer << lhs_str << " = " << format(val, detailed) << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::cmd_evaluate(const std::string& args) {
    perform_evaluate(args, false);
}

void Dashboard::cmd_expression(const std::string& args) {
    if (is_assignment(args))
        perform_set(args, false);
    else
        perform_evaluate(args, false);
}

void Dashboard::cmd_expression_detailed(const std::string& args) {
    if (is_assignment(args))
        perform_set(args, true);
    else
        perform_evaluate(args, true);
}

void Dashboard::cmd_quit(const std::string&) {
    m_running = false;
}

void Dashboard::cmd_set(const std::string& args_str) {
    perform_set(args_str, false);
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
    const CommandEntry* best_entry = nullptr;
    std::string best_cmd;
    for (const auto& pair : m_commands) {
        const std::string& cmd_key = pair.first;
        const CommandEntry& entry = pair.second;
        if (clean_input.compare(0, cmd_key.length(), cmd_key) == 0) {
            if (entry.require_separator) {
                if (clean_input.length() > cmd_key.length() && !std::isspace(static_cast<unsigned char>(clean_input[cmd_key.length()])))
                    continue;
            }
            if (cmd_key.length() > best_cmd.length()) {
                best_cmd = cmd_key;
                best_entry = &entry;
            }
        }
    }
    if (!best_cmd.empty() && best_entry) {
        std::string args = Strings::trim(clean_input.substr(best_cmd.length()));
        (this->*(best_entry->handler))(args);
    } else {
        auto parts = Strings::split_once(clean_input, " \t");
        m_output_buffer << "Unknown command: " << parts.first << "\n";
    }
}

void Dashboard::init() {
    static const std::vector<std::string> commands = {
        "help", "quit", "exit", "map", "stack", "memory", "reg", "rm", 
        "asm", "disasm", "dump", "load", "save", "break", "watch", 
        "step", "run", "toggle", "sym", "find", "fill", "data", "code",
        "set", "eval", "bit", "res", "lines", "undef", "?", "??"
    };

    static const std::vector<std::string> eval_keywords = {
        "af", "bc", "de", "hl", "ix", "iy", "sp", "pc",
        "a", "f", "b", "c", "d", "e", "h", "l", "i", "r",
        "af'", "bc'", "de'", "hl'",
        "low", "high", "len", "abs", "sign", "sqrt", "min", "max", "clamp",
        "sin", "cos", "deg", "rad", "int", "floor", "round", "ceil", "pow2",
        "align", "wrap", "sum", "avg", "all", "any", "asm", "copy", "bytes",
        "words", "str", "val", "hex", "bin", "bcd", "dec", "checksum", "crc"
    };

    m_repl.set_completion_callback([this](std::string const& input, int& contextLen) {
        std::vector<replxx::Replxx::Completion> completions;
        std::string prefix;
        
        size_t first_space = input.find_first_of(" \t");
        if (first_space == std::string::npos) {
            prefix = input;
            contextLen = prefix.length();
            for (const auto& cmd : commands) {
                if (cmd.find(prefix) == 0) {
                    completions.emplace_back(cmd.c_str());
                }
            }
        } else {
            std::string cmd = input.substr(0, first_space);
            bool is_eval = (cmd == "eval" || cmd == "evaluate" || cmd == "?" || cmd == "??" || cmd == "set");
            
            if (is_eval) {
                size_t lastSep = input.find_last_of(" \t,()[]{}+-*/");
                if (lastSep == std::string::npos) prefix = input;
                else prefix = input.substr(lastSep + 1);
                
                contextLen = prefix.length();
                if (prefix.empty()) return completions;

                if (prefix[0] == '@') {
                    std::string var_prefix = prefix.substr(1);
                    const auto& vars = m_debugger.get_core().get_context().getVariables().by_name();
                    for (const auto& pair : vars) {
                        if (pair.first.find(var_prefix) == 0) {
                            std::string comp = "@" + pair.first;
                            completions.emplace_back(comp.c_str());
                        }
                    }
                } else {
                    for (const auto& kw : eval_keywords) {
                        if (kw.find(prefix) == 0) {
                            completions.emplace_back(kw.c_str());
                        }
                    }
                    
                    const auto& symbols = m_debugger.get_core().get_context().getSymbols().by_name();
                    for (const auto& pair : symbols) {
                        if (pair.first.find(prefix) == 0) {
                            completions.emplace_back(pair.first.c_str());
                        }
                    }
                }
            }
        }
        return completions;
    });

    m_repl.set_hint_callback([this](std::string const& input, int& contextLen, replxx::Replxx::Color& color) {
        std::vector<std::string> hints;
        std::string prefix;
        
        size_t first_space = input.find_first_of(" \t");
        if (first_space == std::string::npos) {
            prefix = input;
            contextLen = prefix.length();
            for (const auto& cmd : commands) {
                if (cmd.find(prefix) == 0 && cmd.length() > prefix.length()) {
                    hints.push_back(cmd);
                }
            }
        } else {
            std::string cmd = input.substr(0, first_space);
            bool is_eval = (cmd == "eval" || cmd == "evaluate" || cmd == "?" || cmd == "??" || cmd == "set");
            
            if (is_eval) {
                size_t lastSep = input.find_last_of(" \t,()[]{}+-*/");
                if (lastSep == std::string::npos) prefix = input;
                else prefix = input.substr(lastSep + 1);
                
                contextLen = prefix.length();
                if (prefix.empty()) return hints;

                if (prefix[0] == '@') {
                    std::string var_prefix = prefix.substr(1);
                    const auto& vars = m_debugger.get_core().get_context().getVariables().by_name();
                    for (const auto& pair : vars) {
                        if (pair.first.find(var_prefix) == 0 && pair.first.length() > var_prefix.length()) {
                            hints.push_back("@" + pair.first);
                        }
                    }
                } else {
                    for (const auto& kw : eval_keywords) {
                        if (kw.find(prefix) == 0 && kw.length() > prefix.length()) {
                            hints.push_back(kw);
                        }
                    }
                    
                    const auto& symbols = m_debugger.get_core().get_context().getSymbols().by_name();
                    for (const auto& pair : symbols) {
                        if (pair.first.find(prefix) == 0 && pair.first.length() > prefix.length()) {
                            hints.push_back(pair.first);
                        }
                    }
                }
            }
        }
        
        color = replxx::Replxx::Color::GRAY;
        return hints;
    });

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
        if (m_focus == FOCUS_CMD) {
            std::string val(m_repl.get_state().text());
            if (!val.empty()) {
                return m_repl.invoke(replxx::Replxx::ACTION::COMPLETE_NEXT, code);
            }
        }
        m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
        validate_focus();
        print_dashboard();
        return replxx::Replxx::ACTION_RESULT::RETURN;
    };
    m_repl.bind_key(replxx::Replxx::KEY::TAB, tab_handler);

    auto esc_handler = [this](char32_t code) {
        if (m_focus == FOCUS_CMD) {
            m_repl.set_state(replxx::Replxx::State(""));
            print_dashboard();
            return replxx::Replxx::ACTION_RESULT::RETURN;
        }
        return replxx::Replxx::ACTION_RESULT::CONTINUE;
    };
    m_repl.bind_key(replxx::Replxx::KEY::ESCAPE, esc_handler);
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
        
        // 1. Arithmetic Progression Detection
        size_t arith_len = 1;
        int64_t arith_step = 0;

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
                if (len > 5) { arith_len = len; arith_step = diff; }
            }
        }

        // 2. Repetition Detection
        size_t rep_pat_len = 0;
        size_t rep_count = 0;
        size_t rep_total_len = 0;

        // 2a. RLE (L=1)
        {
            size_t j = i + 1;
            while (j < data.size() && data[j] == data[i]) j++;
            size_t count = j - i;
            if (count >= 4) {
                rep_pat_len = 1;
                rep_count = count;
                rep_total_len = count;
            }
        }

        // 2b. Pattern (L>1)
        size_t remaining = data.size() - i;
        size_t max_pat_len = std::min(remaining / 2, (size_t)16);

        for (size_t len = 2; len <= max_pat_len; ++len) {
            size_t count = 1;
            size_t pos = i + len;
            while (pos + len <= data.size()) {
                bool match = true;
                for (size_t k = 0; k < len; ++k) {
                    if (data[i + k] != data[pos + k]) {
                        match = false;
                        break;
                    }
                }
                if (match) { count++; pos += len; } else break;
            }
            if (count >= 3) {
                size_t total = count * len;
                if (total > rep_total_len) {
                    rep_total_len = total;
                    rep_pat_len = len;
                    rep_count = count;
                }
            }
        }

        // 3. Decision & Formatting
        auto fmt_item = [&](T v) { if (use_hex_prefix) ss << "$"; ss << Strings::hex(v); };

        if (rep_total_len > arith_len) {
            std::vector<T> pattern;
            for(size_t k=0; k<rep_pat_len; ++k) pattern.push_back(data[i+k]);
            ss << format_sequence(pattern, "{", "}", separator, use_hex_prefix, false) << " x " << std::dec << rep_count;
            i += rep_total_len;
        } else if (arith_len > 1) {
            fmt_item(data[i]);
            ss << "..";
            fmt_item(data[i + arith_len - 1]);
            if (std::abs(arith_step) != 1) {
                ss << ":" << std::dec << std::abs(arith_step);
            }
            i += arith_len;
        } else {
            fmt_item(data[i]);
            i++;
        }
    }
    ss << suffix;
    return ss.str();
}

void Dashboard::print_asm_info(std::stringstream& ss, uint16_t addr) {
    auto& core = m_debugger.get_core();
    uint8_t byte_val = core.get_memory().peek(addr);
    ss << "  Content: Byte($" << Strings::hex(byte_val) << ")";
    auto line = core.get_analyzer().parse_instruction(addr);
    if (!line.mnemonic.empty()) {
        ss << " / Asm: " << line.mnemonic;
        if (!line.operands.empty()) {
            ss << " ";
            using Operand = Z80Analyzer<Memory>::CodeLine::Operand;
            for (size_t i = 0; i < line.operands.size(); ++i) {
                if (i > 0) ss << ", ";
                const auto& op = line.operands[i];
                switch (op.type) {
                    case Operand::REG8: case Operand::REG16: case Operand::CONDITION: ss << op.s_val; break;
                    case Operand::IMM8: ss << "$" << Strings::hex((uint8_t)op.num_val); break;
                    case Operand::IMM16: ss << "$" << Strings::hex((uint16_t)op.num_val); break;
                    case Operand::MEM_IMM16: ss << "($" << Strings::hex((uint16_t)op.num_val) << ")"; break;
                    case Operand::PORT_IMM8: ss << "($" << Strings::hex((uint8_t)op.num_val) << ")"; break;
                    case Operand::MEM_REG16: ss << "(" << op.s_val << ")"; break;
                    case Operand::MEM_INDEXED: ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                    case Operand::STRING: ss << "\"" << op.s_val << "\""; break;
                    case Operand::CHAR_LITERAL: ss << "'" << (char)op.num_val << "'"; break;
                    default: break;
                }
            }
        }
    }
}

std::string Dashboard::format_hex_fixed(uint64_t v, int w) {
    std::stringstream hss;
    hss << std::hex << std::uppercase << std::setfill('0');
    if (w == 8) hss << std::setw(2) << (v & 0xFF);
    else if (w == 16) hss << std::setw(4) << (v & 0xFFFF);
    else if (w == 32) {
        hss << std::setw(8) << (v & 0xFFFFFFFF);
    } else {
        hss << std::setw(16) << v;
    }
    return hss.str();
}

std::string Dashboard::format_bin_fixed(uint64_t v, int bits) {
    std::string b;
    for (int i = bits - 1; i >= 0; --i) {
        b += ((v >> i) & 1) ? '1' : '0';
        if (i > 0 && i % 8 == 0) b += " ";
    }
    return b;
}

std::string Dashboard::format_disasm(uint16_t addr, const Z80Analyzer<Memory>::CodeLine& line) {
    std::stringstream lss;
    lss << "$" << Strings::hex(addr) << ": ";
    std::stringstream bytes_ss;
    for (size_t i = 0; i < line.bytes.size() && i < 4; ++i) {
        bytes_ss << Strings::hex(line.bytes[i]) << " ";
    }
    lss << std::left << std::setw(12) << bytes_ss.str(); 

    if (line.mnemonic.empty()) {
            lss << ".db $" << Strings::hex(m_debugger.get_core().get_memory().peek(addr));
    } else {
        lss << line.mnemonic;
        if (!line.operands.empty()) {
            lss << " ";
            using Operand = Z80Analyzer<Memory>::CodeLine::Operand;
            for (size_t i = 0; i < line.operands.size(); ++i) {
                if (i > 0) lss << ", ";
                const auto& op = line.operands[i];
                switch (op.type) {
                    case Operand::REG8: case Operand::REG16: case Operand::CONDITION: lss << op.s_val; break;
                    case Operand::IMM8: lss << "$" << Strings::hex((uint8_t)op.num_val); break;
                    case Operand::IMM16: lss << "$" << Strings::hex((uint16_t)op.num_val); break;
                    case Operand::MEM_IMM16: lss << "($" << Strings::hex((uint16_t)op.num_val) << ")"; break;
                    case Operand::PORT_IMM8: lss << "($" << Strings::hex((uint8_t)op.num_val) << ")"; break;
                    case Operand::MEM_REG16: lss << "(" << op.s_val << ")"; break;
                    case Operand::MEM_INDEXED: lss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                    case Operand::STRING: lss << "\"" << op.s_val << "\""; break;
                    case Operand::CHAR_LITERAL: lss << "'" << (char)op.num_val << "'"; break;
                    default: break;
                }
            }
        }
    }
    return lss.str();
}

void Dashboard::format_detailed_number(std::stringstream& ss, const Expression::Value& val) {
    auto& core = m_debugger.get_core();
    double d = (val.type() == Expression::Value::Type::Number) ? val.number() : (double)val.reg().read(core.get_cpu());
    int64_t i_val = (int64_t)d;
    
    int width = 64;

    if (val.type() == Expression::Value::Type::Register) {
        width = val.reg().is_16bit() ? 16 : 8;
    } else {
        if (i_val >= -128 && i_val <= 255) width = 8;
        else if (i_val >= -32768 && i_val <= 65535) width = 16;
        else if (i_val >= std::numeric_limits<int32_t>::min() && i_val <= std::numeric_limits<uint32_t>::max()) width = 32;
    }
    
    ss << "VALUE: $" << format_hex_fixed((uint64_t)i_val, width) << " (" << std::dec << i_val << ") | Number (" << width << "-bit)\n";
    ss << "------------------------------------------------------------\n";
    ss << "Signed:  " << (i_val >= 0 ? "+" : "") << i_val << "\n";

    if (width == 64) {
        ss << "Binary:  Hi: %" << format_bin_fixed((uint64_t)i_val >> 32, 32) << "\n";
        ss << "         Lo: %" << format_bin_fixed((uint64_t)i_val & 0xFFFFFFFF, 32);
    } else {
        ss << "Binary:  %" << format_bin_fixed((uint64_t)i_val, width);
        if (width == 8) ss << " (bits 7..0)";
        else if (width == 16) ss << " (bits 15..0)";
        
        if (width == 8) {
            int ones = 0;
            for(int k=0; k<8; ++k) if((i_val >> k) & 1) ones++;
            ss << " | Parity: " << ((ones % 2 == 0) ? "Even" : "Odd");
        }
    }
    ss << "\n";
    
    if (width == 8) {
        char c = (i_val >= 32 && i_val <= 126) ? (char)i_val : '.';
        ss << "ASCII:   '" << c << "'\n";
        
        const char* mask = "SZYHXPNC";
        ss << "Flags:   ";
        for (int i = 7; i >= 0; --i) {
            bool set = (i_val >> i) & 1;
            if (set) ss << mask[7-i] << " ";
            else ss << ". ";
        }
        ss << " [SZYHXPNC]\n";
        
        ss << "         (Active: ";
        std::vector<std::string> active_flags;
        const char* full_names[] = {"Sign", "Zero", "Y", "Half-Carry", "X", "Parity/Overflow", "Subtract", "Carry"};
        for (int i = 7; i >= 0; --i) {
            if ((i_val >> i) & 1) active_flags.push_back(full_names[7-i]);
        }
        
        if (active_flags.empty()) ss << "No flags set";
        else if (active_flags.size() == 8) ss << "All flags set";
        else {
            for(size_t k=0; k<active_flags.size(); ++k) {
                if (k > 0) ss << ", ";
                ss << active_flags[k];
            }
        }
        ss << ")";
    } else if (width == 16) {
        char h = (i_val >> 8) & 0xFF;
        char l = i_val & 0xFF;
        if (h < 32 || h > 126) h = '.';
        if (l < 32 || l > 126) l = '.';
        ss << "ASCII:   '" << h << l << "'";
    } else if (width == 32) {
        ss << "ASCII:   '";
        for (int i = 3; i >= 0; --i) {
            char c = (i_val >> (i * 8)) & 0xFF;
            if (c < 32 || c > 126) c = '.';
            ss << c;
        }
        ss << "'";
    } else if (width == 64) {
        ss << "ASCII:   '";
        for (int i = 7; i >= 0; --i) {
            char c = (i_val >> (i * 8)) & 0xFF;
            if (c < 32 || c > 126) c = '.';
            ss << c;
        }
        ss << "'";
    }
}

void Dashboard::format_detailed_address(std::stringstream& ss, const Expression::Value& val) {
    auto& core = m_debugger.get_core();
    auto& analyzer = core.get_analyzer();
    auto& symbols = core.get_context().getSymbols();
    const auto& addrs = val.address();
    
    if (addrs.empty()) {
        ss << "Address: [ Empty ]";
        return;
    }
    
    bool is_contiguous = true;
    if (addrs.size() > 1) {
        for(size_t i=0; i<addrs.size()-1; ++i) {
            if (addrs[i+1] != addrs[i] + 1) {
                is_contiguous = false;
                break;
            }
        }
    }

    std::string sep = "------------------------------------------------------------\n";

    if (addrs.size() == 1 || is_contiguous) {
        uint16_t start_addr = addrs[0];
        uint16_t end_addr = addrs.back();
        size_t size = addrs.size();
        
        std::string mem_type = "Mixed (ROM/RAM)";
        if (start_addr <= end_addr) {
            if (end_addr < 0x4000) mem_type = "ROM (Read-Only)";
            else if (start_addr >= 0x4000) mem_type = "RAM (Writable)";
        }
        
        // Header
        if (size == 1) {
            ss << "ADDRESS: $" << Strings::hex(start_addr);
        } else {
            ss << "RANGE: $" << Strings::hex(start_addr) << "..$" << Strings::hex(end_addr) 
               << " (" << size << " bytes)";
        }
        ss << " | " << mem_type << "\n";
        ss << sep;

        // Symbols
        auto sym = symbols.find_nearest(start_addr);
        if (!sym.first.empty()) {
            ss << "Symbols:  " << sym.first;
            if (sym.second == start_addr) ss << " (exact)";
            else ss << " (+$" << Strings::hex((uint16_t)(start_addr - sym.second)) << ")";
            ss << "\n";
        }
        
        // Stats & Checks
        uint32_t sum = 0;
        uint8_t min_v = 0xFF;
        uint8_t max_v = 0x00;
        uint32_t crc = Checksum::CRC32_START;
        
        for (size_t i = 0; i < size; ++i) {
            uint16_t addr = start_addr + i;
            uint8_t b = core.get_memory().peek(addr);
            sum += b;
            if (b < min_v) min_v = b;
            if (b > max_v) max_v = b;
            crc = Checksum::crc32_update(crc, b);
        }
        crc = Checksum::crc32_finalize(crc);
        
        ss << "Stats:   Min: $" << Strings::hex(min_v) << ", Max: $" << Strings::hex(max_v) << ", Sum: $" << std::hex << std::uppercase << sum << std::dec << "\n";
        ss << "Checks:  Checksum: $" << Strings::hex((uint8_t)(sum & 0xFF)) << ", CRC32: $" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc << std::dec << "\n";
        ss << sep;
        
        // ASM
        ss << "ASM:\n";
        uint16_t pc = start_addr;
        int max_lines = (size == 1) ? 5 : 16;
        int lines_printed = 0;
        uint16_t limit_addr = (size == 1) ? 0xFFFF : end_addr;

        while (lines_printed < max_lines) {
            if (size > 1 && pc > limit_addr) break;
            
            auto line = analyzer.parse_instruction(pc);
            ss << format_disasm(line.address, line) << "\n";
            lines_printed++;
            
            if (line.bytes.empty()) pc++; else pc += line.bytes.size();
        }
        if (size > 1 && pc <= limit_addr) {
             ss << "... and " << (limit_addr - pc + 1) << " more bytes\n";
        }
        ss << sep;

        // DUMP
        ss << "DUMP:\n";
        size_t dump_bytes = (size == 1) ? 8 : std::min(size, (size_t)32);
        
        for (size_t i = 0; i < dump_bytes; i += 8) {
            uint16_t row_addr = start_addr + i;
            ss << "$" << Strings::hex(row_addr) << ": ";
            std::string ascii_part;
            for (size_t j = 0; j < 8; ++j) {
                bool in_range = (size == 1) || (i + j < size);
                if (in_range) {
                    uint8_t b = core.get_memory().peek(row_addr + j);
                    ss << Strings::hex(b) << " ";
                    ascii_part += (b >= 32 && b <= 126) ? (char)b : '.';
                } else {
                    ss << "   ";
                }
            }
            ss << " >" << ascii_part << "<\n";
        }
        if (size > dump_bytes) {
            ss << "... (" << (size - dump_bytes) << " more bytes)\n";
        }

    } else {
        ss << "SPARSE ADDRESS LIST: " << addrs.size() << " items\n";
        ss << sep;
        int max_items = 20;
        for (size_t i = 0; i < addrs.size() && i < (size_t)max_items; ++i) {
            uint16_t addr = addrs[i];
            auto line = analyzer.parse_instruction(addr);
            std::string disasm = format_disasm(line.address, line);
            ss << std::left << std::setw(40) << disasm;
            
            auto sym = symbols.find_nearest(line.address);
            if (!sym.first.empty() && sym.second == line.address) {
                ss << " (" << sym.first << ")";
            } else if (line.address == core.get_cpu().get_PC()) {
                ss << " (Current PC)";
            }
            ss << "\n";
        }
        if (addrs.size() > (size_t)max_items) {
            ss << "... and " << (addrs.size() - max_items) << " more items\n";
        }
    }
}

void Dashboard::format_detailed_collection(std::stringstream& ss, const Expression::Value& val) {
    bool is_bytes = (val.type() == Expression::Value::Type::Bytes);
    size_t count = is_bytes ? val.bytes().size() : val.words().size();
    std::string sep = "------------------------------------------------------------\n";
    
    if (is_bytes) {
        ss << "COLLECTION: Bytes (" << count << " items)\n";
        ss << sep;
        
        const auto& vec = val.bytes();
        ss << "Range:   " << format_sequence(vec, "{", "}", ",", true, true) << "\n";
        
        if (count > 0) {
            uint64_t sum = 0;
            uint8_t min_v = 0xFF;
            uint8_t max_v = 0x00;
            uint8_t checksum = 0;

            for (auto b : vec) {
                sum += b;
                if (b < min_v) min_v = b;
                if (b > max_v) max_v = b;
                checksum += b;
            }
            uint32_t crc = Checksum::crc32(vec);

            ss << "Stats:   Min: $" << Strings::hex(min_v) << ", Max: $" << Strings::hex(max_v) 
               << ", Sum: $" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << sum << std::dec << " (" << sum << ")\n";
            
            ss << "Checks:  Checksum: $" << Strings::hex(checksum) << ", CRC32: $" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc << std::dec << "\n";
            
            ss << "ASCII:   '";
            for(size_t i=0; i<std::min(count, (size_t)64); ++i) {
                char c = (vec[i] >= 32 && vec[i] <= 126) ? (char)vec[i] : '.';
                ss << c;
            }
            if (count > 64) ss << "...";
            ss << "'\n";
        }

    } else {
        // Words
        size_t bytes_count = count * 2;
        ss << "COLLECTION: Words (" << count << " items / " << bytes_count << " bytes)\n";
        ss << sep;
        
        const auto& vec = val.words();
        ss << "Elements: " << format_sequence(vec, "{", "}", ",", true, true) << "\n";
        
        ss << "Memory:   ";
        size_t limit = std::min(count, (size_t)16);
        for (size_t i = 0; i < limit; ++i) {
            uint16_t w = vec[i];
            ss << Strings::hex((uint8_t)(w & 0xFF)) << " " << Strings::hex((uint8_t)(w >> 8)) << " ";
        }
        if (count > limit) ss << "... ";
        ss << "\n";

        if (count > 0) {
            uint64_t sum = 0;
            uint16_t min_v = 0xFFFF;
            uint16_t max_v = 0x0000;
            std::string ascii_str;
            uint32_t crc = Checksum::CRC32_START;
            uint8_t checksum = 0;

            for (auto w : vec) {
                sum += w;
                if (w < min_v) min_v = w;
                if (w > max_v) max_v = w;
                
                uint8_t lb = w & 0xFF;
                uint8_t hb = w >> 8;
                checksum += lb;
                checksum += hb;
                crc = Checksum::crc32_update(crc, lb);
                crc = Checksum::crc32_update(crc, hb);

                if (ascii_str.length() < 64) {
                    ascii_str += (lb >= 32 && lb <= 126) ? (char)lb : '.';
                    if (ascii_str.length() < 64)
                        ascii_str += (hb >= 32 && hb <= 126) ? (char)hb : '.';
                }
            }
            crc = Checksum::crc32_finalize(crc);

            ss << "Stats:    Min: $" << Strings::hex(min_v) << ", Max: $" << Strings::hex(max_v) 
               << ", Sum: $" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << sum << std::dec << "\n";
            
            ss << "Checks:   Checksum: $" << Strings::hex(checksum) << ", CRC32: $" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc << std::dec << "\n";
            
            ss << "ASCII:    '" << ascii_str;
            if (count * 2 > 64)
                ss << "...";
            ss << "'\n";
        }
    }
}

std::string Dashboard::format(const Expression::Value& val, bool detailed) {
    std::stringstream ss;
    
    if (detailed) {
        // --- DETAILED VIEW (??) ---
        switch (val.type()) {
            case Expression::Value::Type::Number:
            case Expression::Value::Type::Register:
                format_detailed_number(ss, val);
                break;
            case Expression::Value::Type::Address:
                format_detailed_address(ss, val);
                break;
            case Expression::Value::Type::Bytes:
            case Expression::Value::Type::Words:
                format_detailed_collection(ss, val);
                break;
            case Expression::Value::Type::Symbol: {
                ss << "Symbol\n";
                ss << "  Name:    " << val.symbol().getName() << "\n";
                uint16_t addr = val.symbol().read();
                ss << "  Value:   $" << Strings::hex(addr) << "\n";
                ss << "  Type:    " << "Label/Address\n";
                print_asm_info(ss, addr);
                break;
            }
            case Expression::Value::Type::String: {
                std::string s = val.string();
                size_t len = s.length();
                std::string display_s = s;
                if (len > 30) {
                    display_s = s.substr(0, 27) + "...";
                }
                
                ss << "STRING:   \"" << display_s << "\" (" << len << " chars)\n";
                ss << "------------------------------------------------------------\n";
                
                ss << "Bytes:    ";
                size_t limit = std::min(len, (size_t)16);
                for (size_t i = 0; i < limit; ++i) {
                    if (i > 0) ss << ",";
                    ss << "$" << Strings::hex((uint8_t)s[i]);
                }
                if (len > limit) {
                    ss << "... (+" << (len - limit) << " more)";
                }
                ss << "\n";
                
                uint32_t crc = Checksum::CRC32_START;
                uint8_t checksum = 0;
                for (char c : s) {
                    uint8_t b = (uint8_t)c;
                    checksum += b;
                    crc = Checksum::crc32_update(crc, b);
                }
                crc = Checksum::crc32_finalize(crc);
                
                ss << "Checks:   Checksum: $" << Strings::hex(checksum) << ", CRC32: $" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc << std::dec;
                break;
            }
        }
        std::string res = ss.str();
        if (!res.empty() && res.back() == '\n') res.pop_back();
        return res;
    } else {
        // --- STANDARD VIEW (?) ---
        switch (val.type()) {
        case Expression::Value::Type::Number: {
            double d = val.number();
            if (d == (int64_t)d) {
                int64_t i = (int64_t)d;
                if (i >= -128 && i <= 255) {
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
        case Expression::Value::Type::String: {
            std::string s = val.string();
            if (s.length() > 50) s = s.substr(0, 47) + "...";
            ss << "\"" << s << "\"";
            break;
        }
        case Expression::Value::Type::Bytes:
            ss << format_sequence(val.bytes(), "{", "}", " ", true, true);
            break;
        case Expression::Value::Type::Words:
            ss << format_sequence(val.words(), "W{", "}", " ", true, true);
            break;
        case Expression::Value::Type::Address:
            ss << format_sequence(val.address(), "[", "]", ", ", true, true);
            break;
        case Expression::Value::Type::Register: {
            std::string name = val.reg().getName();
            uint16_t v = val.reg().read(m_debugger.get_core().get_cpu());
            if (val.reg().is_16bit())
                ss << name << "=$" << Strings::hex(v) << " (" << v << ")";
            else {
                ss << name << "=$" << Strings::hex((uint8_t)v) << " (" << v << ")";
                if (name == "F") {
                    ss << " [";
                    const char* syms = "SZYHXPNC";
                    for (int i = 7; i >= 0; --i) {
                        bool bit = (v >> i) & 1;
                        ss << (bit ? syms[7-i] : '.');
                    }
                    ss << "]";
                }
            }
            break;
        }
        case Expression::Value::Type::Symbol: {
            uint16_t v = val.symbol().read();
            ss << val.symbol().getName() << " ($" << Strings::hex(v) << ")";
            break;
        }
        }
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
