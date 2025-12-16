#include "DebugEngine.h"
#include "../Core/Evaluator.h"
#include <replxx.hxx>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cctype>
#include <algorithm>
#include "../Utils/Strings.h"
#include "../Utils/Terminal.h"
#include "../Core/CodeMap.h"

std::string DebugView::format_header(const std::string& title, const std::string& extra) const {
    std::stringstream ss;
    if (m_has_focus)
        ss << Terminal::COLOR_YELLOW << "[" << title << "]" << Terminal::RESET;
    else
        ss << Terminal::COLOR_GREEN << "[" << title << "]" << Terminal::RESET;
    if (!extra.empty())
        ss << extra;
    return ss.str();
}

std::vector<std::string> MemoryView::render() {
    std::vector<std::string> lines;
    std::string sep = Terminal::COLOR_GRAY + std::string(80, '-') + Terminal::RESET;
    lines.push_back(sep);
    std::stringstream extra;
    extra << Terminal::COLOR_CYAN << " View: " << Terminal::COLOR_HI_WHITE << Strings::hex16(m_start_addr) << Terminal::RESET;
    lines.push_back(format_header("MEMORY", extra.str()));
    lines.push_back(sep);
    auto& mem = m_core.get_memory();
    for (size_t i = 0; i < m_rows * 16; i += 16) {
        std::stringstream ss;
        uint16_t addr = m_start_addr + i;
        ss << Terminal::COLOR_CYAN << Strings::hex16(addr) << Terminal::RESET << ": ";
        for (size_t j = 0; j < 16; ++j) {
            uint8_t b = mem.read(addr + j);
            if (b == 0)
                ss << Terminal::COLOR_GRAY << "00" << Terminal::RESET;
            else
                ss << Strings::hex8(b);
            if (j == 7)
                ss << "  ";
            else if (j == 15)
                ss << "  ";
            else
                ss << " ";
        }
        ss << Terminal::COLOR_GRAY << "|" << Terminal::RESET << " ";
        for (size_t j = 0; j < 16; ++j) {
            uint8_t val = mem.read(addr + j);
            if (std::isprint(val))
                ss << Terminal::COLOR_HI_YELLOW << (char)val << Terminal::RESET;
            else
                ss << Terminal::COLOR_GRAY << "." << Terminal::RESET;
        }
        lines.push_back(ss.str());
    }
    return lines;
}

std::vector<std::string> RegisterView::render() {
    std::vector<std::string> lines;
    long long delta = (long long)m_tstates - m_prev.m_ticks;
    std::stringstream extra;
    extra << Terminal::COLOR_GRAY << " T: " << Terminal::RESET << m_tstates;
    if (delta > 0)
        extra << Terminal::COLOR_RED << " (+" << delta << ")" << Terminal::RESET;
    lines.push_back(format_header("REGS", extra.str()));

    auto& cpu = m_core.get_cpu();
    auto fmt_reg16 = [&](const std::string& l, uint16_t v, uint16_t pv) -> std::string {
        std::stringstream ss;
        ss << Terminal::COLOR_CYAN << std::setw(3) << std::left << l << Terminal::RESET << ": " 
            << (v != pv ? Terminal::COLOR_HI_YELLOW : Terminal::COLOR_GRAY) << Strings::hex16(v) << Terminal::RESET;
        return ss.str();
    };
    auto fmt_reg8_compact = [&](const std::string& l, uint8_t v, uint8_t pv) -> std::string {
        std::stringstream ss;
        ss << Terminal::COLOR_CYAN << l << Terminal::RESET << ":" 
            << (v != pv ? Terminal::COLOR_HI_YELLOW : Terminal::COLOR_GRAY) << Strings::hex8(v) << Terminal::RESET;
        return ss.str();
    };

    std::stringstream ss;
    // Row 1: AF, AF', PC
    ss << "  " << fmt_reg16("AF", cpu.get_AF(), m_prev.m_AF.w) 
       << "   " << fmt_reg16("AF'", cpu.get_AFp(), m_prev.m_AFp.w) 
       << "   " << fmt_reg16("PC", cpu.get_PC(), m_prev.m_PC.w);
    lines.push_back(ss.str());

    // Row 2: BC, BC', SP
    ss.str(""); 
    ss << "  " << fmt_reg16("BC", cpu.get_BC(), m_prev.m_BC.w) 
       << "   " << fmt_reg16("BC'", cpu.get_BCp(), m_prev.m_BCp.w) 
       << "   " << fmt_reg16("SP", cpu.get_SP(), m_prev.m_SP.w);
    lines.push_back(ss.str());

    // Row 3: DE, DE', I, R
    ss.str(""); 
    ss << "  " << fmt_reg16("DE", cpu.get_DE(), m_prev.m_DE.w) 
       << "   " << fmt_reg16("DE'", cpu.get_DEp(), m_prev.m_DEp.w) 
       << "   " << fmt_reg8_compact("I", cpu.get_I(), m_prev.m_I) 
       << " " << fmt_reg8_compact("R", cpu.get_R(), m_prev.m_R);
    lines.push_back(ss.str());

    // Row 4: HL, HL', IM, IFF
    ss.str(""); 
    ss << "  " << fmt_reg16("HL", cpu.get_HL(), m_prev.m_HL.w) 
       << "   " << fmt_reg16("HL'", cpu.get_HLp(), m_prev.m_HLp.w) 
       << "   " << Terminal::COLOR_CYAN << "IM" << Terminal::RESET << ":" 
       << (cpu.get_IRQ_mode() != m_prev.m_IRQ_mode ? Terminal::COLOR_HI_YELLOW : Terminal::COLOR_GRAY) << (int)cpu.get_IRQ_mode() << Terminal::RESET
       << " " << (cpu.get_IFF1() ? (Terminal::COLOR_HI_GREEN + "EI") : (Terminal::COLOR_GRAY + "DI")) << Terminal::RESET;
    lines.push_back(ss.str());

    // Row 5: IX, IY, F
    ss.str(""); 
    ss << "  " << fmt_reg16("IX", cpu.get_IX(), m_prev.m_IX.w) 
       << "   " << fmt_reg16("IY", cpu.get_IY(), m_prev.m_IY.w) << "   "
        << Terminal::COLOR_CYAN << std::setw(3) << std::left << "F" << Terminal::RESET << ": " << format_flags(cpu.get_AF() & 0xFF, m_prev.m_AF.w & 0xFF);
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
            ss << Terminal::COLOR_HI_YELLOW << Terminal::BOLD << c << Terminal::RESET;
        else if (bit)
            ss << Terminal::COLOR_HI_WHITE << c << Terminal::RESET;
        else
            ss << Terminal::COLOR_GRAY << c << Terminal::RESET;
    }
    return ss.str();
}

std::vector<std::string> StackView::render() {
    std::vector<std::string> lines;
    std::stringstream extra;
    extra << Terminal::COLOR_CYAN << " (SP=" << Terminal::COLOR_HI_WHITE << Strings::hex16(m_core.get_cpu().get_SP()) << Terminal::COLOR_CYAN << ")" << Terminal::RESET;
    lines.push_back(format_header("STACK", extra.str()));
    for (int row=0; row<m_rows; ++row) {
        uint16_t addr = m_view_addr + row*2;
        uint8_t l = m_core.get_memory().read(addr);
        uint8_t h = m_core.get_memory().read(addr + 1);
        uint16_t val = l | (h << 8);
        std::stringstream ss;
        ss << "  " << Terminal::COLOR_GRAY << Strings::hex16(addr) << Terminal::RESET << ": " << Terminal::COLOR_HI_WHITE << Strings::hex16(val) << Terminal::RESET;
        uint16_t temp_val = val;
        auto line = m_core.get_analyzer().parse_instruction(temp_val);
        if (!line.label.empty())
            ss << Terminal::COLOR_HI_YELLOW << " (" << line.label << ")" << Terminal::RESET;
        lines.push_back(ss.str());
    }
    return lines;
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
            ss << "  " << Terminal::COLOR_GRAY << Strings::hex16((uint16_t)line.address) << ": ";
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
                        case Operand::PORT_IMM8: ss << "($" << Strings::hex8(op.num_val) << ")"; break;
                        case Operand::MEM_REG16: ss << "(" << op.s_val << ")"; break;
                        case Operand::MEM_INDEXED: ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                        case Operand::STRING: ss << "\"" << op.s_val << "\""; break;
                        case Operand::CHAR_LITERAL: ss << "'" << (char)op.num_val << "'"; break;
                        default: break;
                    }
                }
            }
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
        if (lines.empty()) break;
        const auto& line = lines[0];

        auto& ctx = m_core.get_analyzer().context;
        bool has_block_desc = ctx.metadata.count((uint16_t)line.address) && !ctx.metadata.at((uint16_t)line.address).block_description.empty();
        bool has_label = !line.label.empty();

        // 1. Separacja wertykalna (Pusta linia przed nowym blokiem)
        if (!first_line && (has_label || has_block_desc)) {
            if (lines_count < m_rows) { lines_out.push_back(""); lines_count++; }
        }

        if (ctx.metadata.count((uint16_t)line.address)) {
             const auto& desc = ctx.metadata.at((uint16_t)line.address).block_description;
             if (!desc.empty()) {
                 std::stringstream desc_ss(desc);
                 std::string segment;
                 while(std::getline(desc_ss, segment, '\n')) {
                     if (lines_count < m_rows) { lines_out.push_back(Terminal::COLOR_GRAY + segment + Terminal::RESET); lines_count++; }
                 }
             }
        }

        // Podejście 1: Etykieta w osobnej linii
        if (!line.label.empty()) {
            if (lines_count < m_rows) { lines_out.push_back(Terminal::COLOR_MAGENTA + line.label + ":" + Terminal::RESET); lines_count++; }
        }

        std::stringstream ss;
        bool is_pc = ((uint16_t)line.address == m_pc);
        std::string bg = is_pc ? Terminal::COLOR_BG_DARK_GRAY : "";
        std::string rst = is_pc ? (Terminal::RESET + bg) : Terminal::RESET;
        
        // ZONE 1: Gutter (0-2)
        if (is_pc) 
            ss << bg << Terminal::COLOR_HI_GREEN << Terminal::BOLD << ">  " << rst;
        else
            ss << "   ";

        // ZONE 2: Address (3-8)
        if (is_pc)
            ss << Terminal::COLOR_HI_WHITE << Terminal::BOLD << Strings::hex16((uint16_t)line.address) << rst << ": ";
        else
            ss << Terminal::COLOR_CYAN << Strings::hex16((uint16_t)line.address) << rst << ": ";

        // ZONE 3: Hex (9-18)
        std::stringstream hex_ss;
        if (line.bytes.size() > 3) {
            hex_ss << Strings::hex8(line.bytes[0]) << " " << Strings::hex8(line.bytes[1]) << " ..";
        } else {
            for(size_t i=0; i<line.bytes.size(); ++i) {
                if (i > 0) hex_ss << " ";
                hex_ss << Strings::hex8(line.bytes[i]);
            }
        }
        std::string hex_str = hex_ss.str();
        ss << Terminal::COLOR_GRAY << hex_str << rst;
        int hex_len = (int)hex_str.length();
        int hex_pad = 9 - hex_len;
        if (hex_pad > 0) ss << std::string(hex_pad, ' ');

        // GAP (18-19)
        ss << "  ";

        // ZONE 4: Mnemonic (20-34)
        std::stringstream mn_ss;
        if (is_pc)
            mn_ss << Terminal::BOLD << Terminal::COLOR_WHITE;
        else
            mn_ss << Terminal::COLOR_BLUE;
        mn_ss << line.mnemonic << rst;

        if (!line.operands.empty()) {
            mn_ss << " ";
            using Operand = typename std::decay_t<decltype(line)>::Operand;
            for (size_t i = 0; i < line.operands.size(); ++i) {
                if (i > 0)
                    mn_ss << ", ";
                const auto& op = line.operands[i];
                bool is_num = (op.type == Operand::IMM8 || op.type == Operand::IMM16 || op.type == Operand::MEM_IMM16);
                if (is_num)
                    mn_ss << Terminal::COLOR_YELLOW;
                switch (op.type) {
                    case Operand::REG8: case Operand::REG16: case Operand::CONDITION: mn_ss << op.s_val; break;
                    case Operand::IMM8: mn_ss << "$" << Strings::hex8(op.num_val); break;
                    case Operand::IMM16: mn_ss << "$" << Strings::hex16(op.num_val); break;
                    case Operand::MEM_IMM16: mn_ss << "($" << Strings::hex16(op.num_val) << ")"; break;
                    case Operand::PORT_IMM8: mn_ss << "($" << Strings::hex8(op.num_val) << ")"; break;
                    case Operand::MEM_REG16: mn_ss << "(" << op.s_val << ")"; break;
                    case Operand::MEM_INDEXED: mn_ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                    case Operand::STRING: mn_ss << "\"" << op.s_val << "\""; break;
                    case Operand::CHAR_LITERAL: mn_ss << "'" << (char)op.num_val << "'"; break;
                    default: break;
                }
                if (is_num)
                    mn_ss << rst;
            }
        }
        
        std::string mn_str = mn_ss.str();
        int mn_len = (int)Strings::length(mn_str);
        if (mn_len > 15) {
             std::string clipped;
             int visible = 0;
             bool in_ansi = false;
             for (char c : mn_str) {
                 if (c == '\x1B') in_ansi = true;
                 if (in_ansi) {
                     clipped += c;
                     if (c == 'm' || c == 'K') in_ansi = false;
                 } else {
                     if (visible < 12) {
                         clipped += c;
                         visible++;
                     } else {
                         break;
                     }
                 }
             }
             clipped += Terminal::RESET + "...";
             ss << clipped;
        } else {
            ss << Strings::padding(mn_str, 15);
        }

        // ZONE 5: Comment (35-79)
        if (ctx.metadata.count((uint16_t)line.address)) {
             const auto& comment = ctx.metadata.at((uint16_t)line.address).inline_comment;
             if (!comment.empty()) {
                 std::string cmt_full = "; " + comment;
                 if (cmt_full.length() > 45) {
                     cmt_full = cmt_full.substr(0, 42) + "...";
                 }
                 ss << Terminal::COLOR_GREEN << cmt_full << Terminal::RESET;
             }
        }

        if (m_width > 0) {
            std::string s = ss.str();
            if (is_pc) s += Terminal::COLOR_BG_DARK_GRAY;
            s = Strings::padding(s, m_width);
            s += Terminal::RESET; 
            if (lines_count < m_rows) { lines_out.push_back(s); lines_count++; }
        } else
            if (lines_count < m_rows) { lines_out.push_back(ss.str()); lines_count++; }
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
    for (const auto& bp : m_breakpoints) {
        if (bp.enabled && bp.addr == pc)
            return true;
    }
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
            log("Stepping over... (Target: " + Strings::hex16(next_pc) + ")");
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
    m_repl.history_load(".zxtool_history");
    update_code_view();
    m_memory_view.set_address(m_debugger.get_core().get_cpu().get_PC());
    m_stack_view.set_address(m_debugger.get_core().get_cpu().get_SP());
    validate_focus();
    while (m_running) {
        print_dashboard();
        const char* input_cstr = m_repl.input("> ");
        if (input_cstr == nullptr)
            break;
        std::string input(input_cstr);
        if (input.empty()) continue;

        m_repl.history_add(input);
        handle_command(input);
    }
    m_repl.history_save(".zxtool_history");
}


void Dashboard::validate_focus() {
    int attempts = 0;
    while (attempts < FOCUS_COUNT && (
        (m_focus == FOCUS_MEMORY && !m_show_mem) ||
            (m_focus == FOCUS_REGS && !m_show_regs) ||
            (m_focus == FOCUS_STACK && !m_show_stack) ||
            (m_focus == FOCUS_CODE && !m_show_code) ||
            (m_focus == FOCUS_WATCH && !m_show_watch) ||
            (m_focus == FOCUS_BREAKPOINTS && !m_show_watch)
        )) {
            m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
            attempts++;
        }
}

void Dashboard::handle_command(const std::string& input) {
}

void Dashboard::init() {
        m_repl.install_window_change_handler();
        
        auto bind_scroll = [&](char32_t key, int mem_delta, int code_delta, int stack_delta) {
            m_repl.bind_key(key, [this, mem_delta, code_delta, stack_delta](char32_t code) {
                if (m_focus == FOCUS_MEMORY) m_memory_view.scroll(mem_delta);
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
            m_repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
            return replxx::Replxx::ACTION_RESULT::CONTINUE;
        };
        
        m_repl.bind_key(replxx::Replxx::KEY::TAB, tab_handler);
        m_repl.bind_key(9, tab_handler);
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
                if (view_pc == pc) view_pc = highlight_pc;
            }

            m_code_view.set_focus(m_focus == FOCUS_CODE);
            m_code_view.set_state(highlight_pc, width, m_debugger.get_last_pc(), m_debugger.has_history(), m_debugger.pc_moved());
            auto code_lines = m_code_view.render();
            for (const auto& l : code_lines) std::cout << l << "\n";
        }

        if (m_show_watch) {
            print_separator();
            std::cout << (m_focus == FOCUS_WATCH || m_focus == FOCUS_BREAKPOINTS ? Terminal::COLOR_YELLOW : Terminal::COLOR_GREEN) << "[STATUS]" << Terminal::RESET << "\n";

            std::stringstream ss;
            std::string label = " WATCH: ";
            ss << Terminal::COLOR_CYAN << label << Terminal::RESET;
            
            const auto& watches = m_debugger.get_watches();
            std::vector<std::string> items;
            for (uint16_t addr : watches) {
                uint8_t val = core.get_memory().read(addr);
                std::stringstream item_ss;
                auto pair = core.get_context().find_nearest_symbol(addr);
                if (!pair.first.empty() && pair.second == addr) item_ss << pair.first;
                else item_ss << Strings::hex16(addr);
                item_ss << "=" << (int)val;
                items.push_back(item_ss.str());
            }
            
            int max_len = 80;
            int current_len = (int)label.length();
            bool first = true;
            for (size_t i = 0; i < items.size(); ++i) {
                std::string sep = first ? "" : ", ";
                if (current_len + sep.length() + items[i].length() > (size_t)(max_len - 10)) {
                    ss << Terminal::COLOR_GRAY << "... (+" << (items.size() - i) << ")" << Terminal::RESET;
                    break;
                }
                ss << Terminal::COLOR_HI_WHITE << sep << items[i] << Terminal::RESET;
                current_len += sep.length() + items[i].length();
                first = false;
            }
            if (items.empty()) ss << Terminal::COLOR_GRAY << "No items." << Terminal::RESET;
            std::cout << ss.str() << "\n";
            
            ss.str(""); ss.clear();
            label = " BREAK: ";
            ss << Terminal::COLOR_RED << label << Terminal::RESET;
            
            const auto& breakpoints = m_debugger.get_breakpoints();
            items.clear();
            for (const auto& bp : breakpoints) {
                std::stringstream item_ss;
                item_ss << (bp.enabled ? "*" : "o") << Strings::hex16(bp.addr);
                auto pair = core.get_context().find_nearest_symbol(bp.addr);
                if (!pair.first.empty() && pair.second == bp.addr) item_ss << " (" << pair.first << ")";
                items.push_back(item_ss.str());
            }
            
            max_len = 80;
            current_len = (int)label.length();
            first = true;
            for (size_t i = 0; i < items.size(); ++i) {
                std::string sep = first ? "" : ", ";
                if (current_len + sep.length() + items[i].length() > (size_t)(max_len - 10)) {
                    ss << Terminal::COLOR_GRAY << "... (+" << (items.size() - i) << ")" << Terminal::RESET;
                    break;
                }
                ss << Terminal::COLOR_HI_WHITE << sep << items[i] << Terminal::RESET;
                current_len += sep.length() + items[i].length();
                first = false;
            }
            if (items.empty()) ss << Terminal::COLOR_GRAY << "No items." << Terminal::RESET;
            std::cout << ss.str() << "\n";
            print_separator();
        }

        bool has_output = (m_output_buffer.tellp() > 0);
        print_output_buffer();
        if (has_output || !m_show_watch) print_separator();
        print_footer();
        std::cout << std::flush;
}

void Dashboard::print_output_buffer() {
    if (m_output_buffer.tellp() > 0) {
        std::cout << Terminal::COLOR_HI_YELLOW << "[OUTPUT]" << Terminal::RESET << "\n";
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
    for (const auto& c : cmds) {
        std::cout << Terminal::COLOR_GRAY << "[" << Terminal::COLOR_HI_WHITE << Terminal::BOLD << c.k << Terminal::RESET << Terminal::COLOR_GRAY << "]" << c.n << " " << Terminal::RESET;
    }
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
                if (has_bg) l_padded += Terminal::COLOR_BG_DARK_GRAY;
                std::cout << Strings::padding(l_padded, left_width);
                if (has_bg) std::cout << Terminal::RESET;
                std::cout << Terminal::COLOR_GRAY << " | " << Terminal::RESET;
                if (row < right.size()) std::cout << " " << right[row];
            } else {
                std::cout << l;
                if (has_bg) std::cout << Terminal::COLOR_BG_DARK_GRAY << Terminal::RESET;
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
            uint16_t pc = m_core.parse_address(ep);
            m_core.get_cpu().set_PC(pc);
        } catch (const std::exception& e) {
            std::cerr << "Error parsing entry point: " << e.what() << "\n";
        }
    }

    Debugger debugger(m_core);
    Dashboard dashboard(debugger, m_repl);
    dashboard.run();
    
    return 0;
}
