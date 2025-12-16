#include "DebugEngine.h"
#include "../Core/Evaluator.h"
#include <replxx.hxx>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cctype>
#include <algorithm>
#ifdef _WIN32
    #include <windows.h>
#else
#endif
#include "../Utils/Strings.h"
#include "../Utils/Terminal.h"
#include "../Core/CodeMap.h"

static size_t levenshtein_distance(const std::string& s1, const std::string& s2) {
    const size_t m = s1.length();
    const size_t n = s2.length();
    std::vector<std::vector<size_t>> dp(m + 1, std::vector<size_t>(n + 1));

    for (size_t i = 0; i <= m; ++i) dp[i][0] = i;
    for (size_t j = 0; j <= n; ++j) dp[0][j] = j;

    for (size_t i = 1; i <= m; ++i) {
        for (size_t j = 1; j <= n; ++j) {
            size_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            dp[i][j] = std::min({ dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost });
        }
    }
    return dp[m][n];
}

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
    auto& mem = m_core.get_memory();
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

    auto& cpu = m_core.get_cpu();
    auto fmt_reg16 = [&](const std::string& l, uint16_t v, uint16_t pv) -> std::string {
        std::stringstream ss;
        ss << Terminal::CYAN << std::setw(3) << std::left << l << Terminal::RESET << ": " 
            << (v != pv ? Terminal::HI_YELLOW : Terminal::GRAY) << Strings::hex16(v) << Terminal::RESET;
        return ss.str();
    };
    auto fmt_reg8_compact = [&](const std::string& l, uint8_t v, uint8_t pv) -> std::string {
        std::stringstream ss;
        ss << Terminal::CYAN << l << Terminal::RESET << ":" 
            << (v != pv ? Terminal::HI_YELLOW : Terminal::GRAY) << Strings::hex8(v) << Terminal::RESET;
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
       << "   " << Terminal::CYAN << "IM" << Terminal::RESET << ":" 
       << (cpu.get_IRQ_mode() != m_prev.m_IRQ_mode ? Terminal::HI_YELLOW : Terminal::GRAY) << (int)cpu.get_IRQ_mode() << Terminal::RESET
       << " " << (cpu.get_IFF1() ? (Terminal::HI_GREEN + "EI") : (Terminal::GRAY + "DI")) << Terminal::RESET;
    lines.push_back(ss.str());

    // Row 5: IX, IY, F
    ss.str(""); 
    ss << "  " << fmt_reg16("IX", cpu.get_IX(), m_prev.m_IX.w) 
       << "   " << fmt_reg16("IY", cpu.get_IY(), m_prev.m_IY.w) << "   "
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
    extra << Terminal::CYAN << " (SP=" << Terminal::HI_WHITE << Strings::hex16(m_core.get_cpu().get_SP()) << Terminal::CYAN << ")" << Terminal::RESET;
    lines.push_back(format_header("STACK", extra.str()));

    for (int i=0; i<5; ++i) {
        uint16_t addr = m_view_addr + i*2;
        uint8_t l = m_core.get_memory().read(addr);
        uint8_t h = m_core.get_memory().read(addr + 1);
        uint16_t val = l | (h << 8);
        std::stringstream ss;
        ss << "  " << Terminal::GRAY << Strings::hex16(addr) << Terminal::RESET << ": " << Terminal::HI_WHITE << Strings::hex16(val) << Terminal::RESET;
        uint16_t temp_val = val;
        auto line = m_core.get_analyzer().parse_instruction(temp_val);
        if (!line.label.empty())
            ss << Terminal::HI_YELLOW << " (" << line.label << ")" << Terminal::RESET;
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
                     if (lines_count < m_rows) { lines_out.push_back(Terminal::GRAY + segment + Terminal::RESET); lines_count++; }
                 }
             }
        }

        // Podejście 1: Etykieta w osobnej linii
        if (!line.label.empty()) {
            if (lines_count < m_rows) { lines_out.push_back(Terminal::MAGENTA + line.label + ":" + Terminal::RESET); lines_count++; }
        }

        std::stringstream ss;
        bool is_pc = ((uint16_t)line.address == m_pc);
        std::string bg = is_pc ? Terminal::BG_DARK_GRAY : "";
        std::string rst = is_pc ? (Terminal::RESET + bg) : Terminal::RESET;
        
        // ZONE 1: Gutter (0-2)
        if (is_pc) 
            ss << bg << Terminal::HI_GREEN << Terminal::BOLD << ">  " << rst;
        else
            ss << "   ";

        // ZONE 2: Address (3-8)
        if (is_pc)
            ss << Terminal::HI_WHITE << Terminal::BOLD << Strings::hex16((uint16_t)line.address) << rst << ": ";
        else
            ss << Terminal::CYAN << Strings::hex16((uint16_t)line.address) << rst << ": ";

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
        ss << Terminal::GRAY << hex_str << rst;
        int hex_len = (int)hex_str.length();
        int hex_pad = 9 - hex_len;
        if (hex_pad > 0) ss << std::string(hex_pad, ' ');

        // GAP (18-19)
        ss << "  ";

        // ZONE 4: Mnemonic (20-34)
        std::stringstream mn_ss;
        if (is_pc)
            mn_ss << Terminal::BOLD << Terminal::WHITE;
        else
            mn_ss << Terminal::BLUE;
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
                    mn_ss << Terminal::YELLOW;
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
                 ss << Terminal::GREEN << cmt_full << Terminal::RESET;
             }
        }

        if (m_width > 0) {
            std::string s = ss.str();
            if (is_pc) s += Terminal::BG_DARK_GRAY;
            s = Strings::padding(s, m_width);
            s += Terminal::RESET; 
            if (lines_count < m_rows) { lines_out.push_back(s); lines_count++; }
        } else
            if (lines_count < m_rows) { lines_out.push_back(ss.str()); lines_count++; }
        first_line = false;
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

void Debugger::record_history(uint16_t pc) {
    if (m_execution_history.size() >= 100)
        m_execution_history.pop_front();
    m_execution_history.push_back({pc});
}

void Debugger::step(int n) {
    m_prev_state = m_core.get_cpu().save_state();
    for (int i = 0; i < n; ++i) {
        if (i > 0 && check_breakpoints(m_core.get_cpu().get_PC()))
            break;
        uint16_t pc_before = m_core.get_cpu().get_PC();
        record_history(pc_before);
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
            record_history(pc_before);
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
            record_history(m_core.get_cpu().get_PC());
        } else {
            record_history(pc_before);
            m_core.get_cpu().step();
        }
        }
        uint16_t pc_after = m_core.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
}

void Debugger::cont() {
    m_prev_state = m_core.get_cpu().save_state();
    while (true) {
        if (check_breakpoints(m_core.get_cpu().get_PC())) {
            log("Breakpoint hit!");
            return;
        }
        uint16_t pc_before = m_core.get_cpu().get_PC();
        record_history(pc_before);
        m_core.get_cpu().step();
        uint16_t pc_after = m_core.get_cpu().get_PC();
        m_last_pc = pc_before;
        m_has_history = true;
        m_pc_moved = (pc_before != pc_after);
    }
}

void Debugger::run_until_return() {
    m_prev_state = m_core.get_cpu().save_state();
    while (true) {
        if (check_breakpoints(m_core.get_cpu().get_PC())) {
            log("Breakpoint hit!");
            return;
        }
        
        uint16_t pc = m_core.get_cpu().get_PC();
        uint8_t opcode = m_core.get_memory().peek(pc);
        bool is_ret = false;
        int instr_len = 1;

        if (opcode == 0xC9 || (opcode & 0xC7) == 0xC0) {
            is_ret = true;
        } else if (opcode == 0xED) {
            uint8_t op2 = m_core.get_memory().peek(pc + 1);
            if (op2 == 0x45 || op2 == 0x4D) {
                is_ret = true;
                instr_len = 2;
            }
        }
        
        record_history(pc);
        m_core.get_cpu().step();
        
        if (is_ret) {
            uint16_t pc_after = m_core.get_cpu().get_PC();
            if (pc_after != pc + instr_len) {
                m_last_pc = pc;
                m_has_history = true;
                m_pc_moved = true;
                return;
            }
        }
        
        m_last_pc = pc;
        m_has_history = true;
        m_pc_moved = true;
    }
}

void Debugger::run_to(uint16_t addr) {
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), 
        [addr](const Breakpoint& b){ return b.addr == addr; });
    
    bool existed = (it != m_breakpoints.end());
    bool was_enabled = false;
    
    if (existed) {
        was_enabled = it->enabled;
        it->enabled = true;
    } else {
        add_breakpoint(addr);
    }
    
    cont();
    
    if (existed) {
        auto it2 = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), 
            [addr](const Breakpoint& b){ return b.addr == addr; });
        if (it2 != m_breakpoints.end()) it2->enabled = was_enabled;
    } else {
        remove_breakpoint(addr);
    }
}

void Dashboard::run() {
    setup_replxx();
    m_repl.history_load("zxtool_history.txt");
    update_code_view();
    m_mem_view_addr = m_debugger.get_core().get_cpu().get_PC();
    m_stack_view_addr = m_debugger.get_core().get_cpu().get_SP();
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
            std::stringstream ss(input);
            std::string cmd;
            ss >> cmd;
            if (cmd == "s" || cmd == "step" || cmd == "n" || cmd == "next" || cmd == "g" || cmd == "go") {
                m_last_command = input;
            } else {
                m_last_command.clear();
            }
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
            (m_focus == FOCUS_BREAKPOINTS && !m_show_watch)
        )) {
            m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
            attempts++;
        }
}

static std::string preprocess_expr(const std::string& input) {
    std::string result;
    result.reserve(input.length());
    for (size_t i = 0; i < input.length(); ++i) {
        if (input[i] == '$') {
            bool is_hex = false;
            if (i + 1 < input.length()) {
                char next = input[i+1];
                if (std::isxdigit(static_cast<unsigned char>(next))) {
                    is_hex = true;
                }
            }
            result += (is_hex ? "$" : "PC");
        } else {
            result += input[i];
        }
    }
    return result;
}

std::vector<uint8_t> Dashboard::assemble_code(const std::string& code_in, uint16_t pc) {
    std::string code = code_in;
    size_t pos = 0;
    while ((pos = code.find("\\\\", pos)) != std::string::npos) {
        code.replace(pos, 2, "\n");
        pos += 1;
    }

    LineAssembler assembler;
    std::vector<uint8_t> bytes;
    std::map<std::string, uint16_t> symbols;
    for (const auto& [addr, name] : m_debugger.get_core().get_context().labels) {
        symbols[name] = addr;
    }
    assembler.assemble(code, symbols, pc, bytes);
    return bytes;
}

void Dashboard::perform_assignment(const std::string& lhs_in, const std::string& rhs_in) {
    // Check for asm(...) in raw rhs_in first to avoid preprocessing messing up assembly syntax (e.g. $)
    std::string rhs_trimmed_raw = rhs_in;
    size_t first_raw = rhs_trimmed_raw.find_first_not_of(" \t");
    if (first_raw != std::string::npos) {
        size_t last_raw = rhs_trimmed_raw.find_last_not_of(" \t");
        rhs_trimmed_raw = rhs_trimmed_raw.substr(first_raw, (last_raw - first_raw + 1));
    }

    if (rhs_trimmed_raw.size() >= 5 && rhs_trimmed_raw.substr(0, 4) == "asm(" && rhs_trimmed_raw.back() == ')') {
        std::string lhs = preprocess_expr(lhs_in);
        std::string target = lhs;
        target.erase(std::remove_if(target.begin(), target.end(), ::isspace), target.end());

        if (target.size() < 2 || target.front() != '[' || target.back() != ']') {
             log(Terminal::RED + "Error: asm() assignment only supported for memory targets (e.g. [HL])." + Terminal::RESET);
             return;
        }

        try {
            // 1. Calculate Start Address
            std::string addr_expr = target.substr(1, target.size() - 2);
            Evaluator eval(m_debugger.get_core());
            uint16_t start_addr = static_cast<uint16_t>(eval.evaluate(addr_expr).as_number());
            
            // 2. Extract instruction
            size_t open_paren = rhs_trimmed_raw.find('(');
            size_t close_paren = rhs_trimmed_raw.rfind(')');
            std::string content = rhs_trimmed_raw.substr(open_paren + 1, close_paren - open_paren - 1);
            
            // Trim content
            size_t c_first = content.find_first_not_of(" \t");
            if (c_first != std::string::npos) {
                size_t c_last = content.find_last_not_of(" \t");
                content = content.substr(c_first, (c_last - c_first + 1));
            }

            // Remove quotes if present
            if (content.size() >= 2 && ((content.front() == '"' && content.back() == '"') || (content.front() == '\'' && content.back() == '\''))) {
                content = content.substr(1, content.size() - 2);
            }

            // 3. Assemble
            std::vector<uint8_t> bytes = assemble_code(content, start_addr);

            if (bytes.empty()) {
                log(Terminal::RED + "Error: Assembly produced no bytes." + Terminal::RESET);
                return;
            }

            // 4. Write to Memory
            uint16_t current_addr = start_addr;
            for (uint8_t byte_val : bytes) {
                m_debugger.get_core().get_memory().write(current_addr, byte_val);
                current_addr++;
            }
            m_debugger.get_code_map().invalidate_region(start_addr, bytes.size());
            
            std::stringstream out;
            out << "Patched " << Terminal::CYAN << Strings::hex16(start_addr) << Terminal::RESET << " with ";
            out << Terminal::HI_YELLOW;
            for (size_t i = 0; i < bytes.size(); ++i) {
                if (i > 0) out << " ";
                out << Strings::hex8(bytes[i]);
            }
            out << Terminal::RESET << " (" << content << ")";
            log(out.str());
            
            // Re-analyze code to update CodeMap flags
            m_debugger.get_core().get_analyzer().parse_code(start_addr, 0, &m_debugger.get_core().get_code_map(), false, true);

            if (m_auto_follow) update_code_view();
        } catch (const std::exception& e) {
            log(std::string(Terminal::RED) + "Error: " + e.what() + Terminal::RESET);
        }
        return;
    }

    std::string lhs = preprocess_expr(lhs_in);
    std::string rhs = preprocess_expr(rhs_in);

    // Check for block initialization: { ... }
    std::string rhs_trimmed = rhs;
    size_t first = rhs_trimmed.find_first_not_of(" \t");
    if (first != std::string::npos) {
        size_t last = rhs_trimmed.find_last_not_of(" \t");
        rhs_trimmed = rhs_trimmed.substr(first, (last - first + 1));
    }

    if (rhs_trimmed.size() >= 2 && rhs_trimmed.front() == '{' && rhs_trimmed.back() == '}') {
        std::string target = lhs;
        target.erase(std::remove_if(target.begin(), target.end(), ::isspace), target.end());
        
        if (target.size() < 2 || target.front() != '[' || target.back() != ']') {
             log(Terminal::RED + "Error: Block initialization only supported for memory targets (e.g. [HL])." + Terminal::RESET);
             return;
        }

        try {
            // 1. Calculate Start Address
            std::string addr_expr = target.substr(1, target.size() - 2);
            Evaluator eval(m_debugger.get_core());
            uint16_t start_addr = static_cast<uint16_t>(eval.evaluate(addr_expr).as_number());
            
            // 2. Parse Byte List
            std::string list_content = rhs_trimmed.substr(1, rhs_trimmed.size() - 2);
            std::vector<std::string> elements;
            std::string current;
            int paren_level = 0;
            for (char c : list_content) {
                if (c == ',' && paren_level == 0) {
                    elements.push_back(current);
                    current.clear();
                } else {
                    if (c == '(') paren_level++;
                    if (c == ')') paren_level--;
                    current += c;
                }
            }
            if (!current.empty() || elements.empty()) elements.push_back(current);

            // 3. Write to Memory
            uint16_t current_addr = start_addr;
            for (const auto& el : elements) {
                if (el.find_first_not_of(" \t") == std::string::npos) continue;
                double val = eval.evaluate(el).as_number();
                uint8_t byte_val = static_cast<uint8_t>(static_cast<int>(val));
                m_debugger.get_core().get_memory().write(current_addr, byte_val);
                current_addr++;
            }
            
            m_debugger.get_code_map().invalidate_region(start_addr, current_addr - start_addr);
            log("Written " + std::to_string(current_addr - start_addr) + " bytes to " + Strings::hex16(start_addr));
            
            // Re-analyze code to update CodeMap flags (handle new instruction lengths)
            m_debugger.get_core().get_analyzer().parse_code(start_addr, 0, &m_debugger.get_core().get_code_map(), false, true);

            if (m_auto_follow) update_code_view();
        } catch (const std::exception& e) {
            log(std::string(Terminal::RED) + "Error: " + e.what() + Terminal::RESET);
        }
        return;
    }

    try {
        Evaluator eval(m_debugger.get_core());
        double val = eval.evaluate(rhs).as_number(); 
        uint16_t val16 = static_cast<uint16_t>(val);

        std::string target = lhs;
        target.erase(std::remove_if(target.begin(), target.end(), ::isspace), target.end());
        std::string target_upper = target;
        std::transform(target_upper.begin(), target_upper.end(), target_upper.begin(), ::toupper);

        // 1. Rejestr?
        if (Evaluator::is_register(target_upper)) {
            eval.assign(target, val); // Evaluator handles registers
            
            if (target_upper == "PC") {
                auto& core = m_debugger.get_core();
                core.get_profiler().reset();
                core.get_analyzer().parse_code(val16, 0, &core.get_code_map(), false, true);
                log("PC changed. History reset and static analysis performed.");
                m_auto_follow = true;
                update_code_view();
            }
            
            std::stringstream out;
            out << "Assigned " << Terminal::HI_YELLOW << Strings::hex16(val16) << Terminal::RESET
                << " to " << Terminal::CYAN << target_upper << Terminal::RESET;
            log(out.str());
        }
        // 2. Pamięć?
        else if (target.front() == '[' && target.back() == ']') {
            // Manual assignment to capture address for re-analysis and avoid double evaluation side-effects
            std::string addr_expr = target.substr(1, target.size() - 2);
            uint16_t addr = static_cast<uint16_t>(eval.evaluate(addr_expr).as_number());
            m_debugger.get_core().get_memory().write(addr, (uint8_t)val16);
            
            m_debugger.get_code_map().invalidate_region(addr, 1);

            // Re-analyze code to update CodeMap flags
            m_debugger.get_core().get_analyzer().parse_code(addr, 0, &m_debugger.get_core().get_code_map(), false, true);

            std::stringstream out;
            out << "Assigned " << Terminal::HI_YELLOW << Strings::hex8((uint8_t)val16) << Terminal::RESET
                << " to memory " << Terminal::CYAN << target << Terminal::RESET;
            log(out.str());
        }
        // 3. Symbol
        else {
            // Check for valid symbol name
            if (isdigit(target[0])) {
                    log(Terminal::RED + "Error: Symbol name cannot start with a digit." + Terminal::RESET);
            } else {
                auto result = m_debugger.get_core().get_context().add_or_update_symbol(target, val16);
                
                if (result.result == Context::SymbolResult::Created) {
                    log(Terminal::MAGENTA + "Defined NEW Symbol '" + target + "' = " + Strings::hex16(val16) + Terminal::RESET);
                    
                    // Fuzzy match check
                    for (const auto& [addr, name] : m_debugger.get_core().get_context().labels) {
                        if (name != target && levenshtein_distance(target, name) <= 1) {
                            log(Terminal::YELLOW + "Warning: Did you mean '" + name + "'?" + Terminal::RESET);
                        }
                    }
                } else {
                    log(Terminal::YELLOW + "UPDATED Symbol '" + target + "': " + 
                        Strings::hex16(result.old_address) + " -> " + Strings::hex16(val16) + Terminal::RESET);
                }
                // Force refresh code view to show new label
                update_code_view();
            }
        }
        
        if (m_auto_follow && target_upper != "PC") update_code_view();
    } catch (const std::exception& e) {
        log(std::string(Terminal::RED) + "Error: " + e.what() + Terminal::RESET);
    }
}

void Dashboard::perform_find(uint16_t start_addr, const std::vector<uint8_t>& pattern) {
    if (pattern.empty()) {
        log("No pattern to search.");
        return;
    }
    
    m_last_pattern = pattern;
    auto& mem = m_debugger.get_core().get_memory();
    
    uint32_t addr = start_addr;
    size_t scanned = 0;
    
    // Przeszukaj całą przestrzeń adresową (64KB), zawijając się
    while (scanned < 0x10000) {
        uint16_t cur = (uint16_t)(addr & 0xFFFF);
        bool match = true;
        for (size_t i = 0; i < pattern.size(); ++i) {
            if (mem.read((uint16_t)(cur + i)) != pattern[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            m_last_found_addr = cur;
            m_mem_view_addr = cur;
            m_focus = FOCUS_MEMORY;
            log("Found at " + Strings::hex16(cur));
            return;
        }
        
        addr++;
        scanned++;
    }
    
    log("Pattern not found.");
}

void Dashboard::handle_command(const std::string& input) {
}

void Dashboard::setup_replxx() {
        m_repl.install_window_change_handler();
        
        auto bind_scroll = [&](char32_t key, int mem_delta, int code_delta, int stack_delta) {
            m_repl.bind_key(key, [this, mem_delta, code_delta, stack_delta](char32_t code) {
                if (m_focus == FOCUS_MEMORY) m_mem_view_addr += mem_delta;
                else if (m_focus == FOCUS_CODE) {
                    m_auto_follow = false;
                    if (code_delta < 0) {
                        m_code_view_addr = find_prev_instruction_pc(m_code_view_addr);
                    } else {
                        uint16_t temp = m_code_view_addr;
                        m_debugger.get_core().get_analyzer().parse_instruction(temp);
                        m_code_view_addr = temp;
                    }
                }
                else if (m_focus == FOCUS_STACK) m_stack_view_addr += stack_delta;
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
        Terminal::clear();
        auto& core = m_debugger.get_core();
        auto& cpu = core.get_cpu();
        uint16_t pc = cpu.get_PC();
        const int terminal_width = 80;
        if (m_show_mem) {
            MemoryView view(core, m_mem_view_addr, m_mem_rows, m_focus == FOCUS_MEMORY);
            auto lines = view.render();
            for (const auto& line : lines)
                std::cout << line << "\n";
        }
        std::cout << std::setfill(' ') << std::right << std::dec;
        std::vector<std::string> left_lines;
        std::vector<std::string> right_lines;
        if (m_show_regs) {
            RegisterView view(core, m_debugger.get_prev_state(), m_focus == FOCUS_REGS, m_debugger.get_tstates());
            auto regs_lines = view.render();
            left_lines.insert(left_lines.end(), regs_lines.begin(), regs_lines.end());
        }
        if (m_show_stack) {
            StackView view(core, m_stack_view_addr, m_focus == FOCUS_STACK);
            auto stack_lines = view.render();
            right_lines.insert(right_lines.end(), stack_lines.begin(), stack_lines.end());
        }
        print_separator();
        print_columns(left_lines, right_lines, 40);
        print_separator();
        left_lines.clear();
        right_lines.clear();
        if (m_show_code) {
            int width = terminal_width;
            
            uint16_t view_pc = m_code_view_addr;
            uint16_t highlight_pc = pc;
            if (cpu.is_halted()) {
                highlight_pc = pc - 1;
                if (view_pc == pc) view_pc = highlight_pc;
            }

            CodeView view(core, view_pc, m_code_rows, highlight_pc, width, m_focus == FOCUS_CODE, m_debugger.get_last_pc(), m_debugger.has_history(), m_debugger.pc_moved());
            auto code_lines = view.render();
            for (const auto& l : code_lines) std::cout << l << "\n";
        }

        if (m_show_watch) {
            print_separator();
            std::cout << (m_focus == FOCUS_WATCH || m_focus == FOCUS_BREAKPOINTS ? Terminal::YELLOW : Terminal::GREEN) << "[STATUS]" << Terminal::RESET << "\n";

            std::stringstream ss;
            std::string label = " WATCH: ";
            ss << Terminal::CYAN << label << Terminal::RESET;
            
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
                    ss << Terminal::GRAY << "... (+" << (items.size() - i) << ")" << Terminal::RESET;
                    break;
                }
                ss << Terminal::HI_WHITE << sep << items[i] << Terminal::RESET;
                current_len += sep.length() + items[i].length();
                first = false;
            }
            if (items.empty()) ss << Terminal::GRAY << "No items." << Terminal::RESET;
            std::cout << ss.str() << "\n";
            
            ss.str(""); ss.clear();
            label = " BREAK: ";
            ss << Terminal::RED << label << Terminal::RESET;
            
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
                    ss << Terminal::GRAY << "... (+" << (items.size() - i) << ")" << Terminal::RESET;
                    break;
                }
                ss << Terminal::HI_WHITE << sep << items[i] << Terminal::RESET;
                current_len += sep.length() + items[i].length();
                first = false;
            }
            if (items.empty()) ss << Terminal::GRAY << "No items." << Terminal::RESET;
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
        std::cout << Terminal::yellow("[OUTPUT]") << "\n";
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
        std::cout << Terminal::GRAY << "[" << Terminal::HI_WHITE << Terminal::BOLD << c.k << Terminal::RESET << Terminal::GRAY << "]" << c.n << " " << Terminal::RESET;
    }
    std::cout << "\n";
}

uint16_t Dashboard::find_prev_instruction_pc(uint16_t target_addr) {
    auto& analyzer = m_debugger.get_core().get_analyzer();
    auto& code_map = m_debugger.get_core().get_code_map();
    
    // 1. Try execution history
    const auto& history = m_debugger.get_execution_history();
    for (auto it = history.rbegin(); it != history.rend(); ++it) {
        uint16_t pc = it->pc;
        uint16_t diff = target_addr - pc;
        if (diff >= 1 && diff <= 6) {
             uint16_t temp = pc;
             analyzer.parse_instruction(temp);
             if (temp == target_addr) return pc;
        }
    }

    // 2. Try CodeMap (Look for FLAG_CODE_START)
    for (int offset = 1; offset <= 6; ++offset) {
        uint16_t candidate = target_addr - offset;
        if (code_map[candidate] & Z80Analyzer<Memory>::FLAG_CODE_START) {
             uint16_t temp = candidate;
             analyzer.parse_instruction(temp);
             if (temp == target_addr) return candidate;
        }
    }

    // 3. Fallback to heuristic
    for (int offset = 1; offset <= 4; ++offset) {
        uint16_t candidate_addr = target_addr - offset;
        
        // Skip if we know it's inside another instruction
        if (code_map[candidate_addr] & Z80Analyzer<Memory>::FLAG_CODE_INTERIOR) 
            continue;

        uint16_t temp_addr = candidate_addr;
        analyzer.parse_instruction(temp_addr);
        if (temp_addr == target_addr) {
            bool overlap = false;
            for (int k = 1; k < offset; ++k) {
                if (code_map[(uint16_t)(candidate_addr + k)] & Z80Analyzer<Memory>::FLAG_CODE_START) {
                    overlap = true;
                    break;
                }
            }
            if (overlap) continue;
            return candidate_addr;
        }
    }
    return target_addr - 1;
}

void Dashboard::update_code_view() {
    if (!m_auto_follow) return;
    uint16_t pc = m_debugger.get_core().get_cpu().get_PC();
    int offset = m_code_rows / 3;
    uint16_t addr = pc;
    for (int i = 0; i < offset; ++i) {
        addr = find_prev_instruction_pc(addr);
    }
    m_code_view_addr = addr;
}

void Dashboard::print_columns(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width) {
        size_t rows = std::max(left.size(), right.size());

        for (size_t i = 0; i < rows; ++i) {
            std::string l = (i < left.size()) ? left[i] : "";
            bool has_bg = (l.find("[100m") != std::string::npos);

            if (!right.empty()) {
                std::string l_padded = l;
                if (has_bg) l_padded += Terminal::BG_DARK_GRAY;
                std::cout << Strings::padding(l_padded, left_width);
                if (has_bg) std::cout << Terminal::RESET;
                std::cout << Terminal::GRAY << " | " << Terminal::RESET;
                if (i < right.size()) std::cout << " " << right[i];
            } else {
                std::cout << l;
                if (has_bg) std::cout << Terminal::BG_DARK_GRAY << Terminal::RESET;
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
