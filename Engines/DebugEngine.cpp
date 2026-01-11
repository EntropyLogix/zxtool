#include "DebugEngine.h"
#include "TraceModule.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cctype>
#include <algorithm>

#include "../Utils/Strings.h"
#include "../Utils/Commands.h"
#include "../Utils/Terminal.h"
#include "../Utils/Checksum.h"
#include "../Core/Expression.h"
#include <limits>

extern TraceModule g_trace_module;

struct TraceMemoryAdapter {
    uint16_t base_pc;
    const uint8_t* data;
    size_t len;
    uint8_t peek(uint16_t addr) const {
        if (addr >= base_pc && addr < base_pc + len) return data[addr - base_pc];
        return 0;
    }
    uint8_t read(uint16_t addr) const { return peek(addr); }
    void poke(uint16_t, uint8_t) {}
    void write(uint16_t, uint8_t) {}
};

static constexpr const char* HISTORY_FILE = ".zxtool_history";

void CommandRegistry::add(const std::vector<std::string>& names, CommandEntry entry) {
    bool first = true;
    for (const auto& name : names) {
        entry.is_alias = !first;
        m_commands[name] = entry;
        first = false;
    }
}

const CommandRegistry::CommandEntry* CommandRegistry::find_command(const std::string& name) const {
    auto it = m_commands.find(name);
    if (it != m_commands.end()) return &it->second;
    return nullptr;
}

std::string CommandRegistry::get_syntax(const std::string& cmd_name) const {
    auto it = m_commands.find(cmd_name);
    if (it == m_commands.end()) return "";
    const auto& entry = it->second;
    
    if (!entry.usage.empty()) return entry.usage;
    
    if (!entry.subcommands.empty()) {
        std::string s;
        int i = 0;
        for (const auto& pair : entry.subcommands) {
            if (i++ > 0) s += "|";
            s += pair.first;
        }
        return s;
    }
    
    if (!entry.param_types.empty()) {
        std::string s;
        for (size_t i = 0; i < entry.param_types.size(); ++i) {
            if (i > 0) s += " ";
            s += "<arg>";
        }
        return s;
    }
    return "";
}

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

void MemoryView::set_address(uint16_t addr) {
    m_cursor_addr = addr;
    m_view_addr = addr & 0xFFF0;
}

void MemoryView::scroll(int delta) {
    m_cursor_addr += delta;
    ensure_visible();
}

void MemoryView::ensure_visible() {
    int16_t dist = (int16_t)(m_cursor_addr - m_view_addr);
    int view_size = m_rows * 16;
    if (dist < 0) {
        m_view_addr = m_cursor_addr & 0xFFF0;
    } else if (dist >= view_size) {
        m_view_addr = (m_cursor_addr & 0xFFF0) - (m_rows - 1) * 16;
    }
}

bool MemoryView::on_key(const Terminal::Input& in) {
    if (in.key == Terminal::Key::TAB || in.c == '\t') {
        m_focus_ascii = !m_focus_ascii;
        return true;
    }

    if (in.key == Terminal::Key::UP) { scroll(-16); return true; }
    if (in.key == Terminal::Key::DOWN) { scroll(16); return true; }
    if (in.key == Terminal::Key::LEFT) { scroll(-1); return true; }
    if (in.key == Terminal::Key::RIGHT) { scroll(1); return true; }
    
    if (m_focus_ascii) {
        if (in.c >= 32 && in.c <= 126) {
            uint16_t addr = get_address();
            m_core.get_memory().write(addr, (uint8_t)in.c);
            m_core.get_code_map().invalidate_region(addr, 1);
            scroll(1);
            return true;
        }
        if (in.key == Terminal::Key::BACKSPACE || in.c == 127 || in.c == 8) {
            scroll(-1);
            return true;
        }
    } else {
        if (std::isxdigit(static_cast<unsigned char>(in.c))) {
            uint8_t nibble = 0;
            char c = std::toupper(in.c);
            if (c >= '0' && c <= '9') nibble = c - '0';
            else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
            
            uint16_t addr = get_address();
            uint8_t val = m_core.get_memory().peek(addr);
            val = (val << 4) | nibble;
            m_core.get_memory().write(addr, val);
            m_core.get_code_map().invalidate_region(addr, 1);
            return true;
        }
    }
    return false;
}

std::vector<std::string> MemoryView::render() {
    std::vector<std::string> lines;
    std::string sep = m_theme.separator + std::string(80, '-') + Terminal::RESET;
    lines.push_back(sep);

    uint16_t cursor_addr = m_cursor_addr;
    uint16_t view_start = m_view_addr;

    std::stringstream extra;
    extra << m_theme.value_dim << " View: " << m_theme.value_dim << Strings::hex(cursor_addr) << Terminal::RESET;
    lines.push_back(format_header("MEMORY", extra.str()));
    lines.push_back(sep);
    auto& mem = m_core.get_memory();
    std::string inactive_bg = Terminal::rgb_bg(220, 220, 220);
    for (int row = 0; row < m_rows; ++row) {
        std::stringstream ss;
        uint16_t base_addr = view_start + (uint16_t)(row * 16);
        ss << m_theme.address << Strings::hex(base_addr) << Terminal::RESET << ": ";
        for (size_t j = 0; j < 16; ++j) {
            uint16_t real_addr = base_addr + (uint16_t)j;
            uint8_t b = mem.peek(real_addr);
            bool is_cursor = (real_addr == cursor_addr);
            
            if (is_cursor) ss << (m_focus_ascii ? inactive_bg : m_theme.pc_bg);
            if (b == 0)
                ss << m_theme.value_dim << "00" << Terminal::RESET;
            else
                ss << Strings::hex(b) << (is_cursor ? Terminal::RESET : "");
            
            if (j == 7)
                ss << "  ";
            else if (j == 15)
                ss << "  ";
            else
                ss << " ";
        }
        ss << m_theme.separator << "|" << Terminal::RESET << " ";
        for (size_t j = 0; j < 16; ++j) {
            uint16_t real_addr = base_addr + (uint16_t)j;
            uint8_t val = mem.peek(real_addr);
            bool is_cursor = (real_addr == cursor_addr);
            if (is_cursor) ss << (m_focus_ascii ? m_theme.pc_bg : inactive_bg);
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
    lines.push_back(format_header("REGS"));
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
            ss << m_theme.highlight << c << Terminal::RESET;
        else
            ss << m_theme.value_dim << c << Terminal::RESET;
    }
    return ss.str();
}

bool StackView::on_key(const Terminal::Input& in) {
    if (in.key == Terminal::Key::UP) { scroll(-2); return true; }
    if (in.key == Terminal::Key::DOWN) { scroll(2); return true; }
    return false;
}

std::vector<std::string> StackView::render() {
    std::vector<std::string> lines;
    uint16_t sp = m_core.get_cpu().get_SP();
    
    // Blueprint Light Theme Colors
    std::string c_label  = Terminal::rgb_fg(0, 139, 139);   // Dark Cyan / Teal
    std::string c_addr   = m_theme.value_dim;               // Gray (Address)
    std::string c_val    = Terminal::rgb_fg(70, 130, 180);  // Steel Blue (Data)
    std::string c_info   = Terminal::rgb_fg(105, 105, 105); // Dark Gray
    std::string c_ghost  = Terminal::rgb_fg(192, 192, 192); // Light Gray
    std::string c_delta  = Terminal::rgb_fg(255, 241, 107);
    std::string bg_active = Terminal::rgb_bg(220, 220, 220); // Light Gray
    std::string rst      = Terminal::RESET;

    lines.push_back(format_header("STACK"));

    auto& mem = m_core.get_memory();
    auto& symbols = m_core.get_context().getSymbols();

    auto smart_decode = [&](uint16_t val) -> std::string {
        // 1. Return Address (Priority #1)
        uint8_t op_call = mem.peek(val - 3);
        bool is_call = (op_call == 0xCD || (op_call & 0xC7) == 0xC4);
        uint8_t op_rst = mem.peek(val - 1);
        bool is_rst = ((op_rst & 0xC7) == 0xC7);

        if (is_call || is_rst) {
            auto pair = symbols.find_nearest(val);
            if (!pair.first.empty()) {
                std::stringstream ss;
                ss << "ret: " << pair.first;
                if (pair.second != val) ss << "+" << (int)(val - pair.second);
                return ss.str();
            }
            return "ret";
        }

        // 2. Data Label (Priority #2)
        const Symbol* sym = symbols.find(val);
        if (sym) return "&" + sym->getName();

        // 3. ASCII (Priority #3)
        uint8_t l = val & 0xFF;
        uint8_t h = val >> 8;
        if (l >= 32 && l <= 126 && h >= 32 && h <= 126) {
            std::stringstream ss;
            ss << "'" << (char)l << (char)h << "'";
            return ss.str();
        }

        // 4. Fallback (Empty)
        return "";
    };

    if (m_view_addr == sp) {
        uint16_t ghost_addr = sp - 2;
        uint8_t l = mem.peek(ghost_addr);
        uint8_t h = mem.peek(ghost_addr + 1);
        uint16_t val = l | (h << 8);
        std::stringstream ss;
        ss << c_ghost << "  SP-02  " << Strings::hex(ghost_addr) << "  " << Strings::hex(val);
        std::string decoded = smart_decode(val);
        if (!decoded.empty()) {
            if (decoded.length() > 10) decoded = decoded.substr(0, 7) + "...";
            ss << "  .pop: " << decoded;
        }
        ss << rst;
        lines.push_back(ss.str());
    }

    for (int row = 0; row < m_rows; ++row) {
        uint16_t addr = m_view_addr + row * 2;
        uint8_t l = mem.peek(addr);
        uint8_t h = mem.peek(addr + 1);
        uint16_t val = l | (h << 8);
        std::stringstream ss;
        
        bool is_sp = (addr == sp);
        bool is_pushed = (sp < m_prev_sp && addr >= sp && addr < m_prev_sp);

        if (is_sp) ss << bg_active;

        std::string prefix = "  ";
        int offset = (int)addr - (int)sp;
        std::stringstream off_ss;
        
        if (offset >= 0 && offset < 128)
             off_ss << "SP+" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << offset;
        else if (offset < 0 && offset > -128)
             off_ss << "SP-" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << -offset;
        else
             off_ss << "     ";

        ss << c_label << prefix << off_ss.str() << rst;
        if (is_sp) ss << bg_active;

        ss << "  " << c_addr << Strings::hex(addr) << rst;
        if (is_sp) ss << bg_active;
        
        ss << "  ";
        if (is_pushed) ss << c_delta;
        else ss << c_val;
        
        ss << Strings::hex(val) << rst;
        if (is_sp) ss << bg_active;
        
        std::string decoded = smart_decode(val);
        if (!decoded.empty()) {
            if (decoded.length() > 15) decoded = decoded.substr(0, 12) + "...";
            ss << "  " << c_info << decoded << rst;
            if (is_sp) ss << bg_active;
        }
        
        if (is_sp) {
            int current_len = 19;
            if (!decoded.empty()) current_len += 2 + (int)decoded.length();
            int pad = 38 - current_len;
            if (pad > 0) ss << std::string(pad, ' ');
            ss << rst;
        }
        lines.push_back(ss.str());
    }
    return lines;
}

std::vector<std::string> WatchView::render() {
    std::vector<std::string> lines;
    const auto& watches = m_debugger.get_watches();
    std::string extra;
    if (watches.size() > 3) extra = " (Top 3)";
    lines.push_back(format_header("WATCH", extra));

    int count = 0;
    for (size_t i = 0; i < watches.size() && count < 3; ++i) {
        std::stringstream ss;
        ss << m_theme.value_dim << "#" << (i + 1) << " " << Terminal::RESET;
        
        std::string expr = watches[i];
        std::string expr_display = expr;
        if (expr_display.length() > 12) expr_display = expr_display.substr(0, 11) + ".";
        ss << m_theme.label << std::left << std::setw(12) << expr_display << Terminal::RESET << " ";

        try {
            Expression eval(m_core);
            auto val = eval.evaluate(expr);
            std::string val_str;
            std::string smart;
            
            if (val.is_number() || val.is_register() || val.is_symbol()) {
                double d = val.get_scalar(m_core);
                int64_t v = (int64_t)d;
                std::stringstream vs;
                vs << Strings::hex((uint16_t)v) << "  " << std::dec << v;
                val_str = vs.str();
                if (v >= 32 && v <= 126) smart = std::string("'") + (char)v + "'";
                else smart = ".";
            } else {
                val_str = "Complex";
                smart = "?";
            }

            if (val_str.length() > 15) val_str = val_str.substr(0, 14) + ".";
            ss << m_theme.value << std::left << std::setw(15) << val_str << Terminal::RESET << " ";
            ss << m_theme.comment << std::left << std::setw(6) << smart << Terminal::RESET;
        } catch (...) {
            ss << m_theme.error << "Error" << Terminal::RESET;
        }
        lines.push_back(ss.str());
        count++;
    }
    if (watches.size() > 3) {
        lines.push_back(m_theme.value_dim + "... (+" + std::to_string(watches.size() - 3) + " more)" + Terminal::RESET);
    }
    return lines;
}

std::vector<std::string> BreakpointView::render() {
    std::vector<std::string> lines;
    const auto& bps = m_debugger.get_breakpoints();
    std::string extra;
    if (bps.size() > 3) extra = " (Top 3)";
    lines.push_back(format_header("BREAKPOINTS", extra));

    int count = 0;
    for (size_t i = 0; i < bps.size() && count < 3; ++i) {
        const auto& bp = bps[i];
        std::stringstream ss;
        ss << m_theme.value_dim << "#" << (i + 1) << " " << Terminal::RESET;
        ss << (bp.enabled ? (m_theme.highlight + "[*]") : (m_theme.value_dim + "[ ]")) << Terminal::RESET << " ";
        ss << m_theme.address << Strings::hex(bp.addr) << Terminal::RESET << "  ";
        
        auto sym = m_core.get_context().getSymbols().find_nearest(bp.addr);
        std::string label = (!sym.first.empty() && sym.second == bp.addr) ? sym.first : "";
        if (label.length() > 20) label = label.substr(0, 17) + "...";
        ss << m_theme.label << label << Terminal::RESET;
        
        lines.push_back(ss.str());
        count++;
    }
    if (bps.size() > 3) {
        lines.push_back(m_theme.value_dim + "... (+" + std::to_string(bps.size() - 3) + " more)" + Terminal::RESET);
    }
    return lines;
}

void CodeView::format_operands(const Z80Analyzer<Memory>::CodeLine& line, std::ostream& os, const std::string& color_num, const std::string& color_rst, bool bold) {
    if (line.operands.empty()) return;
    using Operand = Z80Analyzer<Memory>::CodeLine::Operand;
    for (size_t i = 0; i < line.operands.size(); ++i) {
        if (i > 0)
            os << ", ";
        const auto& op = line.operands[i];

        std::string label;
        if (op.type == Operand::IMM16 || op.type == Operand::MEM_IMM16) {
             const Symbol* s = m_core.get_context().getSymbols().find((uint16_t)op.num_val);
             if (s) label = s->getName();
        }

        bool is_num = (op.type == Operand::IMM8 || op.type == Operand::IMM16 || op.type == Operand::MEM_IMM16);
        if (!label.empty() && !color_num.empty())
            os << m_theme.label << (bold ? Terminal::BOLD : "");
        else if (is_num)
            os << color_num;
        switch (op.type) {
            case Operand::REG8:
            case Operand::REG16:
            case Operand::CONDITION:
                os << op.s_val;
                break;
            case Operand::IMM8:
                os << "$" << Strings::hex((uint8_t)op.num_val);
                break;
            case Operand::IMM16:
                if (!label.empty())
                    os << label;
                else
                    os << "$" << Strings::hex((uint16_t)op.num_val);
                break;
            case Operand::MEM_IMM16:
                if (!label.empty())
                    os << "(" << label << ")";
                else
                    os << "($" << Strings::hex((uint16_t)op.num_val) << ")";
                break;
            case Operand::PORT_IMM8:
                os << "($" << Strings::hex((uint8_t)op.num_val) << ")";
                break;
            case Operand::MEM_REG16:
                os << "(" << op.s_val << ")";
                break;
            case Operand::MEM_INDEXED:
                os << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")";
                break;
            case Operand::STRING:
                os << "\"" << op.s_val << "\"";
                break;
            case Operand::CHAR_LITERAL:
                os << "'" << (char)op.num_val << "'";
                break;
            default:
                break;
        }
        if (is_num || !label.empty())
            os << color_rst;
    }
}

Z80Analyzer<Memory>::CodeLine CodeView::resolve_line(uint16_t addr, bool& conflict, bool& shadow, bool& is_orphan) {
    Z80Analyzer<Memory>::CodeLine line;
    auto* code_map = &m_core.get_code_map();
    bool is_pc_line = (addr == m_pc);
    conflict = false;
    shadow = false;
    is_orphan = false;

    if (addr < m_pc) {
        // Lookahead logic: Check for collision with PC ("Kill the Parent")
        bool handled = false;
        uint8_t flags = (*code_map)[addr];
        
        if (flags & CodeMap::FLAG_CODE_START) {
            auto p = m_core.get_analyzer().parse_instruction(addr);
            if (addr + p.bytes.size() > m_pc) {
                // Collision detected! Parent swallows PC. Kill the parent.
                line = m_core.get_analyzer().parse_db(addr, 1);
                is_orphan = true;
                handled = true;
            } else {
                line = p;
                handled = true;
            }
        } else if (flags & CodeMap::FLAG_CODE_INTERIOR) {
            // Orphaned byte from previous instruction (which was killed or scrolled out)
            line = m_core.get_analyzer().parse_db(addr, 1);
            shadow = true;
            handled = true;
        }
        
        if (!handled) {
            // Heuristic check: if it looks like code that overlaps PC, kill it.
            auto p = m_core.get_analyzer().parse_instruction(addr);
            if (p.bytes.size() > 0 && addr + p.bytes.size() > m_pc) {
                    line = m_core.get_analyzer().parse_db(addr, 1);
                    is_orphan = true;
            } else {
                    // Use standard parsing respecting map (but avoid skipping)
                    uint16_t next = addr;
                    auto lines = m_core.get_analyzer().parse_code(next, 1, code_map);
                    if (!lines.empty()) {
                        line = lines[0];
                        // Double check collision
                        if (addr + line.bytes.size() > m_pc) {
                            line = m_core.get_analyzer().parse_db(addr, 1);
                            is_orphan = true;
                        }
                    } else {
                        line = m_core.get_analyzer().parse_db(addr, 1);
                    }
            }
        }
    } else {
        // At PC or after: CPU is always right
        line = m_core.get_analyzer().parse_instruction(addr);
        uint8_t flags = (*code_map)[(uint16_t)line.address];
        
        if (is_pc_line) {
            if (flags & CodeMap::FLAG_CODE_INTERIOR) {
                // Logic Layer: PC is inside another instruction. Enforce new instruction.
                conflict = true;
                m_core.get_code_map().mark_code(addr, line.bytes.size(), true);
            }
        } else {
            if (flags & CodeMap::FLAG_CODE_INTERIOR) shadow = true;
        }
    }
    // Safety check: ensure we never return a 0-length line to avoid infinite loops
    if (line.bytes.empty()) {
        line = m_core.get_analyzer().parse_db(addr, 1);
    }
    return line;
}

CodeView::DisasmInfo CodeView::format_disasm(const Z80Analyzer<Memory>::CodeLine& line, bool is_pc, bool is_cursor, bool conflict, bool shadow, bool is_orphan, bool is_traced, bool is_smc) {
    std::stringstream mn_ss;
    std::string rst = is_cursor ? (Terminal::RESET + m_theme.pc_bg) : Terminal::RESET;

    if (is_pc) mn_ss << m_theme.mnemonic << Terminal::BOLD;
    else if (conflict || is_orphan) mn_ss << m_theme.error;
    else if (shadow) mn_ss << m_theme.value_dim;
    else if (is_traced) mn_ss << m_theme.value_dim;
    else mn_ss << m_theme.mnemonic;
    
    mn_ss << line.mnemonic << rst;
    if (!line.operands.empty()) {
        mn_ss << " ";
        if ((is_traced && !is_pc) || shadow) {
            mn_ss << m_theme.value_dim;
            format_operands(line, mn_ss, "", "");
        } else if (conflict || is_orphan) {
            format_operands(line, mn_ss, m_theme.error, rst);
        } else if (is_pc) {
            std::string rst_bold = rst + Terminal::BOLD;
            mn_ss << Terminal::BOLD;
            format_operands(line, mn_ss, m_theme.operand_num + Terminal::BOLD, rst_bold, true);
            // Restore non-bold reset for the end of line if needed, though render handles it
            mn_ss << rst; 
        } else {
            format_operands(line, mn_ss, m_theme.operand_num, rst);
        }
    }
    if (conflict) mn_ss << " (!)";
    if (shadow) mn_ss << " (?)";
    if (is_orphan) mn_ss << " (!)";

    std::string mn_str = mn_ss.str();
    int visible_len = (int)Strings::length(mn_str);
    return {mn_str, visible_len};
}

std::vector<std::string> CodeView::render() {
    std::vector<std::string> lines_out;
    lines_out.push_back(""); // Placeholder for header
    if (m_has_history && m_start_addr == m_pc && (m_last_pc != m_pc || !m_pc_moved)) {
        uint16_t hist_addr = m_last_pc;
        uint16_t temp_hist = hist_addr;
        auto line = m_core.get_analyzer().parse_instruction(temp_hist);
        if (!line.mnemonic.empty()) {
            bool is_smc = false;
            auto* code_map = &m_core.get_code_map();
            for (size_t i = 0; i < line.bytes.size(); ++i) {
                if ((*code_map)[(uint16_t)(line.address + i)] & CodeMap::FLAG_DATA_WRITE) {
                    is_smc = true;
                    break;
                }
            }
            std::stringstream ss;
            if (is_smc) ss << m_theme.value_dim << "M  " << Terminal::RESET;
            else ss << "   ";
            ss << m_theme.value_dim << Strings::hex((uint16_t)line.address) << ": ";
            std::stringstream hex_ss;
            if (line.bytes.size() > 3)
                hex_ss << Strings::hex(line.bytes[0]) << " " << Strings::hex(line.bytes[1]) << " ..";
            else {
                for(size_t i=0; i<line.bytes.size(); ++i) {
                    if (i > 0) hex_ss << " ";
                    hex_ss << Strings::hex(line.bytes[i]);
                }
            }
            std::string hex_str = hex_ss.str();
            ss << hex_str;
            int hex_pad = 9 - (int)hex_str.length();
            if (hex_pad > 0) ss << std::string(hex_pad, ' ');
            ss << "  ";
            ss << line.mnemonic;
            if (!line.operands.empty()) {
                ss << " ";
                format_operands(line, ss, "", "");
            }
            ss << Terminal::RESET;
            lines_out.push_back(ss.str());
        }
    }
    uint16_t temp_pc_iter = m_start_addr;
    bool first_line = true;
    int lines_count = 0;
    int lines_to_skip = m_skip_lines;
    bool pc_visible = false;
    while (lines_count < m_rows) {
        bool conflict = false, shadow = false, is_orphan = false;
        auto line = resolve_line(temp_pc_iter, conflict, shadow, is_orphan);
        bool is_pc = (temp_pc_iter == m_pc);
        bool is_cursor = (temp_pc_iter == m_cursor_addr);
        if (is_pc) pc_visible = true;

        bool is_smc = false;
        auto* code_map = &m_core.get_code_map();
        for (size_t i = 0; i < line.bytes.size(); ++i) {
            if ((*code_map)[(uint16_t)(line.address + i)] & CodeMap::FLAG_DATA_WRITE) {
                is_smc = true;
                break;
            }
        }

        auto& ctx = m_core.get_analyzer().context;
        const Comment* block_cmt = ctx.getComments().find((uint16_t)line.address, Comment::Type::Block);
        bool has_block_desc = block_cmt && !block_cmt->getText().empty();
        bool has_label = !line.label.empty();
        if (block_cmt) {
             const auto& desc = block_cmt->getText();
             if (!desc.empty()) {
                 std::stringstream desc_ss(desc);
                 std::string segment;
                 while(lines_count < m_rows && std::getline(desc_ss, segment, '\n')) {
                     if (m_width > 0 && (int)segment.length() > m_width) {
                         if (m_wrap_comments) {
                             size_t pos = 0;
                             while (pos < segment.length() && lines_count < m_rows) {
                                 std::string sub = segment.substr(pos, m_width);
                                 if (lines_to_skip > 0) {
                                     lines_to_skip--;
                                 } else {
                                     lines_out.push_back(m_theme.value_dim + sub + Terminal::RESET);
                                     lines_count++;
                                 }
                                 pos += m_width;
                             }
                         } else {
                             std::string sub = segment.substr(0, m_width > 3 ? m_width - 3 : m_width) + (m_width > 3 ? "..." : "");
                             if (lines_to_skip > 0) {
                                 lines_to_skip--;
                             } else {
                                 lines_out.push_back(m_theme.value_dim + sub + Terminal::RESET);
                                 lines_count++;
                             }
                         }
                     } else {
                         if (lines_to_skip > 0) {
                             lines_to_skip--;
                         } else {
                             lines_out.push_back(m_theme.value_dim + segment + Terminal::RESET);
                             lines_count++;
                         }
                     }
                 }
             }
        }
        if (!line.label.empty() && lines_count < m_rows) {
            if (lines_to_skip > 0) {
                lines_to_skip--;
            } else {
                lines_out.push_back(m_theme.label + line.label + ":" + Terminal::RESET);
                lines_count++;
            }
        }
        std::stringstream ss;
        bool is_traced = (m_debugger && m_debugger->is_traced((uint16_t)line.address));
        std::string bg = is_cursor ? m_theme.pc_bg : "";
        std::string rst = is_cursor ? (Terminal::RESET + bg) : Terminal::RESET;
        if (is_pc) 
            ss << bg << m_theme.header_blur << Terminal::BOLD << (is_smc ? ">M " : ">  ") << rst;
        else if (is_smc) {
            if (shadow || is_traced) ss << m_theme.value_dim << "M  " << rst;
            else ss << m_theme.error << "M  " << rst;
        }
        else
            ss << bg << "   " << rst;
        
        std::string addr_color = m_theme.address;
        if (is_pc) addr_color = m_theme.address + Terminal::BOLD;
        else if (conflict || is_orphan) addr_color = m_theme.error;
        else if (shadow) addr_color = m_theme.value_dim;
        else if (is_traced) addr_color = m_theme.value_dim;

        ss << addr_color << Strings::hex((uint16_t)line.address) << rst << ": ";

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
        ss << m_theme.value_dim;
        if (is_pc) ss << Terminal::BOLD;
        ss << hex_str << rst;
        int hex_len = (int)hex_str.length();
        int hex_pad = 9 - hex_len;
        if (hex_pad > 0)
            ss << std::string(hex_pad, ' ');
        ss << "  ";
        
        auto disasm_info = format_disasm(line, is_pc, is_cursor, conflict, shadow, is_orphan, is_traced, is_smc);
        ss << disasm_info.text;
        int comment_col = 30;
        int padding = comment_col - disasm_info.visible_len;
        if (padding < 1) padding = 1;
        ss << std::string(padding, ' ');

        std::vector<std::string> extra_lines;
        const Comment* inline_cmt = ctx.getComments().find((uint16_t)line.address, Comment::Type::Inline);
        if (inline_cmt) {
             const auto& comment = inline_cmt->getText();
             if (!comment.empty()) {
                 std::string cmt_full = "; " + comment;
                 int max_width = (m_width > 0) ? m_width : 80;
                 int current_len = disasm_info.visible_len + padding;
                 int available = max_width - current_len;
                 if (available < 10) available = 10;

                 if (m_wrap_comments) {
                     if ((int)cmt_full.length() > available) {
                         ss << m_theme.comment;
                         if (is_pc) ss << Terminal::BOLD;
                         ss << cmt_full.substr(0, available) << Terminal::RESET;
                         int next_available = m_width - comment_col;
                         if (next_available < 10) next_available = 10;
                         size_t pos = available;
                         while (pos < cmt_full.length()) {
                             extra_lines.push_back(cmt_full.substr(pos, next_available));
                             pos += next_available;
                         }
                     } else {
                         ss << m_theme.comment;
                         if (is_pc) ss << Terminal::BOLD;
                         ss << cmt_full << Terminal::RESET;
                     }
                 } else {
                     if ((int)cmt_full.length() > available)
                         cmt_full = cmt_full.substr(0, available - 3) + "...";
                     ss << m_theme.comment;
                     if (is_pc) ss << Terminal::BOLD;
                     ss << cmt_full << Terminal::RESET;
                 }
             }
        }
        if (m_width > 0) {
            std::string s = ss.str();
            if (is_cursor)
                s += m_theme.pc_bg;
            s = Strings::padding(s, m_width);
            s += Terminal::RESET; 
            if (lines_count < m_rows) {
                if (lines_to_skip > 0) {
                    lines_to_skip--;
                } else {
                    lines_out.push_back(s);
                    lines_count++;
                }
            }
            for (const auto& el : extra_lines) {
                if (lines_count < m_rows) {
                    if (lines_to_skip > 0) {
                        lines_to_skip--;
                    } else {
                        std::string s = std::string(comment_col, ' ') + m_theme.comment + el + Terminal::RESET;
                        lines_out.push_back(Strings::padding(s, m_width));
                        lines_count++;
                    }
                }
            }
        } else {
            if (lines_count < m_rows) {
                if (lines_to_skip > 0) {
                    lines_to_skip--;
                } else {
                    lines_out.push_back(ss.str());
                    lines_count++;
                }
            }
            for (const auto& el : extra_lines) {
                if (lines_count < m_rows) {
                    if (lines_to_skip > 0) {
                        lines_to_skip--;
                    } else {
                        lines_out.push_back(std::string(comment_col, ' ') + m_theme.comment + el + Terminal::RESET);
                        lines_count++;
                    }
                }
            }
        }
        first_line = false;
        temp_pc_iter += line.bytes.size();
    }

    long long delta = (long long)m_tstates - m_prev_tstates;
    std::stringstream ss_len;
    ss_len << "T: " << m_tstates;
    if (delta > 0) ss_len << " (+" << delta << ")";
    
    std::string arrow_str;
    if (!pc_visible) {
        int16_t dist = (int16_t)(m_pc - m_start_addr);
        std::string arrow = (dist < 0) ? Terminal::ARROW_UP : Terminal::ARROW_DOWN;
        arrow_str = " " + m_theme.separator + "|" + Terminal::RESET + " " + m_theme.highlight + "PC " + arrow + Terminal::RESET;
    }

    int arrow_len = (int)Strings::length(arrow_str);
    if (!arrow_str.empty()) arrow_len -= 2;
    int padding = std::max(1, m_width - 6 - (int)ss_len.str().length() - arrow_len);
    std::stringstream extra;
    extra << std::string(padding, ' ') << m_theme.value_dim << "T: " << m_tstates << Terminal::RESET;
    if (delta > 0)
        extra << m_theme.highlight << " (+" << delta << ")" << Terminal::RESET;
    extra << arrow_str;
    lines_out[0] = format_header("CODE", extra.str());
    return lines_out;
}

void CodeView::scroll(int delta) {
    if (delta < 0) {
        m_start_addr += delta;
    } else {
        uint16_t temp = m_start_addr;
        auto line = m_core.get_analyzer().parse_instruction(temp);
        m_start_addr += line.bytes.size();
    }
}

int CodeView::get_meta_height(uint16_t addr) {
    int lines = 0;
    if (!m_core.get_context().getSymbols().get_label(addr).empty()) lines++;
    
    const Comment* block_cmt = m_core.get_context().getComments().find(addr, Comment::Type::Block);
    if (block_cmt && !block_cmt->getText().empty()) {
        std::stringstream desc_ss(block_cmt->getText());
        std::string segment;
        while(std::getline(desc_ss, segment, '\n')) {
            if (m_wrap_comments && m_width > 0 && (int)segment.length() > m_width) {
                lines += (segment.length() + m_width - 1) / m_width;
            } else {
                lines++;
            }
        }
    }
    return lines;
}

int CodeView::get_line_height(uint16_t addr) {
    int lines = get_meta_height(addr);
    lines++; // Base instruction line
    
    const Comment* inline_cmt = m_core.get_context().getComments().find(addr, Comment::Type::Inline);
    if (inline_cmt && !inline_cmt->getText().empty() && m_wrap_comments && m_width > 0) {
        auto l = m_core.get_analyzer().parse_instruction(addr);
        // Estimate visible length of instruction
        auto info = format_disasm(l, false, false, false, false, false, false, false);
        
        int comment_col = 30;
        int padding = comment_col - info.visible_len;
        if (padding < 1) padding = 1;
        
        int current_len = info.visible_len + padding;
        int max_width = m_width;
        int available = max_width - current_len;
        if (available < 10) available = 10;
        
        std::string cmt_full = "; " + inline_cmt->getText();
        if ((int)cmt_full.length() > available) {
            int next_available = m_width - comment_col;
            if (next_available < 10) next_available = 10;
            
            int remaining_len = (int)cmt_full.length() - available;
            if (remaining_len > 0) {
                lines += (remaining_len + next_available - 1) / next_available;
            }
        }
    }
    return lines;
}

void CodeView::move_cursor(int delta) {
    if (delta < 0) {
        uint16_t prev = m_core.get_analyzer().parse_instruction_backwards(m_cursor_addr, &m_core.get_code_map());
        m_cursor_addr = prev;
        int diff = (int)m_start_addr - (int)m_cursor_addr;
        if (diff > 0 && diff < 100) {
            m_start_addr = m_cursor_addr;
            m_skip_lines = 0;
        } else if (diff < -60000) {
            m_start_addr = m_cursor_addr;
            m_skip_lines = 0;
        }
    } else {
        auto line = m_core.get_analyzer().parse_instruction(m_cursor_addr);
        m_cursor_addr += line.bytes.size();
        
        while (true) {
            uint16_t p = m_start_addr;
            bool visible = false;
            
            int current_row = -m_skip_lines;
            int safety = 0;

            while (current_row < m_rows && safety++ < 1000) {
                int h = get_line_height(p);
                int meta = get_meta_height(p);

                if (p == m_cursor_addr) {
                    int instr_row = current_row + meta;
                    if (instr_row >= 0 && instr_row < m_rows) visible = true;
                    break;
                }

                current_row += h;

                auto l = m_core.get_analyzer().parse_instruction(p);
                if (l.bytes.empty()) p++; else p += l.bytes.size();
            }

            if (visible) break;

            if (m_start_addr == m_cursor_addr) {
                int meta_lines = get_meta_height(m_start_addr);
                if (meta_lines - m_skip_lines >= m_rows) {
                    m_skip_lines = meta_lines - m_rows + 1;
                }
                break;
            }
            
            auto l = m_core.get_analyzer().parse_instruction(m_start_addr);
            m_start_addr += l.bytes.size();
            m_skip_lines = 0;
        }
    }
}

bool CodeView::on_key(const Terminal::Input& in) {
    if (in.key == Terminal::Key::UP) { move_cursor(-1); return true; }
    if (in.key == Terminal::Key::DOWN) { move_cursor(1); return true; }
    return false;
}

void Dashboard::draw_prompt() {
    std::string prompt = (m_focus == FOCUS_CMD) ? (m_theme.header_focus + "[COMMAND] " + Terminal::RESET) : (Terminal::RESET + m_theme.header_blur + "[COMMAND] " + Terminal::RESET);
    m_editor.draw(prompt);
    std::cout << "\033[?12h" << std::flush;
}

void Dashboard::run() {
    init();
    m_editor.history_load(HISTORY_FILE);
    m_editor.set_completion_callback([this](const std::string& input) { 
        if (!m_show_autocompletion)
            return Terminal::Completion();
        return m_autocompletion.get(input); 
    });
    m_editor.set_hint_callback([this](const std::string& input, int cursor_pos, std::string& color, int& error_pos, std::vector<int>& highlights) { return m_hint.calculate(input, cursor_pos, color, error_pos, highlights); });
    update_code_view();
    update_stack_view();
    m_memory_view.set_address(m_debugger.get_core().get_cpu().get_PC());
    validate_focus();
    Terminal::enable_raw_mode();
    std::string last_command;
    bool needs_repaint = true;
    while (m_running) {
        if (needs_repaint) {
            Terminal::disable_raw_mode();
            print_dashboard();
            Terminal::enable_raw_mode();
            draw_prompt();
            needs_repaint = false;
        }
        Terminal::Input in = Terminal::read_key();
        if (in.key == Terminal::Key::NONE)
            continue;

        bool handled = false;
        bool pass_to_editor = false;
        bool cmd_empty = m_editor.get_line().empty();

        if (in.key == Terminal::Key::SHIFT_TAB) {
            m_last_focus = FOCUS_CMD;
            m_focus = (Focus)((m_focus + 1) % FOCUS_COUNT);
            validate_focus();
            needs_repaint = true;
            handled = true;
        }

        // 1. View Specific Navigation (Precedence if focused)
        if (!handled && m_focus != FOCUS_CMD) {
            bool view_handled = false;
            if (m_focus == FOCUS_MEMORY) view_handled = m_memory_view.on_key(in);
            else if (m_focus == FOCUS_CODE) {
                view_handled = m_code_view.on_key(in);
                if (view_handled) m_auto_follow = false;
            }
            else if (m_focus == FOCUS_STACK) view_handled = m_stack_view.on_key(in);
            else if (m_focus == FOCUS_REGS) view_handled = m_register_view.on_key(in);
            
            if (view_handled) {
                needs_repaint = true;
                handled = true;
            }
        }

        // 2. Space Toggle
        if (!handled && in.c == ' ') {
            if (m_focus != FOCUS_CMD) {
                if (cmd_empty) {
                    m_last_focus = m_focus;
                    m_focus = FOCUS_CMD;
                    needs_repaint = true;
                    handled = true;
                }
            } else {
                if (cmd_empty) {
                    if (m_last_focus != FOCUS_CMD) m_focus = m_last_focus;
                    else m_focus = FOCUS_CODE;
                    validate_focus();
                    needs_repaint = true;
                    handled = true;
                }
            }
        }

        // 4. ESC Handling
        if (!handled && in.key == Terminal::Key::ESC) {
            if (m_focus == FOCUS_CMD) {
                if (!cmd_empty) {
                    m_editor.clear();
                    needs_repaint = true;
                    handled = true;
                } else {
                    m_auto_follow = true;
                    update_code_view();
                    update_stack_view();
                    needs_repaint = true;
                    handled = true;
                }
            } else {
                if (!m_auto_follow) {
                    m_auto_follow = true;
                    update_code_view();
                    update_stack_view();
                    needs_repaint = true;
                    handled = true;
                } else {
                    m_last_focus = m_focus;
                    m_focus = FOCUS_CMD;
                    needs_repaint = true;
                    handled = true;
                }
            }
        }

        // 5. Pass to Editor
        if (!handled) {
            if (m_focus == FOCUS_CMD) {
                pass_to_editor = true;
            } else {
                if (!iscntrl(static_cast<unsigned char>(in.c)) || in.key == Terminal::Key::BACKSPACE || in.key == Terminal::Key::ENTER || in.key == Terminal::Key::TAB) {
                    pass_to_editor = true;
                }
            }
        }

        if (pass_to_editor) {
            auto res = m_editor.on_key(in);
            if (res == Terminal::LineEditor::Result::SUBMIT) {
                std::string cmd = m_editor.get_line();
                if (cmd.empty() && !last_command.empty())
                    cmd = last_command;
                if (!cmd.empty()) {
                    m_editor.history_add(cmd);
                    last_command = cmd;
                }
                m_editor.clear();
                Terminal::disable_raw_mode();
                m_output_buffer << cmd << "\n";
                handle_command(cmd);
                Terminal::enable_raw_mode();
                needs_repaint = true;
            } else if (res != Terminal::LineEditor::Result::IGNORED)
                draw_prompt();
        }
    }
    Terminal::disable_raw_mode();
    m_editor.history_save(HISTORY_FILE);
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
        m_output_buffer << format(val, detailed, expr) << "\n";
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
    size_t eq_pos = args.find('=');
    if (eq_pos == std::string::npos) {
        m_output_buffer << "Error: Invalid syntax for set. '=' is required. Use: set <target> = <value>\n";
        return;
    }
    std::string lhs_str = Strings::trim(args.substr(0, eq_pos));
    std::string rhs_str = Strings::trim(args.substr(eq_pos + 1));
    if (lhs_str.empty() || rhs_str.empty()) {
        m_output_buffer << "Error: Invalid syntax for set. Use: set <target> = <value>\n";
        return;
    }

    if (lhs_str.length() >= 2 && lhs_str[0] == '@' && lhs_str[1] == '@') {
        std::string var_name;
        size_t j = 2;
        while (j < lhs_str.length() && (std::isalnum(static_cast<unsigned char>(lhs_str[j])) || lhs_str[j] == '_')) {
            var_name += lhs_str[j];
            j++;
        }
        auto& vars = m_debugger.get_core().get_context().getVariables();
        if (vars.find(var_name)) {
             m_output_buffer << "Error: System variable @@" << var_name << " is read-only.\n";
        } else {
             m_output_buffer << "Error: Cannot define new system variable @@" << var_name << ".\n";
        }
        return;
    }

    try {
        Expression eval(m_debugger.get_core());
        Expression::Value val = eval.evaluate(rhs_str);

        eval.assign(lhs_str, val);
        m_output_buffer << lhs_str << " = " << format(val, detailed) << "\n";
        if (Strings::upper(lhs_str) == "PC") {
            m_auto_follow = true;
        }
        update_code_view();
        update_stack_view();
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::cmd_evaluate(const std::string& args) {
    perform_evaluate(args, false);
}

void Dashboard::cmd_expression(const std::string& args) {
    if (Commands::is_assignment(args))
        perform_set(args, false);
    else
        perform_evaluate(args, false);
}

void Dashboard::cmd_expression_detailed(const std::string& args) {
    if (Commands::is_assignment(args))
        perform_set(args, true);
    else
        perform_evaluate(args, true);
}

void Dashboard::cmd_quit(const std::string&) {
    m_running = false;
}

void Dashboard::cmd_help(const std::string& args) {
    std::string clean_args = Strings::trim(args);
    if (clean_args.empty()) {
        m_output_buffer << "Available commands:\n";
        m_output_buffer << "------------------------------------------------------------\n";
        const auto& cmds = m_command_registry.get_commands();
        for (const auto& pair : cmds) {
            if (!pair.second.is_alias) {
                std::string syntax = m_command_registry.get_syntax(pair.first);
                m_output_buffer << std::left << std::setw(15) << pair.first << std::setw(30) << syntax << pair.second.description << "\n";
            }
        }
    } else {
        auto parts = Strings::split(clean_args, ' ');
        std::string cmd_name = parts[0];
        const auto* entry = m_command_registry.find_command(cmd_name);
        
        if (!entry) {
            m_output_buffer << "Unknown command: " << cmd_name << "\n";
            return;
        }

        const CommandRegistry::SubcommandEntry* sub = nullptr;
        std::string path = cmd_name;

        for (size_t i = 1; i < parts.size(); ++i) {
            const auto& subs = (sub ? sub->subcommands : entry->subcommands);
            auto it = subs.find(parts[i]);
            if (it != subs.end()) {
                sub = &it->second;
                path += " " + parts[i];
            } else {
                break;
            }
        }

        std::string desc = sub ? sub->description : entry->description;
        std::string usage = sub ? sub->usage : entry->usage;
        if (usage.empty()) {
             if (sub) usage = ""; // Could generate from param_types if needed
             else usage = m_command_registry.get_syntax(cmd_name);
        }

        m_output_buffer << "Command: " << path << "\n";
        m_output_buffer << "Description: " << desc << "\n";
        m_output_buffer << "Usage: " << path << " " << usage << "\n";

        const auto& subs = (sub ? sub->subcommands : entry->subcommands);
        if (!subs.empty()) {
            m_output_buffer << "\nSubcommands:\n";
            size_t max_len = 0;
            for (const auto& pair : subs) {
                if (pair.first.length() > max_len) max_len = pair.first.length();
            }
            for (const auto& pair : subs) {
                m_output_buffer << "  " << std::left << std::setw((int)(max_len + 2)) << pair.first << pair.second.description << "\n";
            }
        }
    }
}

void Dashboard::cmd_step(const std::string& args) {
    int count = 1;
    if (!args.empty()) {
        try {
            Expression eval(m_debugger.get_core());
            auto val = eval.evaluate(args);
            count = (int)val.get_scalar(m_debugger.get_core());
        } catch (const std::exception& e) {
            m_output_buffer << "Error: " << e.what() << "\n";
            return;
        }
    }
    m_debugger.step(count);
    m_auto_follow = true;
    update_code_view();
    update_stack_view();
}

void Dashboard::cmd_next(const std::string&) {
    Terminal::enable_raw_mode();
    std::cout << "Stepping... (Press ESC to stop)\r\n" << std::flush;
    m_debugger.next();
    Terminal::disable_raw_mode();
    m_auto_follow = true;
    update_code_view();
    update_stack_view();
}

void Dashboard::cmd_memory(const std::string& args) {
    if (args.empty()) {
        m_focus = FOCUS_MEMORY;
        m_show_mem = true;
        return;
    }
    try {
        Expression eval(m_debugger.get_core());
        auto val = eval.evaluate(args);
        uint16_t addr = 0;
        if (val.is_address() && !val.address().empty()) addr = val.address()[0];
        else if (val.is_number()) addr = (uint16_t)val.number();
        else if (val.is_symbol()) addr = val.symbol().read();
        else if (val.is_register()) addr = val.reg().read(m_debugger.get_core().get_cpu());
        else { m_output_buffer << "Invalid address.\n"; return; }
        
        m_memory_view.set_address(addr);
        m_focus = FOCUS_MEMORY;
        m_show_mem = true;
        m_output_buffer << "Memory cursor set to $" << Strings::hex(addr) << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::cmd_code(const std::string& args) {
    if (args.empty()) {
        m_focus = FOCUS_CODE;
        m_show_code = true;
        return;
    }
    try {
        Expression eval(m_debugger.get_core());
        auto val = eval.evaluate(args);
        uint16_t addr = 0;
        if (val.is_address() && !val.address().empty()) addr = val.address()[0];
        else if (val.is_number()) addr = (uint16_t)val.number();
        else if (val.is_symbol()) addr = val.symbol().read();
        else if (val.is_register()) addr = val.reg().read(m_debugger.get_core().get_cpu());
        else { m_output_buffer << "Invalid address.\n"; return; }
        
        m_auto_follow = false;
        center_code_view(addr);
        m_focus = FOCUS_CODE;
        m_show_code = true;
        m_output_buffer << "Code view centered at $" << Strings::hex(addr) << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

void Dashboard::cmd_view(const std::string& args) {
    std::string target = Strings::lower(Strings::trim(args));
    if (target.empty()) {
        m_output_buffer << "Current focus: ";
        switch(m_focus) {
            case FOCUS_MEMORY: m_output_buffer << "Memory"; break;
            case FOCUS_REGS: m_output_buffer << "Registers"; break;
            case FOCUS_STACK: m_output_buffer << "Stack"; break;
            case FOCUS_CODE: m_output_buffer << "Code"; break;
            case FOCUS_WATCH: m_output_buffer << "Watch"; break;
            case FOCUS_BREAKPOINTS: m_output_buffer << "Breakpoints"; break;
            case FOCUS_CMD: m_output_buffer << "Command"; break;
            default: m_output_buffer << "Unknown"; break;
        }
        m_output_buffer << "\n";
        return;
    }

    if (target == "memory" || target == "m" || target == "mem") { m_focus = FOCUS_MEMORY; m_show_mem = true; }
    else if (target == "registers" || target == "regs" || target == "r") { m_focus = FOCUS_REGS; m_show_regs = true; }
    else if (target == "stack" || target == "s") { m_focus = FOCUS_STACK; m_show_stack = true; }
    else if (target == "code" || target == "c") { m_focus = FOCUS_CODE; m_show_code = true; }
    else if (target == "watch" || target == "w") { m_focus = FOCUS_WATCH; m_show_watch = true; }
    else if (target == "breakpoints" || target == "break" || target == "b") { m_focus = FOCUS_BREAKPOINTS; m_show_breakpoints = true; }
    else if (target == "command" || target == "cmd") { m_focus = FOCUS_CMD; }
    else {
        m_output_buffer << "Unknown view: " << target << "\n";
        return;
    }
    m_output_buffer << "Focus switched to " << target << "\n";
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

    // Obsługa usuwania zmiennych (@var lub @@var)
    if (name.length() > 0 && name[0] == '@') {
        std::string var_name = (name.length() > 1 && name[1] == '@') ? name.substr(2) : name.substr(1);
        auto& vars = m_debugger.get_core().get_context().getVariables();
        
        if (vars.remove(var_name)) {
            m_output_buffer << "Variable @" << var_name << " removed.\n";
        } else {
            const Variable* v = vars.find(var_name);
            if (v && v->isSystem()) {
                m_output_buffer << "Error: System variable @@" << var_name << " cannot be undefined.\n";
            } else {
                m_output_buffer << "Error: Variable @" << var_name << " not found.\n";
            }
        }
        return;
    }

    if (m_debugger.get_core().get_context().getSymbols().remove(name))
        m_output_buffer << "Symbol '" << name << "' removed.\n";
    else
        m_output_buffer << "Error: Symbol '" << name << "' not found.\n";
}

void Dashboard::update_theme() {
    if (m_show_colors) {
        m_theme = m_default_theme;
    } else {
        m_theme.header_focus = "";
        m_theme.header_blur = "";
        m_theme.separator = "";
        m_theme.address = "";
        m_theme.value = "";
        m_theme.value_dim = "";
        m_theme.highlight = "";
        m_theme.label = "";
        m_theme.mnemonic = "";
        m_theme.operand_num = "";
        m_theme.reg = "";
        m_theme.comment = "";
        m_theme.pc_fg = "";
        m_theme.pc_bg = "";
        m_theme.error = "";
        m_theme.hint_error = "";
        m_theme.bracket_match = "";
    }
    if (m_show_colors) {
        m_editor.set_highlight_color(m_default_theme.bracket_match);
        m_editor.set_error_color(m_default_theme.hint_error);
    } else {
        m_editor.set_highlight_color("");
        m_editor.set_error_color("");
    }
}

void Dashboard::cmd_options(const std::string& args) {
    std::string trimmed_args = Strings::trim(args);
    if (trimmed_args.empty()) {
        const auto& opts = m_debugger.get_options();
        m_output_buffer << "OPTIONS:\n";
        m_output_buffer << "------------------------------------------------------------\n";
        m_output_buffer << "colors:          " << (m_show_colors ? "on" : "off") << "\n";
        m_output_buffer << "autocompletion:  " << (m_show_autocompletion ? "on" : "off") << "\n";
        m_output_buffer << "bracketshighlight: " << (m_show_bracket_highlight ? "on" : "off") << "\n";
        m_output_buffer << "comments:        " << (m_wrap_comments ? "wrap" : "truncate") << "\n";
        m_output_buffer << "Input Files:     ";
        for (size_t i = 0; i < opts.inputFiles.size(); ++i) {
            if (i > 0) m_output_buffer << ", ";
            m_output_buffer << opts.inputFiles[i];
        }
        m_output_buffer << "\n";
    } else {
        std::stringstream ss(trimmed_args);
        std::string opt, val;
        ss >> opt >> val;
        opt = Strings::lower(opt);
        val = Strings::lower(val);

        if (opt == "colors") {
            if (val == "on") m_show_colors = true;
            else if (val == "off") m_show_colors = false;
            else { m_output_buffer << "Invalid value for colors (on/off)\n"; return; }
            update_theme();
            m_output_buffer << "Colors " << (m_show_colors ? "enabled" : "disabled") << "\n";
        } else if (opt == "autocompletion") {
            if (val == "on") m_show_autocompletion = true;
            else if (val == "off") m_show_autocompletion = false;
            else { m_output_buffer << "Invalid value for autocompletion (on/off)\n"; return; }
            m_output_buffer << "Autocompletion " << (m_show_autocompletion ? "enabled" : "disabled") << "\n";
        } else if (opt == "bracketshighlight") {
            if (val == "on") m_show_bracket_highlight = true;
            else if (val == "off") m_show_bracket_highlight = false;
            else { m_output_buffer << "Invalid value for bracketshighlight (on/off)\n"; return; }
            m_output_buffer << "Bracket highlight " << (m_show_bracket_highlight ? "enabled" : "disabled") << "\n";
        } else if (opt == "comments") {
            if (val == "wrap") { m_wrap_comments = true; m_code_view.set_wrap_comments(true); }
            else if (val == "truncate") { m_wrap_comments = false; m_code_view.set_wrap_comments(false); }
            else { m_output_buffer << "Invalid value for comments (wrap/truncate)\n"; return; }
            m_output_buffer << "Comments " << (m_wrap_comments ? "wrapping" : "truncation") << " enabled\n";
        } else {
            m_output_buffer << "Unknown option: " << opt << "\n";
        }
    }
}

void Dashboard::cmd_watch(const std::string& args) {
    std::string expr_str = Strings::trim(args);
    if (expr_str.empty()) {
        cmd_watch_list("");
        return;
    }
    try {
        Expression eval(m_debugger.get_core());
        eval.evaluate(expr_str); // Trial evaluation to validate syntax
        m_debugger.add_watch(expr_str);
        m_show_watch = true;
        m_output_buffer << "Watch added: " << expr_str << "\n";
    } catch (const std::exception& e) {
        m_output_buffer << "Error: Invalid expression: " << e.what() << "\n";
    }
}

void Dashboard::cmd_unwatch(const std::string& args) {
    int id = 0;
    if (Strings::parse_integer(args, id)) {
        if (id > 0 && id <= (int)m_debugger.get_watches().size()) {
            m_debugger.remove_watch(id - 1);
            m_output_buffer << "Watch #" << id << " removed.\n";
        } else {
            m_output_buffer << "Error: Invalid watch ID.\n";
        }
    } else {
        m_output_buffer << "Error: Invalid ID format.\n";
    }
}

void Dashboard::cmd_clear_watch(const std::string&) {
    m_debugger.clear_watches();
    m_output_buffer << "All watches cleared.\n";
}

void Dashboard::cmd_watch_list(const std::string&) {
    const auto& watches = m_debugger.get_watches();
    m_output_buffer << "WATCH LIST:\n";
    m_output_buffer << "------------------------------------------------------------\n";
    for (size_t i = 0; i < watches.size(); ++i) {
        m_output_buffer << "#" << (i + 1) << " " << watches[i];
        try {
            Expression eval(m_debugger.get_core());
            auto val = eval.evaluate(watches[i]);
            m_output_buffer << " = " << format(val, false);
        } catch (...) {
            m_output_buffer << " = Error";
        }
        m_output_buffer << "\n";
    }
    if (watches.empty()) m_output_buffer << "No watches.\n";
}

void Dashboard::cmd_break_list(const std::string&) {
    const auto& bps = m_debugger.get_breakpoints();
    m_output_buffer << "BREAKPOINT LIST:\n";
    m_output_buffer << "------------------------------------------------------------\n";
    for (size_t i = 0; i < bps.size(); ++i) {
        const auto& bp = bps[i];
        m_output_buffer << "#" << (i + 1) << " " << (bp.enabled ? "[*]" : "[ ]") << " $" << Strings::hex(bp.addr);
        auto sym = m_debugger.get_core().get_context().getSymbols().find_nearest(bp.addr);
        if (!sym.first.empty() && sym.second == bp.addr)
            m_output_buffer << " (" << sym.first << ")";
        m_output_buffer << "\n";
    }
    if (bps.empty()) m_output_buffer << "No breakpoints.\n";
}

void Dashboard::cmd_break(const std::string& args) {
    std::string clean_args = Strings::trim(args);
    if (clean_args.empty()) {
        cmd_break_list("");
        return;
    }

    auto parts = Strings::split_once(clean_args, " \t");
    std::string subcmd = Strings::lower(parts.first);
    std::string arg = Strings::trim(parts.second);

    if (subcmd == "list") {
        cmd_break_list("");
        return;
    }

    if (subcmd == "add") {
        if (arg.empty()) { m_output_buffer << "Error: Missing address for add.\n"; return; }
        try {
            Expression eval(m_debugger.get_core());
            auto val = eval.evaluate(arg);
            uint16_t addr = (uint16_t)val.get_scalar(m_debugger.get_core());
            if (m_debugger.has_breakpoint(addr)) {
                m_output_buffer << "Breakpoint already exists at $" << Strings::hex(addr) << "\n";
            } else {
                m_debugger.add_breakpoint(addr);
                m_show_breakpoints = true;
                m_output_buffer << "Breakpoint added at $" << Strings::hex(addr) << "\n";
            }
        } catch (const std::exception& e) {
            m_output_buffer << "Error: " << e.what() << "\n";
        }
        return;
    }

    // Helper lambda for delete/enable/disable logic
    auto handle_target = [&](const std::string& target, auto action_all, auto action_id, auto action_addr) {
        if (target == "all") {
            action_all();
        } else if (!target.empty() && target[0] == '#') {
            int id = 0;
            if (Strings::parse_integer(target.substr(1), id)) {
                if (id > 0 && id <= (int)m_debugger.get_breakpoints().size()) {
                    action_id(id - 1);
                } else {
                    m_output_buffer << "Error: Invalid breakpoint ID #" << id << "\n";
                }
            } else {
                m_output_buffer << "Error: Invalid ID format.\n";
            }
        } else {
            try {
                Expression eval(m_debugger.get_core());
                auto val = eval.evaluate(target);
                uint16_t addr = (uint16_t)val.get_scalar(m_debugger.get_core());
                action_addr(addr);
            } catch (const std::exception& e) {
                m_output_buffer << "Error: " << e.what() << "\n";
            }
        }
    };

    if (subcmd == "delete") {
        if (arg.empty()) { m_output_buffer << "Error: Missing argument for delete (all, #ID, expr).\n"; return; }
        handle_target(arg,
            [this](){ m_debugger.clear_breakpoints(); m_output_buffer << "All breakpoints deleted.\n"; },
            [this](size_t idx){ m_debugger.remove_breakpoint_by_index(idx); m_output_buffer << "Breakpoint #" << (idx+1) << " deleted.\n"; },
            [this](uint16_t addr){ m_debugger.remove_breakpoint(addr); m_output_buffer << "Breakpoint at $" << Strings::hex(addr) << " deleted.\n"; }
        );
    } else if (subcmd == "enable") {
        if (arg.empty()) { m_output_buffer << "Error: Missing argument for enable (all, #ID, expr).\n"; return; }
        handle_target(arg,
            [this](){ m_debugger.enable_all_breakpoints(); m_output_buffer << "All breakpoints enabled.\n"; },
            [this](size_t idx){ m_debugger.enable_breakpoint(idx); m_output_buffer << "Breakpoint #" << (idx+1) << " enabled.\n"; },
            [this](uint16_t addr){ m_debugger.enable_breakpoint(addr); m_output_buffer << "Breakpoint at $" << Strings::hex(addr) << " enabled.\n"; }
        );
    } else if (subcmd == "disable") {
        if (arg.empty()) { m_output_buffer << "Error: Missing argument for disable (all, #ID, expr).\n"; return; }
        handle_target(arg,
            [this](){ m_debugger.disable_all_breakpoints(); m_output_buffer << "All breakpoints disabled.\n"; },
            [this](size_t idx){ m_debugger.disable_breakpoint(idx); m_output_buffer << "Breakpoint #" << (idx+1) << " disabled.\n"; },
            [this](uint16_t addr){ m_debugger.disable_breakpoint(addr); m_output_buffer << "Breakpoint at $" << Strings::hex(addr) << " disabled.\n"; }
        );
    } else {
        m_output_buffer << "Unknown subcommand: " << subcmd << ". Use add, delete, enable, disable, list.\n";
    }
}

void Dashboard::cmd_break_smart(const std::string& args) {
    if (args.empty()) {
        m_output_buffer << "Error: Missing expression for toggle.\n";
        return;
    }
    try {
        Expression eval(m_debugger.get_core());
        auto val = eval.evaluate(args);
        uint16_t addr = (uint16_t)val.get_scalar(m_debugger.get_core());
        
        if (m_debugger.has_breakpoint(addr)) {
            m_debugger.remove_breakpoint(addr);
            m_output_buffer << "Breakpoint removed at $" << Strings::hex(addr) << "\n";
        } else {
            m_debugger.add_breakpoint(addr);
            m_show_breakpoints = true;
            m_output_buffer << "Breakpoint set at $" << Strings::hex(addr) << "\n";
        }
    } catch (const std::exception& e) {
        m_output_buffer << "Error: " << e.what() << "\n";
    }
}

template <typename T>
std::string Dashboard::format_instruction(const T& line) {
    std::stringstream ss;
    ss << m_theme.mnemonic << line.mnemonic << Terminal::RESET;
    if (!line.operands.empty()) {
        ss << " ";
        using Operand = typename T::Operand;
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
    return ss.str();
}

void Dashboard::cmd_trace(const std::string& args) {
    std::string a = Strings::trim(args);
    auto parts = Strings::split_once(a, " ");
    std::string sub = Strings::lower(parts.first);
    
    if (sub == "on") {
        g_trace_module.set_recording(true);
        m_output_buffer << "Trace recording ON.\n";
    } else if (sub == "off") {
        g_trace_module.set_recording(false);
        m_output_buffer << "Trace recording OFF.\n";
    } else if (sub == "clear") {
        g_trace_module.clear();
        m_output_buffer << "Trace buffer cleared.\n";
    } else if (sub == "list") {
        int count = 10;
        if (!parts.second.empty()) Strings::parse_integer(parts.second, count);
        auto history = g_trace_module.get_history(count);
        
        m_output_buffer << "[TRACE] Status: " << (g_trace_module.is_recording() ? "ON" : "OFF") 
                        << " | Buffer: " << g_trace_module.get_count() << "/" << g_trace_module.get_capacity() << "\n";
        
        int idx = -(int)history.size();
        for (const auto& entry : history) {
            std::stringstream ss;
            ss << " " << std::setw(3) << idx << "  " << m_theme.address << Strings::hex(entry.pc) << Terminal::RESET << ": ";
            
            std::stringstream hex_ss;
            for(int i=0; i<entry.len; ++i) hex_ss << Strings::hex(entry.opcodes[i]) << " ";
            ss << m_theme.value_dim << std::left << std::setw(12) << hex_ss.str() << Terminal::RESET;
            
            // Disassemble from trace entry bytes
            TraceMemoryAdapter mem_adapter{entry.pc, entry.opcodes, entry.len};
            Z80Analyzer<TraceMemoryAdapter> analyzer(&mem_adapter);
            auto line = analyzer.parse_instruction(entry.pc);
            
            ss << format_instruction(line);
            
            m_output_buffer << ss.str() << "\n";
            idx++;
        }
    } else {
        m_output_buffer << "Usage: trace on|off|clear|list [N]\n";
    }
}

void Dashboard::cmd_codemap(const std::string& args) {
    std::vector<std::string> tokens;
    std::stringstream ss(args);
    std::string item;
    while (ss >> item) tokens.push_back(item);
    auto& core = m_debugger.get_core();

    if (tokens.empty()) {
        m_output_buffer << "MEMORY MAP (Satellite View, 64KB)\n";
        m_output_buffer << "Legend: [C]ode, [D]ata, [.]Empty/Unknown, [x]Mixed\n\n";
        for (int row = 0; row < 8; ++row) {
            uint16_t base = row * 0x2000;
            std::string line_str = Strings::hex(base) + ": ";
            for (int col = 0; col < 32; ++col) {
                if (col > 0 && col % 8 == 0) line_str += " ";
                int code_w = 0;
                uint16_t chunk_start = base + col * 256;
                for (int i = 0; i < 256; i += 16) {
                    auto l = core.get_analyzer().parse_instruction(chunk_start + i);
                    if (!l.mnemonic.empty()) code_w++;
                }
                if (code_w > 12) line_str += 'C';
                else if (code_w > 4) line_str += 'x';
                else line_str += '.';
            }
            m_output_buffer << line_str << "\n";
        }
        m_output_buffer << "\nCoverage: Estimated based on static analysis.\n";
        return;
    }

    Expression expr(core);
    uint16_t start = 0, end = 0;
    try {
        uint16_t center = (uint16_t)expr.evaluate(args).get_scalar(core);
        start = center - 64;
        end = center + 64;
        m_output_buffer << "Focus: " << Strings::hex(center) << " (Range: " << Strings::hex(start) << " - " << Strings::hex(end) << ")\n";
    } catch (...) {
        bool found = false;
        auto comma = args.find(',');
        if (comma != std::string::npos) {
            try {
                start = (uint16_t)expr.evaluate(args.substr(0, comma)).get_scalar(core);
                end = (uint16_t)expr.evaluate(args.substr(comma + 1)).get_scalar(core);
                found = true;
            } catch(...) {}
        } 
        if (!found) {
            std::vector<std::string> parts = Strings::split(args, ' ');
            for (size_t i = 1; i < parts.size(); ++i) {
                std::string left, right;
                for(size_t j=0; j<i; ++j) left += (j>0?" ":"") + parts[j];
                for(size_t j=i; j<parts.size(); ++j) right += (j>i?" ":"") + parts[j];
                try {
                    start = (uint16_t)expr.evaluate(left).get_scalar(core);
                    end = (uint16_t)expr.evaluate(right).get_scalar(core);
                    found = true;
                    break;
                } catch(...) {}
            }
        }
        if (found) m_output_buffer << "Range: " << Strings::hex(start) << " - " << Strings::hex(end) << "\n";
        else { m_output_buffer << "Error: Invalid address or range expression.\n"; return; }
    }

    m_output_buffer << "\nADDR RANGE      TYPE           FLAGS\n";
    m_output_buffer << "------------------------------------------\n";
    uint16_t pc = start;
    while (pc <= end) {
        auto line = core.get_analyzer().parse_instruction(pc);
        bool is_code = !line.mnemonic.empty();
        std::string type = is_code ? "CODE" : "DATA";
        uint16_t block_start = pc;
        uint16_t block_end = pc;
        while (block_end < end) {
            uint16_t next_pc = block_end + (uint16_t)(is_code ? line.bytes.size() : 1);
            if (next_pc > end || next_pc < block_end) break;
            auto next_line = core.get_analyzer().parse_instruction(next_pc);
            if ((!next_line.mnemonic.empty()) != is_code) break;
            block_end = next_pc;
            line = next_line;
            if (block_end == end) break;
        }
        uint16_t last_byte = block_end + (uint16_t)(is_code ? line.bytes.size() : 1) - 1;
        std::string range = Strings::hex(block_start) + " - " + Strings::hex(last_byte);
        while (range.length() < 15) range += " ";
        m_output_buffer << range << type << "           " << (is_code ? "[Exec]" : "[Read]") << "\n";
        pc = last_byte + 1;
        if (pc <= block_end) break;
    }
}

void Dashboard::cmd_over(const std::string&) {
    m_debugger.over();
    m_auto_follow = true;
    update_code_view();
    update_stack_view();
}

void Dashboard::cmd_skip(const std::string&) {
    m_debugger.skip();
    m_auto_follow = true;
    update_code_view();
}

void Dashboard::handle_command(const std::string& input) {
    std::string sanitized_input;
    for (size_t i = 0; i < input.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 128) {
            sanitized_input += (char)c;
        } else if (i + 2 < input.length()) {
            unsigned char c2 = static_cast<unsigned char>(input[i+1]);
            unsigned char c3 = static_cast<unsigned char>(input[i+2]);
            if (c == 0xE2 && c2 == 0x80) {
                if (c3 == 0x9C || c3 == 0x9D) { // “ ”
                    sanitized_input += '"';
                    i += 2;
                } else if (c3 == 0x98 || c3 == 0x99) { // ‘ ’
                    sanitized_input += '\'';
                    i += 2;
                } else sanitized_input += input[i];
            } else sanitized_input += input[i];
        } else sanitized_input += input[i];
    }
    std::string clean_input = Strings::trim(sanitized_input);
    if (clean_input.empty())
        return;

    const CommandRegistry::CommandEntry* best_entry = nullptr;
    const auto& cmds = m_command_registry.get_commands();
    std::string best_cmd;
    for (const auto& pair : cmds) {
        const std::string& cmd_key = pair.first;
        const auto& entry = pair.second;
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
        best_entry->handler(args);
    } else {
        auto parts = Strings::split_once(clean_input, " \t");
        m_output_buffer << "Unknown command: " << parts.first << "\n";
    }
}

void Dashboard::init() {
    // replxx init removed
    auto& vars = m_debugger.get_core().get_context().getVariables();
    
    vars.add(Variable("mem", [this]() {
        return Expression::Value((double)m_memory_view.get_address());
    }, "Memory View Cursor"));

    vars.add(Variable("code", [this]() {
        return Expression::Value((double)m_code_view.get_cursor());
    }, "Code View Cursor"));

    vars.add(Variable("ret", [this]() {
        auto& core = m_debugger.get_core();
        uint16_t sp = core.get_cpu().get_SP();
        uint16_t ret = core.get_memory().peek(sp) | (core.get_memory().peek((sp + 1) & 0xFFFF) << 8);
        return Expression::Value((double)ret);
    }, "Return address (from stack)"));

    m_debugger.set_interrupt_callback([](){
        Terminal::Input in = Terminal::read_key();
        return in.key == Terminal::Key::ESC;
    });

    m_command_registry.add({"trace", "tr"}, {
        [this](const std::string& args){ cmd_trace(args); },
        true,
        "on|off|clear|list",
        "Flight Recorder (Trace)",
        {CommandRegistry::CTX_SUBCOMMAND}
    });

    m_command_registry.add({"codemap", "cm"}, {
        [this](const std::string& args){ cmd_codemap(args); },
        false, "", "Show memory map or block details", {CommandRegistry::CTX_EXPRESSION}
    });


    m_command_registry.add({"over", "ov"}, {
        [this](const std::string& args){ cmd_over(args); },
        false, "", "Step over (run until next address)", {}
    });

    m_command_registry.add({"skip", "sk"}, {
        [this](const std::string& args){ cmd_skip(args); },
        false, "", "Skip instruction (advance PC without executing)", {}
    });

    m_command_registry.add({"next", "n"}, {
        [this](const std::string& args){ cmd_next(args); },
        false, "", "Step over instruction", {}
    });

    m_command_registry.add({"step", "s"}, {
        [this](const std::string& args){ cmd_step(args); },
        false, "", "Step into instruction", {CommandRegistry::CTX_EXPRESSION}
    });

    m_command_registry.add({"quit", "q"}, {
        [this](const std::string& args){ cmd_quit(args); },
        false, "", "Quit debugger", {}
    });

    m_command_registry.add({"help", "h"}, {
        [this](const std::string& args){ cmd_help(args); },
        false, "", "Show help", {CommandRegistry::CTX_SUBCOMMAND}
    });
}

Dashboard::~Dashboard() {
    auto& vars = m_debugger.get_core().get_context().getVariables();
    vars.removeSystem("mem");
    vars.removeSystem("code");
    vars.removeSystem("ret");
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
        m_register_view.set_state(m_debugger.get_prev_state());
        auto regs_lines = m_register_view.render();
        left_lines.insert(left_lines.end(), regs_lines.begin(), regs_lines.end());
    }
    if (m_show_stack) {
        m_stack_view.set_focus(m_focus == FOCUS_STACK);
        m_stack_view.set_prev_sp(m_debugger.get_prev_state().m_SP.w);
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
        m_code_view.set_state(highlight_pc, width, m_debugger.get_last_pc(), m_debugger.has_history(), m_debugger.pc_moved(), m_debugger.get_tstates(), m_debugger.get_prev_state().m_ticks);
        auto code_lines = m_code_view.render();
        for (const auto& l : code_lines)
            std::cout << l << "\n";
    }
    
    if (m_show_watch || m_show_breakpoints) {
        print_separator();
        std::vector<std::string> left, right;
        if (m_show_watch) left = m_watch_view.render();
        if (m_show_breakpoints) right = m_breakpoint_view.render();
        print_columns(left, right, 38);
    }
    bool is_smc = false;
    auto line = core.get_analyzer().parse_instruction(pc);
    for (size_t i = 0; i < line.bytes.size(); ++i) {
        if (core.get_code_map()[(uint16_t)(pc + i)] & CodeMap::FLAG_DATA_WRITE) {
            is_smc = true;
            break;
        }
    }
    if (is_smc) {
         std::stringstream ss;
         ss << m_theme.error << "[STATUS] SMC Detected at $" << Strings::hex(pc) << "!";
         log(ss.str());
    }
    bool has_output = (m_output_buffer.tellp() > 0);
    print_output_buffer();
    if (has_output || (!m_show_watch && !m_show_breakpoints))
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
    center_code_view(m_debugger.get_core().get_cpu().get_PC());
}

void Dashboard::center_code_view(uint16_t pc) {
    auto& core = m_debugger.get_core();
    int target_row = std::max(3, m_code_view.get_rows() / 3);

    // Calculate lines occupied by PC instruction's metadata (which appear above it)
    int pc_meta_lines = m_code_view.get_meta_height(pc);
    
    // We want the instruction line itself to be at target_row.
    // The lines above the instruction line are:
    // 1. Metadata lines of the PC instruction itself.
    // 2. Lines from previous instructions.
    
    int accumulated_lines_above = pc_meta_lines;
    uint16_t scan_pc = pc;
    int skip = 0;

    if (accumulated_lines_above >= target_row) {
        // PC metadata alone fills the space above
        scan_pc = pc;
        skip = accumulated_lines_above - target_row;
    } else {
        int steps = 0;
        while (steps < 100) {
            uint16_t prev = core.get_analyzer().parse_instruction_backwards(scan_pc, &core.get_code_map());
            if (prev == scan_pc) prev = scan_pc - 1;

            bool is_code = (core.get_code_map()[prev] & CodeMap::FLAG_CODE_START);
            int lines_added = 0;
            int meta = m_code_view.get_meta_height(prev);

            if (is_code || meta > 0) {
                lines_added = 1 + meta;
            } else {
                lines_added = 1;
            }
            
            if (accumulated_lines_above + lines_added > target_row) {
                scan_pc = prev;
                skip = (accumulated_lines_above + lines_added) - target_row;
                break;
            }
            accumulated_lines_above += lines_added;
            scan_pc = prev;
            if (accumulated_lines_above == target_row) {
                skip = 0;
                break;
            }
            steps++;
        }
    }
    m_code_view.set_address(scan_pc);
    m_code_view.set_skip_lines(skip);
    m_code_view.set_cursor(pc);
}

void Dashboard::update_stack_view() {
    if (!m_auto_follow)
        return;
    m_stack_view.set_address(m_debugger.get_core().get_cpu().get_SP());
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
            std::cout << m_theme.separator << " |" << Terminal::RESET;
            if (row < right.size())
                std::cout << right[row];
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
            if (!parts.empty())
                ep = parts[0];
            
            int32_t val = 0;
            if (Strings::parse_integer(ep, val))
                m_core.get_cpu().set_PC((uint16_t)val);
            else
                throw std::runtime_error("Invalid address format");
        } catch (const std::exception& e) {
            std::cerr << "Error parsing entry point: " << e.what() << "\n";
        }
    }
    Debugger debugger(m_core, m_options);
    Dashboard dashboard(debugger);
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
        lss << format_instruction(line);
    }
    return lss.str();
}

void Dashboard::format_variable_header(std::stringstream& ss, const Expression::Value& val, const std::string& expr) {
    if (!expr.empty() && expr[0] == '@') {
        bool is_var = Commands::is_identifier(expr.substr(1));
        if (is_var) {
            ss << "VARIABLE: " << expr << "\n";
            std::string type_name = "Unknown";
            if (val.is_address()) type_name = "Address (Pointer)";
            else if (val.is_number()) type_name = "Number";
            else if (val.is_bytes()) type_name = "Bytes (Array)";
            else if (val.is_words()) type_name = "Words (Array)";
            else if (val.is_string()) type_name = "String";
            else if (val.is_register()) type_name = "Register";
            ss << "Type:     " << type_name << "\n";
            ss << "------------------------------------------------------------\n";
        }
    }
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
    
    ss << "VALUE: $" << Strings::hex((uint64_t)i_val, width) << " (" << std::dec << i_val << ") | Number (" << width << "-bit)\n";
    ss << "------------------------------------------------------------\n";
    ss << "Signed:  " << (i_val >= 0 ? "+" : "") << i_val << "\n";

    if (width == 64) {
        ss << "Binary:  Hi: %" << Strings::bin((uint64_t)i_val >> 32, 32) << "\n";
        ss << "         Lo: %" << Strings::bin((uint64_t)i_val & 0xFFFFFFFF, 32);
    } else {
        ss << "Binary:  %" << Strings::bin((uint64_t)i_val, width);
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

std::string Dashboard::format(const Expression::Value& val, bool detailed, const std::string& expr) {
    std::stringstream ss;
    if (detailed) {
        format_variable_header(ss, val, expr);
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
                if (len > 30)
                    display_s = s.substr(0, 27) + "...";
                ss << "STRING:   \"" << display_s << "\" (" << len << " chars)\n";
                ss << "------------------------------------------------------------\n";
                ss << "Bytes:    ";
                size_t limit = std::min(len, (size_t)16);
                for (size_t i = 0; i < limit; ++i) {
                    if (i > 0)
                        ss << ",";
                    ss << "$" << Strings::hex((uint8_t)s[i]);
                }
                if (len > limit)
                    ss << "... (+" << (len - limit) << " more)";
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
        if (!res.empty() && res.back() == '\n')
            res.pop_back();
        return res;
    } else {
        switch (val.type()) {
            case Expression::Value::Type::Number: {
                double d = val.number();
                if (d == (int64_t)d) {
                    int64_t i = (int64_t)d;
                    if (i >= -128 && i <= 255)
                        ss << "$" << Strings::hex((uint8_t)i) << " (" << i << ")";
                    else if (i >= -32768 && i <= 65535)
                        ss << "$" << Strings::hex((uint16_t)i) << " (" << i << ")";
                    else {
                        std::stringstream temp_ss;
                        temp_ss << std::hex << std::uppercase << i;
                        ss << "$" << temp_ss.str() << " (" << i << ")";
                    }
                } else
                    ss << d;
                break;
            }
            case Expression::Value::Type::String: {
                std::string s = val.string();
                if (s.length() > 50)
                    s = s.substr(0, 47) + "...";
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

CommandRegistry::CompletionType CommandRegistry::resolve_type(const std::string& cmd, int param_index, const std::string& args_part) const {
    if (cmd == "help") {
        if (param_index == 0) return CTX_SUBCOMMAND;
        
        size_t start = 0;
        while (start < args_part.length() && std::isspace(args_part[start])) start++;
        size_t end = start;
        while (end < args_part.length() && !std::isspace(args_part[end])) end++;
        
        if (start < args_part.length()) {
            std::string target_cmd = args_part.substr(start, end - start);
            std::string remaining_args = (end < args_part.length()) ? args_part.substr(end) : "";
            return resolve_type(target_cmd, param_index - 1, remaining_args);
        }
        return CTX_NONE;
    }

    if (m_commands.find(cmd) == m_commands.end()) return CTX_NONE;
    const auto& entry = m_commands.at(cmd);

    const std::vector<CompletionType>* current_types = &entry.param_types;
    const std::map<std::string, SubcommandEntry>* current_subcommands = &entry.subcommands;

    int current_arg_idx = 0;
    size_t pos = 0;

    while (current_arg_idx <= param_index) {
        CompletionType type = CTX_NONE;
        if (current_arg_idx < (int)current_types->size()) {
            type = (*current_types)[current_arg_idx];
        } else if (!current_types->empty() && current_types->back() == CTX_EXPRESSION) {
            type = CTX_EXPRESSION;
        }

        if (current_arg_idx == param_index) {
            return type;
        }

        size_t start = pos;
        while (start < args_part.length() && std::isspace(args_part[start])) start++;
        if (start >= args_part.length()) break;

        size_t end = start;
        while (end < args_part.length() && !std::isspace(args_part[end])) end++;
        
        std::string arg_val = args_part.substr(start, end - start);
        pos = end;

        if (type == CTX_SUBCOMMAND) {
            auto it = current_subcommands->find(arg_val);
            if (it != current_subcommands->end()) {
                current_types = &it->second.param_types;
                current_subcommands = &it->second.subcommands;
                param_index -= (current_arg_idx + 1);
                current_arg_idx = -1;
            }
        }
        current_arg_idx++;
    }
    return CTX_NONE;
}

std::vector<std::string> CommandRegistry::get_subcommand_candidates(const std::string& cmd, int param_index, const std::string& args_part) const {
    if (cmd == "help") {
        if (param_index == 0) {
            std::vector<std::string> candidates;
            for (const auto& pair : m_commands) {
                if (!pair.second.is_alias) candidates.push_back(pair.first);
            }
            return candidates;
        }
        size_t start = 0;
        while (start < args_part.length() && std::isspace(args_part[start])) start++;
        size_t end = start;
        while (end < args_part.length() && !std::isspace(args_part[end])) end++;
        
        if (start < args_part.length()) {
            std::string target_cmd = args_part.substr(start, end - start);
            std::string remaining_args = (end < args_part.length()) ? args_part.substr(end) : "";
            return get_subcommand_candidates(target_cmd, param_index - 1, remaining_args);
        }
        return {};
    }

    if (m_commands.find(cmd) == m_commands.end()) return {};
    const auto& entry = m_commands.at(cmd);

    const std::vector<CompletionType>* current_types = &entry.param_types;
    const std::map<std::string, SubcommandEntry>* current_subcommands = &entry.subcommands;

    int current_arg_idx = 0;
    size_t pos = 0;

    while (current_arg_idx <= param_index) {
        CompletionType type = CTX_NONE;
        if (current_arg_idx < (int)current_types->size()) type = (*current_types)[current_arg_idx];

        if (current_arg_idx == param_index) {
            if (type == CTX_SUBCOMMAND) {
                std::vector<std::string> candidates;
                for (const auto& pair : *current_subcommands) candidates.push_back(pair.first);
                return candidates;
            }
            return {};
        }

        size_t start = pos;
        while (start < args_part.length() && std::isspace(args_part[start])) start++;
        if (start >= args_part.length()) break;
        size_t end = start;
        while (end < args_part.length() && !std::isspace(args_part[end])) end++;
        std::string arg_val = args_part.substr(start, end - start);
        pos = end;

        if (type == CTX_SUBCOMMAND) {
            auto it = current_subcommands->find(arg_val);
            if (it != current_subcommands->end()) {
                current_types = &it->second.param_types;
                current_subcommands = &it->second.subcommands;
                param_index -= (current_arg_idx + 1);
                current_arg_idx = -1;
            }
        }
        current_arg_idx++;
    }
    return {};
}
