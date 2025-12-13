#include "DebugEngine.h"
#include <replxx.hxx>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <map>
#include <vector>
#include <cctype>
#include <set>
#include <algorithm>
#include <deque>
#include <regex>
#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/ioctl.h>
    #include <unistd.h>
#endif
#include "../Utils/Strings.h"
#include "../Utils/Terminal.h"

DebugEngine::DebugEngine(VirtualMachine& vm, const Options& options) : m_vm(vm), m_options(options) {
}
class MemoryView {
public:
    MemoryView(VirtualMachine& vm, uint16_t start_addr, int rows, bool has_focus)  : m_vm(vm), m_start_addr(start_addr), m_rows(rows), m_has_focus(has_focus) {
    }
    std::vector<std::string> render() {
        std::vector<std::string> lines;
        std::string sep = Terminal::GRAY + std::string(80, '-') + Terminal::RESET;
        lines.push_back(sep);

        std::stringstream header;
        if (m_has_focus) header << Terminal::YELLOW << "[MEMORY] " << Terminal::RESET;
        else header << Terminal::GREEN << "[MEMORY] " << Terminal::RESET;
        header << Terminal::CYAN << " View: " << Terminal::HI_WHITE << Strings::hex16(m_start_addr) << Terminal::RESET;
        lines.push_back(header.str());
        
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
private:
    VirtualMachine& m_vm;
    uint16_t m_start_addr;
    int m_rows;
    bool m_has_focus;
};
class RegisterView {
public:
    RegisterView(VirtualMachine& vm, const Z80<Memory>::State& prev, bool has_focus, uint64_t tstates) 
        : m_vm(vm), m_prev(prev), m_has_focus(has_focus), m_tstates(tstates) {
    }
    std::vector<std::string> render() {
        std::vector<std::string> lines;
        std::stringstream header;
        if (m_has_focus) header << Terminal::YELLOW << "[REGS]" << Terminal::RESET;
        else header << Terminal::GREEN << "[REGS]" << Terminal::RESET;
        header << Terminal::CYAN << " T: " << Terminal::RESET << Terminal::HI_WHITE << m_tstates << Terminal::RESET 
               << Terminal::GRAY << " (+" << 4 << ")" << Terminal::RESET;
        lines.push_back(header.str());

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
private:
    std::string format_flags(uint8_t f, uint8_t prev_f) {
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
    VirtualMachine& m_vm;
    const Z80<Memory>::State& m_prev;
    bool m_has_focus;
    uint64_t m_tstates;
};
class StackView {
public:
    StackView(VirtualMachine& vm, uint16_t view_addr, bool has_focus) : m_vm(vm), m_view_addr(view_addr), m_has_focus(has_focus) {
    }
    std::vector<std::string> render() {
        std::vector<std::string> lines;
        std::stringstream header;
        if (m_has_focus) header << Terminal::YELLOW << "[STACK]" << Terminal::RESET;
        else header << Terminal::GREEN << "[STACK]" << Terminal::RESET;
        header << Terminal::CYAN << " (SP=" << Terminal::HI_WHITE << Strings::hex16(m_vm.get_cpu().get_SP()) << Terminal::CYAN << ")" << Terminal::RESET;
        lines.push_back(header.str());

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
private:
    VirtualMachine& m_vm;
    uint16_t m_view_addr;
    bool m_has_focus;
};
class CodeView {
public:
    CodeView(VirtualMachine& vm, uint16_t start_addr, int rows, uint16_t pc, int width, bool has_focus, const std::deque<uint16_t>& history) 
        : m_vm(vm), m_start_addr(start_addr), m_rows(rows), m_pc(pc), m_width(width), m_has_focus(has_focus), m_history(history) {
    }
    std::vector<std::string> render() {
        std::vector<std::string> lines_out;
        
        std::stringstream header;
        if (m_has_focus) header << Terminal::YELLOW << "[CODE]" << Terminal::RESET;
        else header << Terminal::GREEN << "[CODE]" << Terminal::RESET;
        lines_out.push_back(header.str());

        if (!m_history.empty() && m_start_addr == m_pc) {
            uint16_t hist_addr = m_history.back();
            auto hist_lines = m_vm.get_analyzer().parse_code(hist_addr, 1);
            if (!hist_lines.empty()) {
                const auto& line = hist_lines[0];
                std::stringstream ss;
                ss << "  " << Terminal::GRAY << Strings::hex16((uint16_t)line.address) << ": ";
                
                for(size_t i=0; i<std::min((size_t)4, line.bytes.size()); ++i) {
                    ss << Strings::hex8(line.bytes[i]) << " ";
                }
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
private:
    VirtualMachine& m_vm;
    uint16_t m_start_addr;
    int m_rows;
    uint16_t m_pc;
    int m_width;
    bool m_has_focus;
    const std::deque<uint16_t>& m_history;
};
class DebugSession {
        VirtualMachine& vm;
        replxx::Replxx& repl;
        std::string last_command;
        bool running = true;
        std::stringstream m_output_buffer;
        enum Focus { FOCUS_MEMORY, FOCUS_REGS, FOCUS_STACK, FOCUS_CODE, FOCUS_WATCH, FOCUS_BREAKPOINTS };
        Focus m_focus = FOCUS_MEMORY;
        int m_code_rows = 15;
        int m_stack_rows = 4;
        int m_mem_rows = 4;
        uint16_t m_mem_view_addr = 0;
        uint16_t m_code_view_addr = 0;
        uint16_t m_stack_view_addr = 0;
        bool m_show_mem = true;
        bool m_show_regs = true;
        bool m_show_code = true;
        bool m_show_stack = true;
        bool m_show_watch = true;
        bool m_show_breakpoints = true;
        std::map<std::string, std::string> m_colors;
        
        struct Breakpoint { uint16_t addr; bool enabled; };
        std::vector<Breakpoint> m_breakpoints;
        std::vector<uint16_t> m_watches;
        std::deque<uint16_t> m_history;
        uint64_t m_tstates = 0;
        
        Z80<Memory>::State m_prev_regs;

        template<typename T>
        void log(const T& msg) {
            m_output_buffer << msg;
        }
        
        void log_line(const std::string& msg) {
            m_output_buffer << msg << "\n";
        }

        void setup_replxx() {
            repl.install_window_change_handler();
            
            // 1. Completion
            repl.set_completion_callback([this](std::string const& context, int& contextLen) {
                std::vector<replxx::Replxx::Completion> completions;
                std::vector<std::string> cmds = {
                    "step", "next", "finish", "continue", "break", "watch", "delete", "unwatch",
                    "help", "quit", "lines", "toggle"
                };
                
                size_t lastSpace = context.find_last_of(" ");
                if (lastSpace == std::string::npos) {
                    std::string prefix = context;
                    contextLen = prefix.length();
                    for (auto const& c : cmds) {
                        if (c.find(prefix) == 0) completions.push_back(c);
                    }
                } else {
                    std::string cmd = context.substr(0, context.find(' '));
                    std::string prefix = context.substr(lastSpace + 1);
                    contextLen = prefix.length();
                    
                    if (cmd == "toggle") {
                        std::vector<std::string> args = {"mem", "regs", "code", "stack", "watch", "breakpoints"};
                        for (const auto& a : args) if (a.find(prefix) == 0) completions.push_back(a);
                    } else if (cmd == "lines") {
                        std::vector<std::string> args = {"code", "mem", "stack"};
                        for (const auto& a : args) if (a.find(prefix) == 0) completions.push_back(a);
                    }
                }
                return completions;
            });

            // 2. Hints
            repl.set_hint_callback([this](std::string const& input, int& contextLen, replxx::Replxx::Color& color) {
                if (input.empty()) return std::vector<std::string>();
                
                std::stringstream ss(input);
                std::string cmd;
                ss >> cmd;
                
                if (cmd == "lines") return std::vector<std::string>{" <code|mem|stack> <n>"};
                if (cmd == "toggle") return std::vector<std::string>{" <mem|regs|code|stack|watch|breakpoints>"};
                if (cmd == "break" || cmd == "b") return std::vector<std::string>{" <addr>"};
                if (cmd == "watch" || cmd == "w") return std::vector<std::string>{" <addr>"};
                return std::vector<std::string>();
            });

            // 3. Highlighter
            repl.set_highlighter_callback([this](std::string const& input, std::vector<replxx::Replxx::Color>& colors) {
                size_t firstSpace = input.find(' ');
                for (size_t i = 0; i < input.length(); ++i) {
                    if (i < firstSpace || firstSpace == std::string::npos) {
                        colors.push_back(replxx::Replxx::Color::GREEN);
                    } else if (isdigit(input[i])) {
                        colors.push_back(replxx::Replxx::Color::CYAN);
                    } else {
                        colors.push_back(replxx::Replxx::Color::DEFAULT);
                    }
                }
            });

            // 4. Key bindings
            auto bind_scroll = [&](char32_t key, int mem_delta, int code_delta, int stack_delta) {
                repl.bind_key(key, [this, mem_delta, code_delta, stack_delta](char32_t code) {
                    if (m_focus == FOCUS_MEMORY) m_mem_view_addr += mem_delta;
                    else if (m_focus == FOCUS_CODE) m_code_view_addr += code_delta;
                    else if (m_focus == FOCUS_STACK) m_stack_view_addr += stack_delta;
                    print_dashboard();
                    repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
                    return replxx::Replxx::ACTION_RESULT::CONTINUE;
                });
            };

            bind_scroll(replxx::Replxx::KEY::UP, -16, -1, -2);
            bind_scroll(replxx::Replxx::KEY::DOWN, 16, 1, 2);

            auto tab_handler = [this](char32_t code) {
                int attempts = 0;
                do {
                    m_focus = (Focus)((m_focus + 1) % 6);
                    attempts++;
                } while (attempts < 6 && (
                    (m_focus == FOCUS_MEMORY && !m_show_mem) ||
                    (m_focus == FOCUS_REGS && !m_show_regs) ||
                    (m_focus == FOCUS_STACK && !m_show_stack) ||
                    (m_focus == FOCUS_CODE && !m_show_code) ||
                    (m_focus == FOCUS_WATCH && !m_show_watch) ||
                    (m_focus == FOCUS_BREAKPOINTS && !m_show_breakpoints)
                ));
                print_dashboard();
                repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
                return replxx::Replxx::ACTION_RESULT::CONTINUE;
            };
            
            repl.bind_key(replxx::Replxx::KEY::TAB, tab_handler);
            repl.bind_key(9, tab_handler);
        }

        void print_help() {
            m_output_buffer << "\nAvailable Commands:\n";
            m_output_buffer << " [EXECUTION]\n";
            m_output_buffer << "   s, step [n]            Execute instructions (default 1)\n";
            m_output_buffer << "   n, next                Step over subroutine\n";
            m_output_buffer << "   f, finish              Step out of subroutine\n";
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

        bool check_breakpoints(uint16_t pc) {
            for (const auto& bp : m_breakpoints) {
                if (bp.enabled && bp.addr == pc) return true;
            }
            return false;
        }

        void print_separator() {
            std::cout << Terminal::GRAY << std::string(80, '-') << Terminal::RESET << "\n";
        }

        void print_dashboard() {
            Terminal::clear();
            auto& cpu = vm.get_cpu();
            uint16_t pc = cpu.get_PC();

            const int terminal_width = 80;

            // [MEMORY]
            if (m_show_mem) {
                MemoryView view(vm, m_mem_view_addr, m_mem_rows, m_focus == FOCUS_MEMORY);
                auto lines = view.render();
                for(const auto& line : lines) std::cout << line << "\n";
            }

            // Reset formatting (clear sticky flags from Memory/Code sections)
            std::cout << std::setfill(' ') << std::right << std::dec;

            // --- MIDDLE SECTION: ROW 1 (REGS | STACK) ---
            std::vector<std::string> left_lines;
            std::vector<std::string> right_lines;

            if (m_show_regs) {
                RegisterView view(vm, m_prev_regs, m_focus == FOCUS_REGS, m_tstates);
                auto regs_lines = view.render();
                left_lines.insert(left_lines.end(), regs_lines.begin(), regs_lines.end());
            }

            if (m_show_stack) {
                StackView view(vm, m_stack_view_addr, m_focus == FOCUS_STACK);
                auto stack_lines = view.render();
                right_lines.insert(right_lines.end(), stack_lines.begin(), stack_lines.end());
            }

            print_separator();
            print_side_by_side(left_lines, right_lines, 40);
            
            // --- MIDDLE SECTION: SEPARATOR ---
            print_separator();

            // --- MIDDLE SECTION: ROW 2 (CODE | WATCH/BP) ---
            left_lines.clear();
            right_lines.clear();

            if (m_show_code) {
                int width = (m_show_watch || m_show_breakpoints) ? 0 : terminal_width;
                CodeView view(vm, m_code_view_addr, m_code_rows, pc, width, m_focus == FOCUS_CODE, m_history);
                auto code_lines = view.render();
                left_lines.insert(left_lines.end(), code_lines.begin(), code_lines.end());
            }

            if (m_show_watch || m_show_breakpoints) {
                // [WATCH]
                if (m_show_watch) {
                    if (m_focus == FOCUS_WATCH) right_lines.push_back(Terminal::YELLOW + "[WATCH]" + Terminal::RESET);
                    else right_lines.push_back(Terminal::GREEN + "[WATCH]" + Terminal::RESET);
                    
                    for (uint16_t addr : m_watches) {
                        uint8_t val = vm.get_memory().read(addr);
                        std::stringstream ss;
                        ss << "  " << Strings::hex16(addr) << ": " << Terminal::HI_WHITE << Strings::hex8(val) << Terminal::RESET;
                        if (std::isprint(val)) ss << " (" << Terminal::HI_YELLOW << (char)val << Terminal::RESET << ")";
                        right_lines.push_back(ss.str());
                    }
                    if (m_watches.empty()) {
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
                    for (const auto& bp : m_breakpoints) {
                        std::stringstream ss;
                        ss << "  " << i++ << ". " << Strings::hex16(bp.addr);
                        if (!bp.enabled) ss << Terminal::GRAY << " [Disabled]" << Terminal::RESET;
                        right_lines.push_back(ss.str());
                    }
                    if (m_breakpoints.empty()) {
                        right_lines.push_back(Terminal::GRAY + "  No items." + Terminal::RESET);
                        right_lines.push_back(Terminal::GRAY + "  Use 'b <addr>'" + Terminal::RESET);
                    }
                }

                print_side_by_side(left_lines, right_lines, 40);
            } else {
                for(const auto& l : left_lines) std::cout << l << "\n";
            }
            
            if (m_output_buffer.tellp() > 0) {
                std::cout << Terminal::yellow("[OUTPUT]") << "\n";
                std::cout << m_output_buffer.str();
                m_output_buffer.str("");
                m_output_buffer.clear();
            }
            
            print_separator();
            auto pcmd = [](const std::string& key, const std::string& name) {
                std::cout << Terminal::GRAY << "[" << Terminal::HI_WHITE << Terminal::BOLD << key << Terminal::RESET << Terminal::GRAY << "]" << name << " " << Terminal::RESET;
            };
            pcmd("s", "tep");
            pcmd("n", "ext");
            pcmd("f", "inish");
            pcmd("c", "ontinue");
            pcmd("b", "reak");
            pcmd("w", "atch");
            pcmd("h", "elp");
            pcmd("q", "uit");
            std::cout << "\n";
            std::cout << std::flush;
        }

        void do_step(int n) {
            m_prev_regs = vm.get_cpu().save_state();
            if (m_history.size() >= 2) m_history.pop_front();
            m_history.push_back(vm.get_cpu().get_PC());
            m_tstates += 4 * n; // Mock T-states

            for (int i = 0; i < n; ++i) {
                if (i > 0 && check_breakpoints(vm.get_cpu().get_PC())) break;
                vm.get_cpu().step();
            }
        }

        void do_next() {
            m_prev_regs = vm.get_cpu().save_state();
            if (m_history.size() >= 2) m_history.pop_front();
            m_history.push_back(vm.get_cpu().get_PC());
            m_tstates += 4;

            uint16_t pc = vm.get_cpu().get_PC();
            auto lines = vm.get_analyzer().parse_code(pc, 2);
            if (lines.empty()) { do_step(1); return; }

            std::string mnemonic = lines[0].mnemonic;
            // Heuristic: Step over CALL, RST, LDIR, etc.
            bool is_subroutine = (mnemonic.find("CALL") == 0) || (mnemonic.find("RST") == 0) || (mnemonic.find("LDIR") == 0) || (mnemonic.find("LDDR") == 0);

            if (is_subroutine) {
                uint16_t next_pc = (lines.size() > 1) ? lines[1].address : pc + 1;
                log_line("Stepping over... (Target: " + Strings::hex16(next_pc) + ")");
                
                // Simple run loop
                while (vm.get_cpu().get_PC() != next_pc) {
                    if (check_breakpoints(vm.get_cpu().get_PC())) break;
                    vm.get_cpu().step();
                }
            } else {
                vm.get_cpu().step();
            }
        }

        void do_finish() {
            m_prev_regs = vm.get_cpu().save_state();
            log_line("Running until return...");
            
            while (true) {
                if (check_breakpoints(vm.get_cpu().get_PC())) { 
                    log_line("Breakpoint hit!"); 
                    return; 
                }

                uint16_t pc = vm.get_cpu().get_PC();
                auto lines = vm.get_analyzer().parse_code(pc, 1);
                if (lines.empty()) { vm.get_cpu().step(); continue; }
                
                std::string mnemonic = lines[0].mnemonic;
                
                // Check for Return
                if (mnemonic.find("RET") == 0) {
                    uint16_t sp_before = vm.get_cpu().get_SP();
                    
                    if (m_history.size() >= 2) m_history.pop_front();
                    m_history.push_back(pc);
                    m_tstates += 4;

                    vm.get_cpu().step();
                    
                    if (vm.get_cpu().get_SP() > sp_before) {
                        return;
                    }
                    continue;
                }
                
                // Check for Subroutine/Block (Step Over)
                bool is_subroutine = (mnemonic.find("CALL") == 0) || (mnemonic.find("RST") == 0) || (mnemonic.find("LDIR") == 0) || (mnemonic.find("LDDR") == 0);
                                     
                if (is_subroutine) {
                    if (m_history.size() >= 2) m_history.pop_front();
                    m_history.push_back(pc);
                    m_tstates += 4;

                    uint16_t next_pc = pc + lines[0].bytes.size();
                    while (vm.get_cpu().get_PC() != next_pc) {
                        if (check_breakpoints(vm.get_cpu().get_PC())) { log_line("Breakpoint hit!"); return; }
                        vm.get_cpu().step();
                    }
                } else {
                    do_step(1);
                }
            }
        }

        void do_continue() {
            m_prev_regs = vm.get_cpu().save_state();
            log_line("Running... (Press Ctrl+C to stop if supported)");
            print_dashboard();
            // In a real CLI tool, we'd need non-blocking input or signal handling.
            // For this implementation, we run in batches to allow potential future interruption checks.
            while (true) {
                for (int i = 0; i < 10000; ++i) {
                    if (check_breakpoints(vm.get_cpu().get_PC())) { log_line("Breakpoint hit!"); return; }
                    vm.get_cpu().step();
                }
            }
        }

        void print_side_by_side(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width) {
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

        uint16_t parse_addr(std::string arg) {
            if (arg.empty()) return 0;
            if (arg[0] == '$') arg = "0x" + arg.substr(1);
            return vm.parse_address(arg);
        }

        void save_config() {
            std::ofstream f("zxtool_config.ini");
            if (f.is_open()) {
                f << "[Registers]\n";
                f << "\n[View]\n";
                f << "code_rows=" << m_code_rows << "\n";
                f << "mem_rows=" << m_mem_rows << "\n";
                f << "stack_rows=" << m_stack_rows << "\n";
                f << "show_mem=" << m_show_mem << "\n";
                f << "show_regs=" << m_show_regs << "\n";
                f << "show_code=" << m_show_code << "\n";
                f << "show_stack=" << m_show_stack << "\n";
                f << "show_watch=" << m_show_watch << "\n";
                f << "show_breakpoints=" << m_show_breakpoints << "\n";
            }
        }

        void init_colors() {
            m_colors["reset"] = "0";
            m_colors["red"] = "31";
            m_colors["green"] = "32";
            m_colors["yellow"] = "33";
            m_colors["blue"] = "34";
            m_colors["magenta"] = "35";
            m_colors["cyan"] = "36";
            m_colors["white"] = "37";
            m_colors["gray"] = "90";
            m_colors["bold"] = "1";
            m_colors["dim"] = "2";
            m_colors["hi_red"] = "91";
            m_colors["hi_green"] = "92";
            m_colors["hi_yellow"] = "93";
            m_colors["hi_blue"] = "94";
            m_colors["hi_magenta"] = "95";
            m_colors["hi_cyan"] = "96";
            m_colors["hi_white"] = "97";
            m_colors["bg_dark_gray"] = "100";
        }

        void apply_colors() {
            auto set = [&](std::string& var, const std::string& name) {
                if (m_colors.count(name)) var = "\033[" + m_colors[name] + "m";
            };
            set(Terminal::RESET, "reset");
            set(Terminal::RED, "red");
            set(Terminal::GREEN, "green");
            set(Terminal::YELLOW, "yellow");
            set(Terminal::BLUE, "blue");
            set(Terminal::MAGENTA, "magenta");
            set(Terminal::CYAN, "cyan");
            set(Terminal::WHITE, "white");
            set(Terminal::GRAY, "gray");
            set(Terminal::BOLD, "bold");
            set(Terminal::DIM, "dim");
            set(Terminal::HI_RED, "hi_red");
            set(Terminal::HI_GREEN, "hi_green");
            set(Terminal::HI_YELLOW, "hi_yellow");
            set(Terminal::HI_BLUE, "hi_blue");
            set(Terminal::HI_MAGENTA, "hi_magenta");
            set(Terminal::HI_CYAN, "hi_cyan");
            set(Terminal::HI_WHITE, "hi_white");
            set(Terminal::BG_DARK_GRAY, "bg_dark_gray");
        }

        void load_config() {
            std::ifstream f("zxtool_config.ini");
            if (f.is_open()) {
                std::string line;
                std::string section;
                while (std::getline(f, line)) {
                    if (line.empty() || line[0] == ';' || line[0] == '#') continue;
                    if (line[0] == '[') {
                        size_t end = line.find(']');
                        if (end != std::string::npos) {
                            section = line.substr(1, end - 1);
                        }
                        continue;
                    }
                    std::stringstream ss(line);
                    std::string key;
                    if (std::getline(ss, key, '=')) {
                        std::string val_str;
                        std::getline(ss, val_str);
                        
                        try {
                            int val = std::stoi(val_str);
                            if (key == "code_rows") {
                                if (val > 0) m_code_rows = val;
                            } else if (key == "mem_rows") {
                                if (val > 0) m_mem_rows = val;
                            } else if (key == "stack_rows") {
                                if (val > 0) m_stack_rows = val;
                            } else if (key == "show_mem") {
                                m_show_mem = (bool)val;
                            } else if (key == "show_regs") {
                                m_show_regs = (bool)val;
                            } else if (key == "show_code") {
                                m_show_code = (bool)val;
                            } else if (key == "show_stack") {
                                m_show_stack = (bool)val;
                            } else if (key == "show_watch") {
                                m_show_watch = (bool)val;
                            } else if (key == "show_breakpoints") {
                                m_show_breakpoints = (bool)val;
                            }
                        } catch (...) {}
                    }
                }
                apply_colors();
            }
        }

    public:
        DebugSession(VirtualMachine& _vm, replxx::Replxx& _repl) : vm(_vm), repl(_repl) {
            init_colors();
        }

        void start() {
            setup_replxx();
            repl.history_load("zxtool_history.txt");
            load_config();
            m_prev_regs = vm.get_cpu().save_state();
            m_code_view_addr = vm.get_cpu().get_PC();
            m_mem_view_addr = vm.get_cpu().get_PC();
            m_stack_view_addr = vm.get_cpu().get_SP();

            // Ensure focus is on a visible panel
            int attempts = 0;
            while (attempts < 6 && (
                (m_focus == FOCUS_MEMORY && !m_show_mem) ||
                (m_focus == FOCUS_REGS && !m_show_regs) ||
                (m_focus == FOCUS_STACK && !m_show_stack) ||
                (m_focus == FOCUS_CODE && !m_show_code) ||
                (m_focus == FOCUS_WATCH && !m_show_watch) ||
                (m_focus == FOCUS_BREAKPOINTS && !m_show_breakpoints)
            )) {
                m_focus = (Focus)((m_focus + 1) % 6);
                attempts++;
            }

            while (running) {
                print_dashboard();
                const char* input_cstr = repl.input("> ");
                if (input_cstr == nullptr) break;

                std::string input(input_cstr);
                if (input.empty()) {
                    if (last_command.empty()) continue;
                    input = last_command;
                } else {
                    last_command = input;
                    repl.history_add(input);
                }

                std::stringstream ss(input);
                std::string cmd;
                ss >> cmd;

                if (cmd == "s" || cmd == "step") { int n=1; ss >> n; if(ss.fail()) n=1; do_step(n); m_code_view_addr = vm.get_cpu().get_PC(); }
                else if (cmd == "n" || cmd == "next") { do_next(); m_code_view_addr = vm.get_cpu().get_PC(); }
                else if (cmd == "f" || cmd == "finish") { do_finish(); m_code_view_addr = vm.get_cpu().get_PC(); }
                else if (cmd == "c" || cmd == "continue") { do_continue(); }
                else if (cmd == "q" || cmd == "quit") { running = false; }
                else if (cmd == "h" || cmd == "help") { print_help(); }
                else if (cmd == "lines") {
                    std::string type; int n;
                    if (ss >> type >> n && n > 0) {
                        if (type == "code") m_code_rows = n;
                        else if (type == "mem") m_mem_rows = n;
                        else if (type == "stack") m_stack_rows = n;
                        else log_line("Usage: lines <code|mem|stack> <n>");
                    } else log_line("Usage: lines <code|mem|stack> <n>");
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
                        else log_line("Usage: toggle <mem|regs|code|stack|watch|breakpoints>");
                    } else log_line("Usage: toggle <mem|regs|code|stack|watch|breakpoints>");
                }
                else if (cmd == "b" || cmd == "break") {
                    std::string arg; if(ss>>arg) { m_breakpoints.push_back({parse_addr(arg), true}); log_line("Breakpoint set."); }
                }
                else if (cmd == "d" || cmd == "delete") {
                    std::string arg; if(ss>>arg) { 
                        uint16_t a = parse_addr(arg);
                        m_breakpoints.erase(std::remove_if(m_breakpoints.begin(), m_breakpoints.end(), [a](const Breakpoint& b){ return b.addr == a; }), m_breakpoints.end());
                    }
                }
                else if (cmd == "w" || cmd == "watch") {
                    std::string arg; if(ss>>arg) { m_watches.push_back(parse_addr(arg)); }
                }
                else if (cmd == "u" || cmd == "unwatch") {
                    std::string arg; if(ss>>arg) { uint16_t a = parse_addr(arg); m_watches.erase(std::remove(m_watches.begin(), m_watches.end(), a), m_watches.end()); }
                }
                else { log_line("Unknown command."); }
            }
            save_config();
            repl.history_save("zxtool_history.txt");
        }
    };

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

    DebugSession session(m_vm, m_repl);
    session.start();
    
    return 0;
}