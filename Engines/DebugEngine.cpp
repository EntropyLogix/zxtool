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

DebugEngine::DebugEngine(VirtualMachine& vm, const Options& options)
    : m_vm(vm), m_options(options)
{
}

// ANSI Colors for Dashboard
namespace Color {
    std::string RESET   = "\033[0m";
    std::string BOLD    = "\033[1m";
    std::string DIM     = "\033[2m";
    std::string RED     = "\033[31m";
    std::string GREEN   = "\033[32m";
    std::string YELLOW  = "\033[33m";
    std::string BLUE    = "\033[34m";
    std::string MAGENTA = "\033[35m";
    std::string CYAN    = "\033[36m";
    std::string WHITE   = "\033[37m";
    std::string GRAY    = "\033[90m";
    
    std::string HI_RED     = "\033[91m";
    std::string HI_GREEN   = "\033[92m";
    std::string HI_YELLOW  = "\033[93m";
    std::string HI_BLUE    = "\033[94m";
    std::string HI_MAGENTA = "\033[95m";
    std::string HI_CYAN    = "\033[96m";
    std::string HI_WHITE   = "\033[97m";
    std::string BG_DARK_GRAY = "\033[100m";
}

// Helper functions for clean hex output (no 0x prefix)
static std::string hex8(uint8_t v) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)v;
    return ss.str();
}
static std::string hex16(uint16_t v) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << (int)v;
    return ss.str();
}

static std::string format_flags(uint8_t f, uint8_t prev_f) {
    std::stringstream ss;
    const char* syms = "SZ5H3PNC";
    for (int i = 7; i >= 0; --i) {
        bool bit = (f >> i) & 1;
        bool prev_bit = (prev_f >> i) & 1;
        char c = bit ? syms[7-i] : '-';
        
        if (bit != prev_bit) {
            ss << Color::HI_YELLOW << Color::BOLD << c << Color::RESET;
        } else if (bit) {
            ss << Color::HI_WHITE << c << Color::RESET;
        } else {
            ss << Color::GRAY << c << Color::RESET;
        }
    }
    return ss.str();
}

static void print_byte_smart(uint8_t b) {
    if (b == 0) std::cout << Color::GRAY << "00" << Color::RESET;
    else std::cout << Color::HI_WHITE << hex8(b) << Color::RESET;
}

struct Terminal {
    static void clear() {
        std::cout << "\033[H\033[2J\033[3J";
    }
    
    static std::string yellow(const std::string& s) { return "\033[1;33m" + s + "\033[0m"; }
};

static size_t visible_length(const std::string& s) {
    size_t len = 0;
    bool in_esc = false;
    for (char c : s) {
        if (c == '\033') in_esc = true;
        else if (in_esc && c == 'm') in_esc = false;
        else if (!in_esc) len++;
    }
    return len;
}

static void get_terminal_size(int& width, int& height) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    } else {
        // Fallback jeśli się nie uda
        width = 80;
        height = 24;
    }
#else
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        width = w.ws_col;
        height = w.ws_row;
    } else {
        // Fallback
        width = 80;
        height = 24;
    }
#endif
}

namespace {
    class DebugSession {
        VirtualMachine& vm;
        replxx::Replxx& repl;
        std::string last_command;
        bool running = true;
        std::stringstream m_output_buffer;
        enum Focus { FOCUS_MEMORY, FOCUS_REGS, FOCUS_STACK, FOCUS_CODE, FOCUS_WATCH, FOCUS_BREAKPOINTS, FOCUS_MAP };
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
        bool m_show_map = true;
        std::map<std::string, std::string> m_colors;
        
        struct Breakpoint { uint16_t addr; bool enabled; };
        std::vector<Breakpoint> m_breakpoints;
        std::vector<uint16_t> m_watches;
        std::deque<uint16_t> m_history;
        uint64_t m_tstates = 0;
        
        struct RegState {
            uint16_t af, bc, de, hl;
            uint16_t afp, bcp, dep, hlp;
            uint16_t ix, iy, sp, pc;
            uint8_t i, r, im;
            bool iff1;
        };
        RegState m_prev_regs;

        RegState capture_regs() {
            auto& cpu = vm.get_cpu();
            return {
                cpu.get_AF(), cpu.get_BC(), cpu.get_DE(), cpu.get_HL(),
                cpu.get_AFp(), cpu.get_BCp(), cpu.get_DEp(), cpu.get_HLp(),
                cpu.get_IX(), cpu.get_IY(), cpu.get_SP(), cpu.get_PC(),
                cpu.get_I(), cpu.get_R(), (uint8_t)cpu.get_IRQ_mode(), cpu.get_IFF1()
            };
        }

        template<typename T>
        void log(const T& msg) {
            m_output_buffer << msg;
        }
        
        void log_line(const std::string& msg) {
            m_output_buffer << msg << "\n";
        }

        struct CommandHelp {
            std::string shortcut;
            std::string name;
            std::string args;
            std::string desc;
        };

        struct HelpCategory {
            std::string title;
            std::vector<CommandHelp> commands;
        };

        void setup_replxx() {
            repl.install_window_change_handler();
            
            // 1. Completion
            repl.set_completion_callback([this](std::string const& context, int& contextLen) {
                std::vector<replxx::Replxx::Completion> completions;
                std::vector<std::string> cmds = {
                    "step", "next", "finish", "continue", "break", "watch", "delete", "unwatch",
                    "help", "quit", "lines", "toggle", "map"
                };
                
                std::string prefix = context.substr(context.find_last_of(" ") + 1);
                contextLen = prefix.length();
                
                for (auto const& c : cmds) {
                    if (c.rfind(prefix, 0) == 0) {
                        completions.push_back(c);
                    }
                }
                return completions;
            });

            // 2. Hints
            repl.set_hint_callback([this](std::string const& input, int& contextLen, replxx::Replxx::Color& color) {
                if (input.empty()) return std::vector<std::string>();
                if (input == "lines") return std::vector<std::string>{" <code|mem|stack> <n>"};
                if (input == "toggle") return std::vector<std::string>{" <mem|regs|code|stack|watch|breakpoints|map>"};
                if (input == "break" || input == "b") return std::vector<std::string>{" <addr>"};
                if (input == "watch" || input == "w") return std::vector<std::string>{" <addr>"};
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
                    m_focus = (Focus)((m_focus + 1) % 7);
                    attempts++;
                } while (attempts < 7 && (
                    (m_focus == FOCUS_MEMORY && !m_show_mem) ||
                    (m_focus == FOCUS_REGS && !m_show_regs) ||
                    (m_focus == FOCUS_STACK && !m_show_stack) ||
                    (m_focus == FOCUS_CODE && !m_show_code) ||
                    (m_focus == FOCUS_WATCH && !m_show_watch) ||
                    (m_focus == FOCUS_BREAKPOINTS && !m_show_breakpoints) ||
                    (m_focus == FOCUS_MAP && !m_show_map)
                ));
                print_dashboard();
                repl.invoke(replxx::Replxx::ACTION::REPAINT, code);
                return replxx::Replxx::ACTION_RESULT::CONTINUE;
            };
            
            repl.bind_key(replxx::Replxx::KEY::TAB, tab_handler);
            repl.bind_key(9, tab_handler);
        }

        void print_help() {
            std::vector<HelpCategory> categories = {
                {
                    "EXECUTION", {
                        {"s", "step", "[n]",    "Execute instructions (default 1)"},
                        {"n", "next", "",       "Step over subroutine"},
                        {"f", "finish", "",     "Step out of subroutine"},
                        {"c", "continue", "",   "Continue execution"}
                    }
                },
                {
                    "SYSTEM", {
                        {"h", "help", "", "Show this message"},
                        {"lines", "", "<type> <n>", "Set lines (code/mem/stack)"},
                        {"toggle", "", "<panel>", "Toggle panel visibility"},
                        {"map", "", "", "Show memory mini-map"},
                        {"b", "break", "<addr>", "Set breakpoint"},
                        {"d", "delete", "<addr>", "Delete breakpoint"},
                        {"w", "watch", "<addr>", "Add watch address"},
                        {"u", "unwatch", "<addr>", "Remove watch"},
                        {"q", "quit", "", "Exit debugger"}
                    }
                }
            };

            m_output_buffer << "\nAvailable Commands:\n";

            for (const auto& cat : categories) {
                m_output_buffer << " [" << cat.title << "]\n";
                for (const auto& cmd : cat.commands) {
                    std::string left = "   " + cmd.shortcut;
                    if (!cmd.name.empty()) left += ", " + cmd.name;
                    if (!cmd.args.empty()) left += " " + cmd.args;
                    
                    m_output_buffer << std::left << std::setw(26) << left << cmd.desc << "\n";
                }
                m_output_buffer << "\n";
            }
        }

        uint16_t read16(uint16_t addr) {
            uint8_t l = vm.get_memory().read(addr);
            uint8_t h = vm.get_memory().read(addr + 1);
            return l | (h << 8);
        }

        std::string pad_to(const std::string& s, size_t width) {
            size_t vis = visible_length(s);
            if (vis >= width) return s;
            return s + std::string(width - vis, ' ');
        }

        std::string pad_to_with_bg(const std::string& s, size_t width, const std::string& bg_color) {
            size_t vis = visible_length(s);
            if (vis >= width) return s;
            return s + bg_color + std::string(width - vis, ' ') + Color::RESET;
        }

        template<typename CPU>
        std::vector<std::string> get_regs_lines(CPU& cpu, const RegState& prev) {
            std::vector<std::string> lines;
            auto p16 = [&](const std::string& l, uint16_t v, uint16_t pv) -> std::string {
                std::stringstream ss;
                ss << Color::CYAN << std::setw(3) << std::left << l << Color::RESET << ": " 
                   << (v != pv ? Color::HI_YELLOW : Color::GRAY) << hex16(v) << Color::RESET;
                return ss.str();
            };
            auto p8 = [&](const std::string& l, uint8_t v, uint8_t pv) -> std::string {
                std::stringstream ss;
                ss << Color::CYAN << std::setw(3) << std::left << l << Color::RESET << ": " 
                   << (v != pv ? Color::HI_YELLOW : Color::GRAY) << hex8(v) << Color::RESET;
                return ss.str();
            };

            // Row 1
            std::stringstream ss;
            ss << "  " << p16("AF", cpu.get_AF(), prev.af) << "   " << p16("AF'", cpu.get_AFp(), prev.afp) << "   " << p8("I", cpu.get_I(), prev.i);
            lines.push_back(ss.str());
            
            // Row 2
            ss.str(""); ss << "  " << p16("BC", cpu.get_BC(), prev.bc) << "   " << p16("BC'", cpu.get_BCp(), prev.bcp) << "   " << p8("R", cpu.get_R(), prev.r);
            lines.push_back(ss.str());
            
            // Row 3
            ss.str(""); ss << "  " << p16("DE", cpu.get_DE(), prev.de) << "   " << p16("DE'", cpu.get_DEp(), prev.dep) << "   "
               << Color::CYAN << std::setw(3) << std::left << "IM" << Color::RESET << ": " 
               << (cpu.get_IRQ_mode() != prev.im ? Color::HI_YELLOW : Color::GRAY) << (int)cpu.get_IRQ_mode() << Color::RESET;
            lines.push_back(ss.str());

            // Row 4
            ss.str(""); ss << "  " << p16("HL", cpu.get_HL(), prev.hl) << "   " << p16("HL'", cpu.get_HLp(), prev.hlp) << "   "
               << Color::CYAN << std::setw(3) << std::left << "IFF" << Color::RESET << ": " 
               << (cpu.get_IFF1() ? (Color::HI_GREEN + "ON ") : (Color::GRAY + "OFF")) << Color::RESET;
            lines.push_back(ss.str());
            
            // Row 5
            ss.str(""); ss << "  " << p16("IX", cpu.get_IX(), prev.ix) << "   " << p16("IY", cpu.get_IY(), prev.iy) << "   "
               << Color::CYAN << std::setw(3) << std::left << "F" << Color::RESET << ": " << format_flags(cpu.get_AF() & 0xFF, prev.af & 0xFF);
            lines.push_back(ss.str());
            
            return lines;
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
                if (has_bg) std::cout << Color::BG_DARK_GRAY;
                std::cout << std::string(padding, ' ');
                if (has_bg) std::cout << Color::RESET;

                std::cout << Color::GRAY << " | " << Color::RESET;

                if (i < right.size()) {
                    std::cout << " " << right[i];
                }
                std::cout << "\n";
            }
        }

        bool check_breakpoints(uint16_t pc) {
            for (const auto& bp : m_breakpoints) {
                if (bp.enabled && bp.addr == pc) return true;
            }
            return false;
        }

        void print_dashboard() {
            Terminal::clear();
            auto& cpu = vm.get_cpu();
            uint16_t pc = cpu.get_PC();

            const int term_w = 80;

            auto print_sep = [term_w]() { std::cout << Color::GRAY << std::string(term_w, '-') << Color::RESET << "\n"; };

            // [MEMORY]
            if (m_show_mem) {
                print_sep();
                if (m_focus == FOCUS_MEMORY) std::cout << Color::YELLOW << "[MEMORY] " << Color::RESET;
                else std::cout << Color::GREEN << "[MEMORY] " << Color::RESET;
                std::cout << Color::CYAN << " View: " << Color::HI_WHITE << hex16(m_mem_view_addr) << Color::RESET << "\n";
                print_sep();

                auto& mem = vm.get_memory();
                for (size_t i = 0; i < m_mem_rows * 16; i += 16) {
                    uint16_t addr = m_mem_view_addr + i;
                    std::cout << Color::CYAN << hex16(addr) << Color::RESET << ": ";
                    for (size_t j = 0; j < 16; ++j) {
                        print_byte_smart(mem.read(addr + j));
                        if (j == 7) std::cout << "  ";
                        else if (j == 15) std::cout << "  ";
                        else std::cout << " ";
                    }
                    std::cout << Color::GRAY << "|" << Color::RESET << " ";
                    for (size_t j = 0; j < 16; ++j) {
                        uint8_t val = mem.read(addr + j);
                        if (std::isprint(val)) std::cout << Color::HI_YELLOW << (char)val << Color::RESET;
                        else std::cout << Color::GRAY << "." << Color::RESET;
                    }
                    std::cout << "\n";
                }
            }

            // Reset formatting (clear sticky flags from Memory/Code sections)
            std::cout << std::setfill(' ') << std::right << std::dec;

            // --- MIDDLE SECTION: ROW 1 (REGS | STACK) ---
            std::vector<std::string> left_lines;
            std::vector<std::string> right_lines;

            if (m_show_regs) {
                std::stringstream header;
                if (m_focus == FOCUS_REGS) header << Color::YELLOW << "[REGS]" << Color::RESET;
                else header << Color::GREEN << "[REGS]" << Color::RESET;
                
                // T-States in header
                header << Color::CYAN << " T: " << Color::RESET << Color::HI_WHITE << m_tstates << Color::RESET 
                       << Color::GRAY << " (+" << 4 << ")" << Color::RESET; // Mock delta
                
                left_lines.push_back(header.str());

                auto regs_lines = get_regs_lines(cpu, m_prev_regs);
                left_lines.insert(left_lines.end(), regs_lines.begin(), regs_lines.end());
            }

            if (m_show_stack) {
                std::stringstream header;
                if (m_focus == FOCUS_STACK) header << Color::YELLOW << "[STACK]" << Color::RESET;
                else header << Color::GREEN << "[STACK]" << Color::RESET;
                header << Color::CYAN << " (SP=" << Color::HI_WHITE << hex16(cpu.get_SP()) << Color::CYAN << ")" << Color::RESET;
                right_lines.push_back(header.str());

                uint16_t sp = m_stack_view_addr;
                for(int i=0; i<5; ++i) {
                    uint16_t addr = sp + i*2;
                    uint16_t val = read16(addr);
                    std::stringstream ss;
                    ss << "  " << Color::GRAY << hex16(addr) << Color::RESET << ": " << Color::HI_WHITE << hex16(val) << Color::RESET;
                    auto code_lines = vm.get_analyzer().parse_code(val, 1);
                    if (!code_lines.empty() && !code_lines[0].label.empty()) {
                        ss << Color::HI_YELLOW << " (" << code_lines[0].label << ")" << Color::RESET;
                    }
                    right_lines.push_back(ss.str());
                }
            }

            print_sep();
            print_side_by_side(left_lines, right_lines, 40);
            
            // --- MIDDLE SECTION: SEPARATOR ---
            print_sep();

            // --- MIDDLE SECTION: ROW 2 (CODE | WATCH/BP) ---
            left_lines.clear();
            right_lines.clear();

            if (m_show_code) {
                if (m_focus == FOCUS_CODE) left_lines.push_back(Color::YELLOW + "[CODE]" + Color::RESET);
                else left_lines.push_back(Color::GREEN + "[CODE]" + Color::RESET);

                // History (1 line back)
                if (!m_history.empty() && m_code_view_addr == pc) {
                    uint16_t hist_addr = m_history.back();
                    auto hist_lines = vm.get_analyzer().parse_code(hist_addr, 1);
                    if (!hist_lines.empty()) {
                        const auto& line = hist_lines[0];
                        std::stringstream ss;
                        ss << "  " << Color::GRAY << hex16((uint16_t)line.address) << ": ";
                        
                        for(size_t i=0; i<std::min((size_t)4, line.bytes.size()); ++i) {
                            ss << hex8(line.bytes[i]) << " ";
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
                                    case Operand::IMM8: ss << "$" << hex8(op.num_val); break;
                                    case Operand::IMM16: ss << "$" << hex16(op.num_val); break;
                                    case Operand::MEM_IMM16: ss << "($" << hex16(op.num_val) << ")"; break;
                                    case Operand::MEM_REG16: ss << "(" << op.s_val << ")"; break;
                                    case Operand::MEM_INDEXED: ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                                    case Operand::STRING: ss << "\"" << op.s_val << "\""; break;
                                    default: break;
                                }
                            }
                        }
                        ss << Color::RESET;
                        left_lines.push_back(ss.str());
                    }
                }

                uint16_t temp_pc_iter = m_code_view_addr;
                auto lines = vm.get_analyzer().parse_code(temp_pc_iter, m_code_rows);
                for (const auto& line : lines) {
                    std::stringstream ss;
                    bool is_pc = ((uint16_t)line.address == pc);
                    std::string bg = is_pc ? Color::BG_DARK_GRAY : "";
                    std::string rst = is_pc ? (Color::RESET + bg) : Color::RESET;

                    // Gutter
                    if (is_pc) {
                        ss << bg << Color::HI_GREEN << Color::BOLD << "> " << rst;
                    } else {
                        ss << "  ";
                    }
                    
                    // Address
                    if (is_pc) ss << Color::HI_WHITE << Color::BOLD << hex16((uint16_t)line.address) << rst << ": ";
                    else ss << Color::GRAY << hex16((uint16_t)line.address) << rst << ": ";
                    
                    // Bytes
                    ss << Color::GRAY;
                    for(size_t i=0; i<std::min((size_t)4, line.bytes.size()); ++i) {
                        ss << hex8(line.bytes[i]) << " ";
                    }
                    for(size_t i=line.bytes.size(); i<4; ++i) ss << "   ";
                    ss << rst << " ";

                    // Mnemonic
                    if (is_pc) ss << Color::BOLD << Color::WHITE;
                    else ss << Color::BLUE;
                    ss << std::left << std::setw(5) << line.mnemonic << rst << " ";
                    
                    if (!line.operands.empty()) {
                        using Operand = typename std::decay_t<decltype(line)>::Operand;
                        for (size_t i = 0; i < line.operands.size(); ++i) {
                            if (i > 0) ss << ", ";
                            const auto& op = line.operands[i];
                            
                            bool is_num = (op.type == Operand::IMM8 || op.type == Operand::IMM16 || op.type == Operand::MEM_IMM16);
                            if (is_num) ss << Color::YELLOW;

                            switch (op.type) {
                                case Operand::REG8: case Operand::REG16: case Operand::CONDITION: ss << op.s_val; break;
                                case Operand::IMM8: ss << "$" << hex8(op.num_val); break;
                                case Operand::IMM16: ss << "$" << hex16(op.num_val); break;
                                case Operand::MEM_IMM16: ss << "($" << hex16(op.num_val) << ")"; break;
                                case Operand::MEM_REG16: ss << "(" << op.s_val << ")"; break;
                                case Operand::MEM_INDEXED: ss << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                                case Operand::STRING: ss << "\"" << op.s_val << "\""; break;
                                default: break;
                            }
                            if (is_num) ss << rst;
                        }
                    }
                    
                    if (m_show_watch || m_show_breakpoints) {
                        // No manual padding here, handled by print_side_by_side
                        left_lines.push_back(ss.str());
                    } else {
                        // Fixed width mode: pad to term_w
                        size_t len = visible_length(ss.str());
                        int pad = term_w - (int)len;
                        if (pad > 0) ss << std::string(pad, ' ');
                        ss << Color::RESET; // Reset background after padding
                        left_lines.push_back(ss.str());
                    }
                }
            }

            if (m_show_watch || m_show_breakpoints) {
                // [WATCH]
                if (m_show_watch) {
                    if (m_focus == FOCUS_WATCH) right_lines.push_back(Color::YELLOW + "[WATCH]" + Color::RESET);
                    else right_lines.push_back(Color::CYAN + "[WATCH]" + Color::RESET);
                    
                    for (uint16_t addr : m_watches) {
                        uint8_t val = vm.get_memory().read(addr);
                        std::stringstream ss;
                        ss << "  " << hex16(addr) << ": " << Color::HI_WHITE << hex8(val) << Color::RESET;
                        if (std::isprint(val)) ss << " (" << Color::HI_YELLOW << (char)val << Color::RESET << ")";
                        right_lines.push_back(ss.str());
                    }
                    if (m_watches.empty()) right_lines.push_back(Color::GRAY + "  (empty)" + Color::RESET);
                    right_lines.push_back("");
                }
                
                // [BREAKPOINTS]
                if (m_show_breakpoints) {
                    if (m_focus == FOCUS_BREAKPOINTS) right_lines.push_back(Color::YELLOW + "[BREAKPOINTS]" + Color::RESET);
                    else right_lines.push_back(Color::CYAN + "[BREAKPOINTS]" + Color::RESET);
                    int i = 1;
                    for (const auto& bp : m_breakpoints) {
                        std::stringstream ss;
                        ss << "  " << i++ << ". " << hex16(bp.addr);
                        if (!bp.enabled) ss << Color::GRAY << " [Disabled]" << Color::RESET;
                        right_lines.push_back(ss.str());
                    }
                    if (m_breakpoints.empty()) right_lines.push_back(Color::GRAY + "  (none)" + Color::RESET);
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
            
            print_sep();
            if (m_show_map) print_mini_map();
            auto pcmd = [](const std::string& key, const std::string& name) {
                std::cout << Color::GRAY << "[" << Color::HI_WHITE << Color::BOLD << key << Color::RESET << Color::GRAY << "]" << name << " " << Color::RESET;
            };
            pcmd("s", "tep");
            pcmd("n", "ext");
            pcmd("f", "inish");
            pcmd("c", "ontinue");
            pcmd("b", "reak");
            pcmd("w", "atch");
            pcmd("h", "elp");
            pcmd("m", "ap");
            pcmd("q", "uit");
            std::cout << "\n";
            std::cout << std::flush;
        }

        void do_step(int n) {
            m_prev_regs = capture_regs();
            if (m_history.size() >= 2) m_history.pop_front();
            m_history.push_back(vm.get_cpu().get_PC());
            m_tstates += 4 * n; // Mock T-states

            for (int i = 0; i < n; ++i) {
                if (i > 0 && check_breakpoints(vm.get_cpu().get_PC())) break;
                vm.get_cpu().step();
            }
        }

        void do_next() {
            m_prev_regs = capture_regs();
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
                log_line("Stepping over... (Target: " + hex16(next_pc) + ")");
                
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
            m_prev_regs = capture_regs();
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
            m_prev_regs = capture_regs();
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

        struct BlockInfo {
            char symbol;
            std::string color;
        };

        uint16_t parse_addr(std::string arg) {
            if (arg.empty()) return 0;
            if (arg[0] == '$') arg = "0x" + arg.substr(1);
            return vm.parse_address(arg);
        }

        BlockInfo analyze_block(uint16_t start_addr, uint16_t size) {
            auto& mem = vm.get_memory();
            uint16_t pc = vm.get_cpu().get_PC();
            uint16_t sp = vm.get_cpu().get_SP();
            uint32_t end_addr = (uint32_t)start_addr + size;

            bool is_pc = ((uint32_t)pc >= start_addr && (uint32_t)pc < end_addr);
            bool is_sp = ((uint32_t)sp >= start_addr && (uint32_t)sp < end_addr);
            
            if (is_pc && is_sp) return { '!', Color::RED + Color::BOLD };

            bool all_zeros = true;
            bool all_ff = true;
            int non_zero_count = 0;

            for (uint16_t i = 0; i < size; ++i) {
                uint8_t val = mem.read(start_addr + i);
                if (val != 0) {
                    all_zeros = false;
                    non_zero_count++;
                }
                if (val != 0xFF) all_ff = false;
            }

            char sym = ' ';
            if (all_zeros) sym = ' ';
            else if (all_ff) sym = '=';
            else if (non_zero_count < (size / 4)) sym = '.';
            else sym = '#';

            std::string color = Color::GRAY;
            if (sym != ' ') {
                if (start_addr < 0x4000) color = Color::RED;
                else if (start_addr >= 0x4000 && start_addr < 0x5800) color = Color::YELLOW;
                else if (start_addr >= 0x5800 && start_addr < 0x5B00) color = Color::HI_YELLOW;
                else color = Color::BLUE;
            }

            if (is_pc) { sym = '@'; color = Color::HI_WHITE + Color::BOLD; }
            else if (is_sp) { sym = 'S'; color = Color::RED + Color::BOLD; }

            return { sym, color };
        }

        void print_mini_map() {
            if (m_focus == FOCUS_MAP) std::cout << Color::YELLOW << "[MAP]" << Color::RESET;
            else std::cout << Color::GRAY << "[MAP]" << Color::RESET;
            std::cout << " " << Color::GRAY << "[" << Color::RESET;
            const int blocks = 64;
            const int bytes_per_block = 1024;
            
            for (int i = 0; i < blocks; ++i) {
                uint16_t addr = i * bytes_per_block;
                auto info = analyze_block(addr, bytes_per_block);
                std::cout << info.color << info.symbol << Color::RESET;
            }
            std::cout << Color::GRAY << "]" << Color::RESET << "\n";
        }

        void do_map(std::stringstream& ss) {
            std::string arg;
            if (ss >> arg) {
                // Detailed Map
                uint16_t start_addr = 0;
                try { start_addr = parse_addr(arg); } catch(...) {}
                
                m_output_buffer << "Detailed Map (1 char = 1 byte) from " << hex16(start_addr) << ":\n";
                const int cols = 64;
                const int rows = 16; // 1024 bytes total
                auto& mem = vm.get_memory();

                for (int r = 0; r < rows; ++r) {
                    uint16_t row_addr = start_addr + r * cols;
                    m_output_buffer << hex16(row_addr) << ": ";
                    for (int c = 0; c < cols; ++c) {
                        uint16_t addr = row_addr + c;
                        uint8_t val = mem.read(addr);
                        
                        if (val == 0) m_output_buffer << Color::GRAY << "." << Color::RESET;
                        else if (val == 0xFF) m_output_buffer << Color::BLUE << "=" << Color::RESET;
                        else if (std::isprint(val)) m_output_buffer << Color::HI_YELLOW << (char)val << Color::RESET;
                        else m_output_buffer << Color::BLUE << "#" << Color::RESET;
                    }
                    m_output_buffer << "\n";
                }
            } else {
                // Global Map
                m_output_buffer << "Global Memory Map (1 char = 128 bytes):\n";
                const int width = 64;
                const int bytes_per_block = 128;
                const int rows = 65536 / (width * bytes_per_block); // 8 rows

                for (int r = 0; r < rows; ++r) {
                    m_output_buffer << hex16(r * width * bytes_per_block) << ": ";
                    for (int c = 0; c < width; ++c) {
                        uint16_t addr = (r * width + c) * bytes_per_block;
                        auto info = analyze_block(addr, bytes_per_block);
                        m_output_buffer << info.color << info.symbol << Color::RESET;
                    }
                    m_output_buffer << "\n";
                }
                m_output_buffer << "Legend: " 
                                << Color::RED << "ROM" << Color::RESET << " "
                                << Color::YELLOW << "SCR" << Color::RESET << " "
                                << Color::HI_YELLOW << "ATTR" << Color::RESET << " "
                                << Color::BLUE << "RAM" << Color::RESET << " | "
                                << Color::HI_WHITE << Color::BOLD << "@" << Color::RESET << " PC "
                                << Color::RED << Color::BOLD << "S" << Color::RESET << " SP "
                                << Color::RED << Color::BOLD << "!" << Color::RESET << " Collision\n";
            }
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
                f << "show_map=" << m_show_map << "\n";
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
            set(Color::RESET, "reset");
            set(Color::RED, "red");
            set(Color::GREEN, "green");
            set(Color::YELLOW, "yellow");
            set(Color::BLUE, "blue");
            set(Color::MAGENTA, "magenta");
            set(Color::CYAN, "cyan");
            set(Color::WHITE, "white");
            set(Color::GRAY, "gray");
            set(Color::BOLD, "bold");
            set(Color::DIM, "dim");
            set(Color::HI_RED, "hi_red");
            set(Color::HI_GREEN, "hi_green");
            set(Color::HI_YELLOW, "hi_yellow");
            set(Color::HI_BLUE, "hi_blue");
            set(Color::HI_MAGENTA, "hi_magenta");
            set(Color::HI_CYAN, "hi_cyan");
            set(Color::HI_WHITE, "hi_white");
            set(Color::BG_DARK_GRAY, "bg_dark_gray");
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
                            } else if (key == "show_map") {
                                m_show_map = (bool)val;
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
            m_prev_regs = capture_regs();
            m_code_view_addr = vm.get_cpu().get_PC();
            m_mem_view_addr = vm.get_cpu().get_PC();
            m_stack_view_addr = vm.get_cpu().get_SP();

            // Ensure focus is on a visible panel
            int attempts = 0;
            while (attempts < 7 && (
                (m_focus == FOCUS_MEMORY && !m_show_mem) ||
                (m_focus == FOCUS_REGS && !m_show_regs) ||
                (m_focus == FOCUS_STACK && !m_show_stack) ||
                (m_focus == FOCUS_CODE && !m_show_code) ||
                (m_focus == FOCUS_WATCH && !m_show_watch) ||
                (m_focus == FOCUS_BREAKPOINTS && !m_show_breakpoints) ||
                (m_focus == FOCUS_MAP && !m_show_map)
            )) {
                m_focus = (Focus)((m_focus + 1) % 7);
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
                        else if (panel == "map") m_show_map = !m_show_map;
                        else log_line("Usage: toggle <mem|regs|code|stack|watch|breakpoints|map>");
                    } else log_line("Usage: toggle <mem|regs|code|stack|watch|breakpoints|map>");
                }
                else if (cmd == "map") { do_map(ss); }
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

    DebugSession session(m_vm, m_repl);
    session.start();
    
    return 0;
}

void DebugEngine::print_registers() {
    auto& m_cpu = m_vm.get_cpu();
    std::cout << "PC: " << hex16(m_cpu.get_PC()) << " SP: " << hex16(m_cpu.get_SP()) << "\n";
    std::cout << "AF: " << hex16(m_cpu.get_AF()) << " BC: " << hex16(m_cpu.get_BC()) << "\n";
    std::cout << "DE: " << hex16(m_cpu.get_DE()) << " HL: " << hex16(m_cpu.get_HL()) << "\n";
}

void DebugEngine::print_instruction(uint16_t pc) {
    auto line = m_vm.get_analyzer().parse_instruction(pc);
    std::cout << hex16(line.address) << ": " << line.mnemonic;
    
    if (!line.operands.empty()) {
        std::cout << " ";
        using Operand = typename std::decay_t<decltype(line)>::Operand;
        for (size_t i = 0; i < line.operands.size(); ++i) {
            if (i > 0) std::cout << ", ";
            const auto& op = line.operands[i];
            switch (op.type) {
                case Operand::REG8: case Operand::REG16: case Operand::CONDITION:
                    std::cout << op.s_val; break;
                case Operand::IMM8:
                    std::cout << "$" << hex8(op.num_val); break;
                case Operand::IMM16:
                    std::cout << "$" << hex16(op.num_val); break;
                case Operand::MEM_IMM16:
                    std::cout << "($" << hex16(op.num_val) << ")"; break;
                case Operand::MEM_REG16:
                    std::cout << "(" << op.s_val << ")"; break;
                case Operand::MEM_INDEXED:
                    std::cout << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                default: break;
            }
        }
    }
    std::cout << std::endl;
}

void DebugEngine::print_memory(uint16_t addr, uint16_t len) {
    auto& mem = m_vm.get_memory();
    std::cout << "--- Memory Dump from " << hex16(addr) << " (" << std::dec << len << " bytes) ---\n";
    for (size_t i = 0; i < len; i += 16) {
        std::cout << Color::GRAY << hex16((uint16_t)(addr + i)) << Color::RESET << ": ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) { print_byte_smart(mem.read(addr + i + j)); std::cout << " "; }
            else std::cout << "   ";
        }
        std::cout << Color::GRAY << "| " << Color::RESET;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) {
                uint8_t val = mem.read(addr + i + j);
                if (std::isprint(val)) std::cout << Color::HI_YELLOW << (char)val << Color::RESET;
                else std::cout << Color::GRAY << "." << Color::RESET;
            }
        }
        std::cout << "\n";
    }
}