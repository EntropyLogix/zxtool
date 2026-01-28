#ifndef __DEBUGENGINE_H__
#define __DEBUGENGINE_H__

#include "Engine.h"

#include <vector>
#include <string>
#include <functional>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <map>

#include "../Core/Core.h"
#include "../Cmd/Options.h"
#include "../Core/Expression.h"
#include "../Utils/Terminal.h"
#include "../Utils/Strings.h"
#include "../Utils/Commands.h"
#include "Autocompletion.h"
#include "Hint.h"
#include "../Core/Debugger.h"

struct Theme {
    std::string header_focus = Terminal::rgb_fg(109, 222, 111) + Terminal::BOLD;
    std::string header_blur = Terminal::rgb_fg(109, 222, 111);
    std::string separator = Terminal::rgb_fg(137, 137, 137);
    std::string address = Terminal::rgb_fg(20, 208, 255);
    std::string value = Terminal::rgb_fg(64, 64, 64);
    std::string value_dim = Terminal::rgb_fg(255, 255, 255 );
    std::string highlight = Terminal::rgb_fg(255, 241, 107);
    std::string label = Terminal::rgb_fg(193, 24, 193);
    std::string mnemonic = Terminal::rgb_fg(72, 127, 188);
    std::string operand_num = Terminal::rgb_fg(142, 144, 63);
    std::string reg = Terminal::rgb_fg(20, 208, 255);
    std::string comment = Terminal::rgb_fg(78, 155, 156);
    std::string pc_fg = Terminal::rgb_fg(220, 220, 220);
    std::string pc_bg = Terminal::rgb_bg(102, 102, 102);
    std::string error = Terminal::rgb_fg(255, 0, 0);
    std::string hint_error = Terminal::rgb_fg(255, 100, 100);
    std::string bracket_match = Terminal::rgb_fg(255, 0, 255);
};

class DebugView {
public:
    DebugView(Core& core, const Theme& theme) : m_core(core), m_theme(theme) {}
    virtual ~DebugView() = default;
    virtual std::vector<std::string> render() = 0;
    void set_focus(bool focus) { m_has_focus = focus; }
    void set_rows(int rows) { m_rows = rows; }
    int get_rows() const { return m_rows; }
    virtual bool on_key(const Terminal::Input& in) { return false; }

protected:
    std::string format_header(const std::string& title, const std::string& extra = "") const;

    Core& m_core;
    const Theme& m_theme;
    bool m_has_focus = false;
    int m_rows = 0;
};

class MemoryView : public DebugView {
public:
    MemoryView(Core& core, int rows, const Theme& theme) : DebugView(core, theme) { m_rows = rows; }
    std::vector<std::string> render() override;
    void set_address(uint16_t addr);
    uint16_t get_address() const { return m_cursor_addr; }
    void scroll(int delta);
    bool on_key(const Terminal::Input& in) override;
private:
    void ensure_visible();
    uint16_t m_cursor_addr = 0;
    uint16_t m_view_addr = 0;
    bool m_focus_ascii = false;
};

class RegisterView : public DebugView {
public:
    RegisterView(Core& core, const Theme& theme) : DebugView(core, theme) {}
    std::vector<std::string> render() override;
    void set_state(const Core::CpuType::State& prev) { m_prev = prev; }
private:
    std::string format_flags(uint8_t f, uint8_t prev_f);
    Core::CpuType::State m_prev;
};

class StackView : public DebugView {
public:
    StackView(Core& core, int rows, const Theme& theme) : DebugView(core, theme) { m_rows = rows; }
    std::vector<std::string> render() override;
    void set_address(uint16_t addr) { m_view_addr = addr; }
    uint16_t get_address() const { return m_view_addr; }
    void scroll(int delta) { m_view_addr += delta; }
    void set_prev_sp(uint16_t sp) { m_prev_sp = sp; }
    bool on_key(const Terminal::Input& in) override;
private:
    uint16_t m_view_addr = 0;
    uint16_t m_prev_sp = 0;
};

class CodeView : public DebugView {
public:
    CodeView(Core& core, int rows, const Theme& theme) : DebugView(core, theme) { m_rows = rows; }
    std::vector<std::string> render() override;
    void set_address(uint16_t addr) { m_start_addr = addr; m_skip_lines = 0; }
    void set_skip_lines(int skip) { m_skip_lines = skip; }
    uint16_t get_address() const { return m_start_addr; }
    void scroll(int delta);
    bool on_key(const Terminal::Input& in) override;
    void set_state(uint16_t pc, int width, uint16_t last_pc, bool has_history, bool pc_moved, uint64_t tstates, uint64_t prev_tstates) {
        m_pc = pc; m_width = width; m_last_pc = last_pc; m_has_history = has_history; m_pc_moved = pc_moved;
        m_tstates = tstates; m_prev_tstates = prev_tstates;
    }
    void set_debugger(Debugger* dbg) { m_debugger = dbg; }
    void set_wrap_comments(bool wrap) { m_wrap_comments = wrap; }
    void set_cursor(uint16_t addr) { m_cursor_addr = addr; }
    uint16_t get_cursor() const { return m_cursor_addr; }
    void move_cursor(int delta);
    int get_line_height(uint16_t addr);
    int get_meta_height(uint16_t addr);

    void add_output_line(std::vector<std::string>& lines, int& lines_count, int& lines_to_skip, const std::string& text);
    void render_history(std::vector<std::string>& lines);
    void process_address(uint16_t& addr, std::vector<std::string>& lines, int& lines_count, int& lines_to_skip, bool& pc_visible);
    void render_block_comments(uint16_t addr, std::vector<std::string>& lines, int& lines_count, int& lines_to_skip);
    void render_labels(const std::string& label, std::vector<std::string>& lines, int& lines_count, int& lines_to_skip);
    void render_instruction_line(const Z80Decoder<Memory>::CodeLine& line, bool is_pc, bool is_cursor, bool is_smc, bool conflict, bool shadow, bool is_orphan, bool is_traced, std::vector<std::string>& lines, int& lines_count, int& lines_to_skip);

private:
    struct DisasmInfo {
        std::string text;
        int visible_len;
    };
    Z80Decoder<Memory>::CodeLine resolve_line(uint16_t addr, bool& conflict, bool& shadow, bool& is_orphan);
    DisasmInfo format_disasm(const Z80Decoder<Memory>::CodeLine& line, bool is_pc, bool is_cursor, bool conflict, bool shadow, bool is_orphan, bool is_traced, bool is_smc);
    void format_operands(const Z80Decoder<Memory>::CodeLine& line, std::ostream& os, const std::string& color_num, const std::string& color_rst, bool bold = false);
    uint16_t m_start_addr = 0;
    uint16_t m_pc = 0;
    int m_width = 80;
    uint16_t m_last_pc = 0;
    bool m_has_history = false;
    bool m_pc_moved = false;
    Debugger* m_debugger = nullptr;
    uint64_t m_tstates = 0;
    uint64_t m_prev_tstates = 0;
    int m_skip_lines = 0;
    bool m_wrap_comments = false;
    uint16_t m_cursor_addr = 0;
};

class WatchView : public DebugView {
public:
    WatchView(Core& core, Debugger& debugger, const Theme& theme) 
        : DebugView(core, theme), m_debugger(debugger) {}
    std::vector<std::string> render() override;
private:
    Debugger& m_debugger;
};

class BreakpointView : public DebugView {
public:
    BreakpointView(Core& core, Debugger& debugger, const Theme& theme) 
        : DebugView(core, theme), m_debugger(debugger) {}
    std::vector<std::string> render() override;
private:
    Debugger& m_debugger;
};

class CommandRegistry {
public:
    enum CompletionType { CTX_NONE, CTX_EXPRESSION, CTX_SYMBOL, CTX_CUSTOM, CTX_SUBCOMMAND };

    struct SubcommandEntry {
        std::vector<CompletionType> param_types;
        std::map<std::string, SubcommandEntry> subcommands;
        std::string description;
        std::string usage;
    };

    struct CommandEntry {
        std::function<void(const std::string&)> handler;
        bool require_separator;
        std::string usage;
        std::string description;
        std::vector<CompletionType> param_types;
        std::function<void(const std::string& full_input, int param_index, const std::string& args, Terminal::Completion& result)> custom_completer = nullptr;
        std::map<std::string, SubcommandEntry> subcommands;
        bool is_alias = false;
    };

    void add(const std::vector<std::string>& names, CommandEntry entry);
    const std::map<std::string, CommandEntry>& get_commands() const { return m_commands; }
    
    CompletionType resolve_type(const std::string& cmd, int param_index, const std::string& args_part) const;
    std::vector<std::string> get_subcommand_candidates(const std::string& cmd, int param_index, const std::string& args_part) const;
    
    std::string get_syntax(const std::string& cmd_name) const;
    const CommandEntry* find_command(const std::string& name) const;

private:
    std::map<std::string, CommandEntry> m_commands;
};

class Dashboard {
public:
    friend class Autocompletion;
    friend class Hint;
    Dashboard(Debugger& debugger) 
        : m_debugger(debugger)
        , m_memory_view(debugger.get_core(), 4, m_theme)
        , m_register_view(debugger.get_core(), m_theme)
        , m_stack_view(debugger.get_core(), 4, m_theme)
        , m_code_view(debugger.get_core(), 15, m_theme)
        , m_watch_view(debugger.get_core(), debugger, m_theme)
        , m_breakpoint_view(debugger.get_core(), debugger, m_theme)
    {
        m_code_view.set_debugger(&m_debugger);
        m_debugger.set_logger([this](const std::string& msg){ log(msg); });
        m_editor.set_highlight_color(m_theme.bracket_match);
        m_editor.set_error_color(m_theme.hint_error);
        
        m_command_registry.add({"evaluate", "eval"}, {[this](const std::string& s){ cmd_evaluate(s); }, true, "expression", "Evaluate expression", {CommandRegistry::CTX_EXPRESSION}});
        m_command_registry.add({"quit", "q"}, {[this](const std::string& s){ cmd_quit(s); }, true, "", "Exit debugger", {}});
        m_command_registry.add({"help"}, {[this](const std::string& s){ cmd_help(s); }, false, "[command]", "Show help", {}});
        m_command_registry.add({"set"}, {[this](const std::string& s){ cmd_set(s); }, true, "target = value", "Set variable/memory", {CommandRegistry::CTX_EXPRESSION, CommandRegistry::CTX_EXPRESSION, CommandRegistry::CTX_EXPRESSION}});
        m_command_registry.add({"undef"}, {[this](const std::string& s){ cmd_undef(s); }, true, "symbol", "Undefine symbol", {CommandRegistry::CTX_SYMBOL}});
        m_command_registry.add({"?"}, {[this](const std::string& s){ cmd_expression(s); }, false, "expression", "Evaluate expression", {CommandRegistry::CTX_EXPRESSION}});
        m_command_registry.add({"??"}, {[this](const std::string& s){ cmd_expression_detailed(s); }, false, "expression", "Evaluate detailed", {CommandRegistry::CTX_EXPRESSION}});
        
        CommandRegistry::CommandEntry opt_entry;
        opt_entry.handler = [this](const std::string& s){ cmd_options(s); };
        opt_entry.require_separator = false;
        opt_entry.description = "Configure options";
        opt_entry.param_types = {CommandRegistry::CTX_SUBCOMMAND};
        
        CommandRegistry::SubcommandEntry leaf;
        leaf.param_types = {};

        CommandRegistry::SubcommandEntry bool_opts;
        bool_opts.param_types = {CommandRegistry::CTX_SUBCOMMAND};
        bool_opts.description = "Enable/Disable";
        bool_opts.subcommands = { {"on", { {}, {}, "Enable", "" }}, {"off", { {}, {}, "Disable", "" }} };

        CommandRegistry::SubcommandEntry comment_opts;
        comment_opts.param_types = {CommandRegistry::CTX_SUBCOMMAND};
        comment_opts.description = "Comment mode";
        comment_opts.subcommands = { {"wrap", { {}, {}, "Wrap comments", "" }}, {"truncate", { {}, {}, "Truncate comments", "" }} };

        opt_entry.subcommands = {
            {"colors", { bool_opts.param_types, bool_opts.subcommands, "Toggle colors", "" }},
            {"autocompletion", { bool_opts.param_types, bool_opts.subcommands, "Toggle autocompletion", "" }},
            {"bracketshighlight", { bool_opts.param_types, bool_opts.subcommands, "Toggle bracket highlight", "" }},
            {"comments", { comment_opts.param_types, comment_opts.subcommands, "Configure comments", "" }}
        };
        m_command_registry.add({"options"}, opt_entry);

        m_command_registry.add({"watch", "w"}, {[this](const std::string& s){ cmd_watch(s); }, true, "expression", "Add watch", {CommandRegistry::CTX_EXPRESSION}});
        m_command_registry.add({"bl"}, {[this](const std::string& s){ cmd_break_list(s); }, false, "", "List breakpoints", {}});
        
        CommandRegistry::CommandEntry break_entry;
        break_entry.handler = [this](const std::string& s){ cmd_break(s); };
        break_entry.require_separator = true;
        break_entry.description = "Manage breakpoints";
        break_entry.param_types = {CommandRegistry::CTX_SUBCOMMAND};
        
        CommandRegistry::SubcommandEntry break_expr_arg;
        break_expr_arg.param_types = {CommandRegistry::CTX_EXPRESSION};
        break_expr_arg.usage = "<expr>";
        
        CommandRegistry::SubcommandEntry break_leaf;
        break_leaf.param_types = {};

        break_entry.subcommands = {
            {"add", { break_expr_arg.param_types, {}, "Add breakpoint", "<expr>" }},
            {"delete", { break_expr_arg.param_types, {}, "Delete breakpoint", "all|#ID|<expr>" }},
            {"enable", { break_expr_arg.param_types, {}, "Enable breakpoint", "all|#ID|<expr>" }},
            {"disable", { break_expr_arg.param_types, {}, "Disable breakpoint", "all|#ID|<expr>" }},
            {"list", { break_leaf.param_types, {}, "List breakpoints", "" }}
        };
        m_command_registry.add({"break"}, break_entry);
        
        m_command_registry.add({"b"}, {[this](const std::string& s){ cmd_break_smart(s); }, true, "expression", "Toggle breakpoint", {CommandRegistry::CTX_EXPRESSION}});

        m_command_registry.add({"step", "s"}, {[this](const std::string& s){ cmd_step(s); }, true, "[count]", "Step instruction", {CommandRegistry::CTX_EXPRESSION}});
        m_command_registry.add({"memory", "m"}, {[this](const std::string& s){ cmd_memory(s); }, true, "[address]", "Memory view", {CommandRegistry::CTX_EXPRESSION}});
        m_command_registry.add({"code", "c"}, {[this](const std::string& s){ cmd_code(s); }, true, "address", "Code view", {CommandRegistry::CTX_EXPRESSION}});
        auto view_completer = [](const std::string&, int, const std::string& a, Terminal::Completion& r){ std::vector<std::string> opts = {"memory", "registers", "stack", "code", "watch", "breakpoints"}; for (const auto& o : opts) if (o.find(a) == 0) r.candidates.push_back(o); };
        m_command_registry.add({"view", "v"}, {[this](const std::string& s){ cmd_view(s); }, true, "target", "Switch view", {CommandRegistry::CTX_CUSTOM}, view_completer});
        m_command_registry.add({"analyze"}, {[this](const std::string&){ m_debugger.analyze(); }, false, "", "Run heuristic analysis from PC", {}});
    }
    ~Dashboard();
    void run();
    const CommandRegistry& get_command_registry() const { return m_command_registry; }

private:    
    enum Focus { FOCUS_MEMORY, FOCUS_REGS, FOCUS_STACK, FOCUS_CODE, FOCUS_WATCH, FOCUS_BREAKPOINTS, FOCUS_CMD, FOCUS_COUNT };
    Focus m_focus = FOCUS_CODE;
    Focus m_last_focus = FOCUS_CMD;

    Debugger& m_debugger;
    Theme m_theme;
    Theme m_default_theme;
    bool m_running = true;
    std::stringstream m_output_buffer;
    MemoryView m_memory_view;
    RegisterView m_register_view;
    StackView m_stack_view;
    CodeView m_code_view;
    WatchView m_watch_view;
    BreakpointView m_breakpoint_view;
    bool m_show_mem = true;
    bool m_show_regs = true;
    bool m_show_code = true;
    bool m_show_stack = true;
    bool m_show_watch = true;
    bool m_show_breakpoints = true;
    bool m_auto_follow = true;
    bool m_show_colors = true;
    bool m_show_autocompletion = true;
    bool m_show_bracket_highlight = true;
    bool m_wrap_comments = false;
    
    CommandRegistry m_command_registry;
    Terminal::LineEditor m_editor;
    Autocompletion m_autocompletion{ *this };
    Hint m_hint{ *this };
    
    void validate_focus();
    void handle_command(const std::string& input);
    void init();
    void print_separator() { std::cout << m_theme.separator << std::string(80, '-') << Terminal::RESET << "\n"; }
    void print_dashboard();
    void draw_prompt();
    void print_footer();
    void print_columns(const std::vector<std::string>& left, const std::vector<std::string>& right, size_t left_width);
    void print_output_buffer();
    void log(const std::string& msg) { m_output_buffer << msg << "\n"; }
    void update_code_view();
    void center_code_view(uint16_t addr);
    void update_stack_view();
    void update_theme();

    void cmd_evaluate(const std::string& args);
    void cmd_expression(const std::string& args);
    void cmd_expression_detailed(const std::string& args);
    void cmd_quit(const std::string& args);
    void cmd_set(const std::string& args);
    void cmd_undef(const std::string& args);
    void cmd_options(const std::string& args);
    void cmd_watch(const std::string& args);
    void cmd_break(const std::string& args);
    void cmd_break_smart(const std::string& args);
    void cmd_unwatch(const std::string& args);
    void cmd_watch_list(const std::string& args);
    void cmd_break_list(const std::string& args);
    void cmd_clear_watch(const std::string& args);
    void cmd_help(const std::string& args);
    void cmd_step(const std::string& args);
    void cmd_next(const std::string& args);
    void cmd_memory(const std::string& args);
    void cmd_code(const std::string& args);
    void cmd_view(const std::string& args);
    void cmd_trace(const std::string& args);
    void cmd_codemap(const std::string& args);
    void cmd_over(const std::string& args);
    void cmd_skip(const std::string& args);
    void cmd_label(const std::string& args);
    void cmd_mark(const std::string& args);
    
    void perform_evaluate(const std::string& expr, bool detailed);
    void perform_set(const std::string& args, bool detailed);
    std::string format(const Expression::Value& val, bool detailed = false, const std::string& expr = "");
    bool is_assignment(const std::string& expr);
    
    // Format helpers
    void format_detailed_number(std::stringstream& ss, const Expression::Value& val);
    void format_detailed_address(std::stringstream& ss, const Expression::Value& val);
    void format_detailed_collection(std::stringstream& ss, const Expression::Value& val);
    void format_variable_header(std::stringstream& ss, const Expression::Value& val, const std::string& expr);
    void print_asm_info(std::stringstream& ss, uint16_t addr);
    std::string format_disasm(uint16_t addr, const Z80Decoder<Memory>::CodeLine& line);
    void update_crc32(uint32_t& crc, uint8_t b);
    template <typename T> std::string format_instruction(const T& line);

    template <typename T> std::string format_sequence(const std::vector<T>& data, const std::string& prefix, const std::string& suffix, const std::string& separator, bool use_hex_prefix, bool allow_step_gt_1);
};

class DebugEngine : public Engine {
public:
    DebugEngine(Core& core, const Options& options) : m_core(core), m_options(options) {}
    virtual ~DebugEngine() = default;
    
    int run() override;

private:
    Core& m_core;
    const Options& m_options;
};

#endif // __DEBUGENGINE_H__