#include "Autocompletion.h"
#include "DebugEngine.h"
#include "../Utils/Strings.h"
#include "../Utils/Commands.h"

Autocompletion::Autocompletion(Dashboard& dashboard) : m_dashboard(dashboard) {}

std::string Autocompletion::find_matching_command(const std::string& input) {
    std::string best_match;
    const auto& cmds = m_dashboard.get_command_registry().get_commands();
    for (const auto& pair : cmds) {
        const std::string& cmd = pair.first;
        bool is_alnum = Commands::is_identifier(cmd);
        bool require_separator = is_alnum;
        if (input.length() >= cmd.length()) {
            if (input.compare(0, cmd.length(), cmd) == 0) {
                bool is_match = false;
                if (require_separator) {
                    if (input.length() > cmd.length() && std::isspace(static_cast<unsigned char>(input[cmd.length()])))
                        is_match = true;
                } else
                    is_match = true;
                if (is_match && cmd.length() > best_match.length())
                    best_match = cmd;
            }
        }
    }
    return best_match;
}

void Autocompletion::complete_expression(const std::string& full_input, const std::string& arguments_part, size_t current_argument_offset, Terminal::Completion& result) {
    static constexpr const char* SEPARATORS = " \t,()[]{}+-*/%^&|~<>!=:";
    result.is_custom_context = true;
    std::string current_argument = arguments_part.substr(current_argument_offset);
    size_t last_separator_pos = current_argument.find_last_of(SEPARATORS);
    size_t prefix_start_index = (last_separator_pos == std::string::npos) ? 0 : last_separator_pos + 1;
    std::string prefix_before_trim = current_argument.substr(prefix_start_index);
    size_t command_length = full_input.length() - arguments_part.length();
    result.prefix = Strings::trim(prefix_before_trim);
    result.replace_pos = (int)(command_length + current_argument_offset + prefix_start_index + (prefix_before_trim.length() - result.prefix.length()));
    if (result.prefix.empty())
        result.replace_pos = (int)full_input.length();
    bool expect_term = true;
    if (prefix_start_index > 0) {
        size_t last_char_pos = Strings::find_last_non_space(current_argument, prefix_start_index - 1);
        if (last_char_pos != std::string::npos) {
            char c = current_argument[last_char_pos];
            if (c == ')' || c == ']' || c == '}')
                expect_term = false;
        }
    }
    if (expect_term) {
        std::string prefix_upper = Strings::upper(result.prefix);
        for (const auto& pair : Expression::get_functions()) {
            if (Strings::upper(pair.first).find(prefix_upper) == 0)
                result.candidates.push_back(pair.first);
        }
        for (const auto& r : Register::get_names()) {
            if (Strings::upper(r).find(prefix_upper) == 0)
                result.candidates.push_back(r);
        }
        if (!result.prefix.empty() && result.prefix[0] == '@') {
            auto& vars = m_dashboard.m_debugger.get_core().get_context().getVariables();
            for (const auto& pair : vars.by_name()) {
                std::string var_name = (pair.second.isSystem() ? "@@" : "@") + pair.first;
                std::string var_upper = Strings::upper(var_name);
                if (var_upper.find(prefix_upper) == 0)
                    result.candidates.push_back(var_name);
            }
        }
        auto& symbols = m_dashboard.m_debugger.get_core().get_context().getSymbols();
        for (const auto& pair : symbols.by_name()) {
            std::string sym_upper = Strings::upper(pair.first);
            if (sym_upper.find(prefix_upper) == 0)
                result.candidates.push_back(pair.first);
        }
    }
}

void Autocompletion::complete_symbol(const std::string& full_input, const std::string& arguments_part, size_t current_argument_offset, Terminal::Completion& result) {
    result.is_custom_context = true;
    std::string current_argument = arguments_part.substr(current_argument_offset);
    result.prefix = Strings::trim(current_argument);
    size_t command_length = full_input.length() - arguments_part.length();
    result.replace_pos = (int)(command_length + current_argument_offset);    
    std::string prefix_upper = Strings::upper(result.prefix);
    auto& symbols = m_dashboard.m_debugger.get_core().get_context().getSymbols();
    for (const auto& pair : symbols.by_name()) {
        if (Strings::upper(pair.first).find(prefix_upper) == 0)
            result.candidates.push_back(pair.first);
    }
    auto& vars = m_dashboard.m_debugger.get_core().get_context().getVariables();
    for (const auto& pair : vars.by_name()) {
        std::string var_name = (pair.second.isSystem() ? "@@" : "@") + pair.first;
        if (Strings::upper(var_name).find(prefix_upper) == 0)
            result.candidates.push_back(var_name);
    }
}

void Autocompletion::complete_command_name(const std::string& input, Terminal::Completion& result) {
    std::string trimmed_input = Strings::trim(input);
    size_t first_non_space = Strings::find_first_non_space(input);
    if (first_non_space == std::string::npos)
        first_non_space = 0;
    result.replace_pos = (int)first_non_space;
    result.prefix = trimmed_input;
    const auto& cmds = m_dashboard.get_command_registry().get_commands();
    for (const auto& pair : cmds) {
        const std::string& cmd = pair.first;
        if (cmd.find(trimmed_input) == 0)
            result.candidates.push_back(cmd);
    }
}

void Autocompletion::complete_options(const std::string& full_input, int param_index, const std::string& arg_full, Terminal::Completion& result) {
    std::string prefix = Strings::trim(arg_full);
    result.prefix = prefix;
    if (param_index == 0) {
        std::vector<std::string> opts = {"colors", "autocompletion", "bracketshighlight", "comments"};
        for (const auto& o : opts)
            if (o.find(prefix) == 0)
                result.candidates.push_back(o);
    } else if (param_index == 1) {
        std::vector<std::string> opts = {"on", "off", "wrap", "truncate"};
        for (const auto& o : opts) {
            if (o.find(prefix) == 0)
                result.candidates.push_back(o);
        }
    }
}

Terminal::Completion Autocompletion::get(const std::string& input) {
    Terminal::Completion result;
    std::string trimmed_input = Strings::trim(input);
    if (trimmed_input.empty())
        return result;
    std::string matched_command = find_matching_command(input);
    if (!matched_command.empty()) {
        std::string arguments_part = input.substr(matched_command.length());
        const auto& registry = m_dashboard.get_command_registry();
        const auto& entry = registry.get_commands().at(matched_command);
        int parameter_index = 0;
        size_t current_argument_offset = 0;
        Commands::get_current_arg(arguments_part, parameter_index, current_argument_offset);
        CommandRegistry::CompletionType type = registry.resolve_type(matched_command, parameter_index, arguments_part);

        if (type == CommandRegistry::CTX_EXPRESSION)
            complete_expression(input, arguments_part, current_argument_offset, result);
        else if (type == CommandRegistry::CTX_SYMBOL)
            complete_symbol(input, arguments_part, current_argument_offset, result);
        else if (type == CommandRegistry::CTX_SUBCOMMAND) {
            result.is_custom_context = true;
            std::string current_argument = arguments_part.substr(current_argument_offset);
            result.replace_pos = (int)(matched_command.length() + current_argument_offset);
            result.prefix = current_argument;
            std::vector<std::string> candidates = registry.get_subcommand_candidates(matched_command, parameter_index, arguments_part);
            for (const auto& c : candidates) {
                if (c.find(result.prefix) == 0)
                    result.candidates.push_back(c);
            }
        }
        else if (type == CommandRegistry::CTX_CUSTOM && entry.custom_completer) {
            result.is_custom_context = true;
            std::string current_argument = arguments_part.substr(current_argument_offset);
            result.replace_pos = (int)(matched_command.length() + current_argument_offset);
            result.prefix = current_argument;
            entry.custom_completer(input, parameter_index, current_argument, result);
        }
    } else
        complete_command_name(input, result);
    std::sort(result.candidates.begin(), result.candidates.end(), [](const std::string& a, const std::string& b) {
        std::string ua = Strings::upper(a);
        std::string ub = Strings::upper(b);
        if (ua != ub)
            return ua < ub;
        return a < b;
    });
    result.candidates.erase(std::unique(result.candidates.begin(), result.candidates.end()), result.candidates.end());
    return result;
}