#include "Hint.h"
#include "DebugEngine.h"
#include "../Utils/Strings.h"
#include "../Utils/Commands.h"

Hint::Hint(Dashboard& dashboard) : m_dashboard(dashboard) {}

std::string Hint::get_collection_hint(const std::string& input, const Commands::ParamInfo& info, char opener, const std::string& type_prefix) {
    char closer = (opener == '[') ? ']' : '}';
    std::string range_marker = (opener == '}') ? "end}" : "end]";
    if (info.count == 0) {
        if (!info.current_has_text)
            return type_prefix + " | start..end" + closer;
        size_t range_op = input.find("..", info.last_comma_pos + 1);
        if (range_op != std::string::npos) {
            bool has_end_val = false;
            for (size_t k = range_op + 2; k < input.length(); ++k) {
                 if (!std::isspace(static_cast<unsigned char>(input[k]))) {
                     has_end_val = true;
                     break;
                 }
            }
            return has_end_val ? std::string(1, closer) : range_marker;
        }
    }
    std::string hint;
    if (!info.current_has_text)
        hint += "..." + std::string(1, closer);
    else
        hint += closer;
    return hint;
}

std::string Hint::get_command_syntax_hint(const std::string& input) {
    auto parts = Strings::split_once(input, " \t");
    if (parts.first.length() < input.length()) {
        std::string command_name = parts.first;
        auto command_iterator = m_dashboard.m_commands.find(command_name);
        if (command_iterator != m_dashboard.m_commands.end() && !command_iterator->second.syntax.empty()) {
            std::string arguments = parts.second;
            bool is_whitespace_only = arguments.empty() || std::all_of(arguments.begin(), arguments.end(), [](unsigned char c){ return std::isspace(c); });
            if (is_whitespace_only)
                return command_iterator->second.syntax;
        }
    }
    return "";
}

std::string Hint::get_completion_hint(const Terminal::Completion& completion) {
    if (!completion.candidates.empty() && !completion.prefix.empty()) {
        const std::string& best_candidate = completion.candidates[0];
        std::string best_lower = Strings::lower(best_candidate);
        std::string prefix_lower = Strings::lower(completion.prefix);
        if (best_lower.find(prefix_lower) == 0) {
            if (best_candidate.length() > completion.prefix.length())
                return best_candidate.substr(completion.prefix.length());
        }
    }
    return "";
}

std::string Hint::get_operator_hint(const std::string& input) {
    size_t last_char_pos = Strings::find_last_non_space(input);
    if (last_char_pos != std::string::npos) {
        char last_char = input[last_char_pos];
        if (last_char == 'x') {
            size_t prev_pos = Strings::find_last_non_space(input, last_char_pos - 1);
            if (prev_pos != std::string::npos) {
                char prev_char = input[prev_pos];
                if (prev_char == ']' || prev_char == '}') {
                    return " count";
                }
            }
        }
    }
    return "";
}

std::string Hint::get_function_hint(const std::string& input, size_t opener_pos, std::string& hint_color, int& error_pos) {
    std::string func_name = Commands::find_preceding_word(input, opener_pos);
    if (func_name.empty())
        return "";
    std::string func_upper = Strings::upper(func_name);
    const auto& funcs = Expression::get_functions();
    auto it = funcs.find(func_upper);
    if (it == funcs.end())
        return "";
    const auto& func_info = it->second;
    Commands::ParamInfo info = Commands::analyze_params(input, opener_pos, func_info.num_args);
    if (func_info.num_args != -1 && info.count >= func_info.num_args) {
        hint_color = Terminal::rgb_fg(255, 100, 100);
        error_pos = (info.error_comma_pos != std::string::npos) ? (int)info.error_comma_pos : (int)opener_pos;
        return ")";
    }
    std::vector<std::string> param_list = Strings::split(func_info.params, ',');
    for(auto& p : param_list)
        p = Strings::trim(p);
    bool is_variadic = false;
    if (!param_list.empty() && param_list.back() == "...") {
        is_variadic = true;
        param_list.pop_back();
    }
    std::string hint;
    if (info.count < (int)param_list.size()) {
        if (!info.current_has_text)
            hint += param_list[info.count];
        for (size_t k = info.count + 1; k < param_list.size(); ++k)
            hint += ", " + param_list[k];
        if (is_variadic)
            hint += ", ...";
    } else {
        if (is_variadic && !info.current_has_text)
            hint += "...";
    }
    return hint + ")";
}

std::string Hint::get_context_hint(const std::string& input, std::string& hint_color, int& error_pos) {
    char opener = 0;
    size_t opener_pos = std::string::npos;
    Commands::find_opener(input, opener, opener_pos);
    if (opener_pos == std::string::npos)
        return "";
    if (opener == '(') {
        return get_function_hint(input, opener_pos, hint_color, error_pos);
    } else if (opener == '[') {
        Commands::ParamInfo info = Commands::analyze_params(input, opener_pos);
        return get_collection_hint(input, info, '[', "addr");
    } else if (opener == '{') {
        bool is_word = (opener_pos > 0 && input[opener_pos-1] == 'W');
        std::string type = is_word ? "word" : "byte";
        Commands::ParamInfo info = Commands::analyze_params(input, opener_pos);
        return get_collection_hint(input, info, '{', type);
    }
    return "";
}

std::string Hint::calculate(const std::string& input, std::string& color, int& error_pos) {
    Terminal::Completion completion_result = m_dashboard.m_autocompletion.get(input);
    std::string completion_hint = get_completion_hint(completion_result);
    if (!completion_result.is_custom_context) {
        if (!completion_hint.empty())
            return completion_hint;
        return get_command_syntax_hint(input);
    }
    if (completion_result.is_custom_context && completion_result.prefix.empty() && !completion_result.candidates.empty() && completion_result.candidates.size() <= 10) {
        std::string hint;
        for(size_t i=0; i<completion_result.candidates.size(); ++i) {
            if (i > 0)
                hint += "|";
            hint += completion_result.candidates[i];
            if (hint.length() > 30)
                hint += "..."; break;
        }
        return hint;
    }
    std::string operator_hint = get_operator_hint(input);
    std::string context_hint = get_context_hint(input, color, error_pos);
    if (!operator_hint.empty()) {
        if (context_hint == ")" || context_hint == "]" || context_hint == "}")
            return operator_hint + context_hint;
        return operator_hint;
    }
    if (!completion_hint.empty()) {
        if (context_hint == ")" || context_hint == "]" || context_hint == "}")
            return completion_hint + context_hint;
        return completion_hint;
    }
    if (!context_hint.empty())
        return context_hint;
    return get_command_syntax_hint(input);
}