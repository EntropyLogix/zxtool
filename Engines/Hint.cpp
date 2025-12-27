#include "Hint.h"
#include "DebugEngine.h"
#include "../Utils/Strings.h"
#include "../Utils/Commands.h"
#include <utility>
#include <cctype>

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
        return ")";
    std::string func_upper = Strings::upper(func_name);
    const auto& funcs = Expression::get_functions();
    auto it = funcs.find(func_upper);
    if (it == funcs.end())
        return ")";
    const auto& func_info = it->second;
    Commands::ParamInfo info = Commands::analyze_params(input, opener_pos, func_info.num_args);
    if (func_info.num_args != -1 && info.count >= func_info.num_args) {
        hint_color = m_dashboard.m_theme.hint_error;
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

void Hint::update_cache(const std::string& input) {
    m_cached_brackets.clear();
    m_cached_unclosed.clear();
    m_cached_highlight = false;

    std::string trimmed_input = Strings::trim(input);
    if (!trimmed_input.empty()) {
        std::string best_cmd;
        for (const auto& pair : m_dashboard.m_commands) {
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
                    if (is_match && cmd.length() > best_cmd.length())
                        best_cmd = cmd;
                }
            }
        }

        if (!best_cmd.empty()) {
            std::string arguments_part = input.substr(best_cmd.length());
            const auto& entry = m_dashboard.m_commands.at(best_cmd);
            int parameter_index = 0;
            size_t current_argument_offset = 0;
            Commands::get_current_arg(arguments_part, parameter_index, current_argument_offset);
            
            Dashboard::CompletionType type = Dashboard::CTX_NONE;
            if (parameter_index < (int)entry.param_types.size())
                type = entry.param_types[parameter_index];
            else if (!entry.param_types.empty() && entry.param_types.back() == Dashboard::CTX_EXPRESSION)
                type = Dashboard::CTX_EXPRESSION;
            
            if (type == Dashboard::CTX_EXPRESSION)
                m_cached_highlight = true;
        }
    }

    if (m_cached_highlight) {
        std::vector<std::pair<char, int>> stack;
        bool in_quote = false;
        for (int i = 0; i < (int)input.length(); ++i) {
            char c = input[i];
            if (c == '"') {
                in_quote = !in_quote;
                continue;
            }
            if (in_quote) continue;
            if (c == '(' || c == '[' || c == '{') {
                stack.push_back({c, i});
            } else if (c == ')' || c == ']' || c == '}') {
                if (!stack.empty()) {
                    char open_c = stack.back().first;
                    int o_idx = stack.back().second;
                    bool match = (open_c == '(' && c == ')') || 
                                 (open_c == '[' && c == ']') || 
                                 (open_c == '{' && c == '}');
                    if (match) {
                        m_cached_brackets.push_back({o_idx, i});
                        stack.pop_back();
                    }
                }
            }
        }
        for (const auto& p : stack)
            m_cached_unclosed.push_back(p.second);
    }
}

std::string Hint::calculate(const std::string& input, int cursor_pos, std::string& color, int& error_pos, std::vector<int>& highlights) {
    if (input != m_last_input) {
        m_last_input = input;
        if (m_dashboard.m_show_bracket_highlight) update_cache(input);
    }

    if (m_cached_highlight) {
        bool found = false;
        for (const auto& pair : m_cached_brackets) {
            if (pair.first < cursor_pos && cursor_pos <= pair.second + 1) {
                if (input[pair.first] == '{' && pair.first > 0 && input[pair.first - 1] == 'W')
                    highlights.push_back(pair.first - 1);
                highlights.push_back(pair.first);
                highlights.push_back(pair.second);
                found = true;
                break;
            }
        }
        if (!found && !m_cached_unclosed.empty()) {
            for (auto it = m_cached_unclosed.rbegin(); it != m_cached_unclosed.rend(); ++it) {
                if (*it < cursor_pos) {
                    if (input[*it] == '{' && *it > 0 && input[*it - 1] == 'W')
                        highlights.push_back(*it - 1);
                    highlights.push_back(*it);
                    break;
                }
            }
        }
    }

    if (!m_dashboard.m_show_autocompletion) return "";

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
            if (hint.length() > 80) {
                hint += "..."; break; }
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