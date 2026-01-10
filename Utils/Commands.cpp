#include "Commands.h"
#include "Strings.h"
#include <cctype>

void Commands::find_opener(const std::string& input, char& opener, size_t& opener_pos) {
    int depth_paren = 0;
    int depth_bracket = 0;
    int depth_brace = 0;
    opener = 0;
    opener_pos = std::string::npos;
    for (size_t i = input.length(); i > 0; --i) {
        char c = input[i-1];
        if (c == ')')
            depth_paren++;
        else if (c == ']')
            depth_bracket++;
        else if (c == '}')
            depth_brace++;
        else if (c == '(') {
            if (depth_paren > 0)
                depth_paren--;
            else {
                opener = '(';
                opener_pos = i - 1;
                break;
            }
        }
        else if (c == '[') {
            if (depth_bracket > 0)
                depth_bracket--;
            else {
                opener = '[';
                opener_pos = i-1;
                break;
            }
        }
        else if (c == '{') {
            if (depth_brace > 0)
                depth_brace--;
            else {
                opener = '{';
                opener_pos = i-1;
                break;
            }
        }
    }
}

Commands::ParamInfo Commands::analyze_params(const std::string& input, size_t opener_pos, int max_args) {
    ParamInfo info;
    info.last_comma_pos = opener_pos;
    int depth = 0;
    bool in_quote = false;
    for (size_t i = opener_pos + 1; i < input.length(); ++i) {
        char c = input[i];
        if (c == '"') {
            in_quote = !in_quote;
            continue;
        }
        if (in_quote) continue;
        if (c == '(' || c == '[' || c == '{')
            depth++;
        else if (c == ')' || c == ']' || c == '}')
            depth--;
        else if (c == ',' && depth == 0) {
            info.count++;
            if (max_args != -1 && info.count == max_args && info.error_comma_pos == std::string::npos)
                info.error_comma_pos = i;
            info.last_comma_pos = i;
        }
    }
    for (size_t i = info.last_comma_pos + 1; i < input.length(); ++i) {
        if (!std::isspace(static_cast<unsigned char>(input[i]))) {
            info.current_has_text = true;
            break;
        }
    }
    return info;
}

bool Commands::is_assignment(const std::string& expr) {
    int depth = 0;
    bool in_string = false;
    for (size_t i = 0; i < expr.length(); ++i) {
        char c = expr[i];
        if (in_string) {
            if (c == '"')
                in_string = false;
            continue;
        }
        if (c == '"') {
            in_string = true;
            continue;
        }
        if (c == '\'') {
            if (i + 2 < expr.length() && expr[i+2] == '\'')
                i += 2;
            continue;
        }
        if (c == '(' || c == '[' || c == '{')
            depth++;
        else if (c == ')' || c == ']' || c == '}')
            depth--;
        else if (c == '=' && depth == 0) {
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
            if (!is_cmp)
                return true;
        }
    }
    return false;
}

std::string Commands::find_preceding_word(const std::string& input, size_t pos) {
    if (pos == 0)
        return "";
    size_t end = Strings::find_last_non_space(input, pos - 1);
    if (end == std::string::npos)
        return "";
    size_t start = end;
    while (start > 0) {
        char c = input[start - 1];
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            break;
        start--;
    }
    return input.substr(start, end - start + 1);
}

void Commands::get_current_arg(const std::string& input, int& arg_index, size_t& arg_start) {
    arg_index = 0;
    arg_start = 0;
    size_t i = 0;
    while (i < input.length() && std::isspace(static_cast<unsigned char>(input[i])))
        i++;
    arg_start = i;
    bool in_quote = false;
    int bracket_depth = 0;
    for (; i < input.length(); ++i) {
        char c = input[i];
        if (c == '"') in_quote = !in_quote;
        else if (!in_quote) {
            if (c == '[' || c == '(' || c == '{')
                bracket_depth++;
            else if (c == ']' || c == ')' || c == '}') {
                if (bracket_depth > 0)
                    bracket_depth--;
            }
            else if (bracket_depth == 0) {
                if (std::isspace(static_cast<unsigned char>(c))) {
                    size_t next_start = i + 1;
                    while (next_start < input.length() && std::isspace(static_cast<unsigned char>(input[next_start])))
                        next_start++;
                    if (next_start == input.length()) {
                        arg_index++;
                        arg_start = next_start;
                        break;
                    }
                    arg_index++;
                    arg_start = next_start;
                    i = next_start - 1;
                }
            }
        }
    }
}

bool Commands::is_identifier(const std::string& s) {
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return false;
    }
    return true;
}

int Commands::find_matching_bracket(const std::string& input, int pos) {
    if (pos < 0 || pos >= (int)input.length()) return -1;
    
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
                char open = stack.back().first;
                int open_idx = stack.back().second;
                bool match = (open == '(' && c == ')') || (open == '[' && c == ']') || (open == '{' && c == '}');
                if (match) {
                    stack.pop_back();
                    if (open_idx == pos) return i;
                    if (i == pos) return open_idx;
                }
            }
        }
    }
    return -1;
}