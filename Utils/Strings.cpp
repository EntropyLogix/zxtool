#include "Strings.h"
#include <sstream>
#include <iomanip>
#include <charconv>
#include <algorithm>
#include <cctype>
#include <vector>
#include <utility>

std::string Strings::hex(uint8_t v) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)v;
    return ss.str();
}

std::string Strings::hex(uint16_t v) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << (int)v;
    return ss.str();
}

std::string Strings::hex(uint64_t v, int bit_width) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    if (bit_width == 8)
        ss << std::setw(2) << (v & 0xFF);
    else if (bit_width == 16)
        ss << std::setw(4) << (v & 0xFFFF);
    else if (bit_width == 32)
        ss << std::setw(8) << (v & 0xFFFFFFFF);
    else
        ss << std::setw(16) << v;
    return ss.str();
}

std::string Strings::bin(uint8_t v) {
    char buffer[9];
    buffer[8] = '\0';
    for (int i = 0; i < 8; ++i) {
        buffer[7 - i] = (v & 1) ? '1' : '0';
        v >>= 1;
    }
    return std::string(buffer);
}

std::string Strings::bin(uint16_t v) {
    char buffer[17];
    buffer[16] = '\0';
    for (int i = 0; i < 16; ++i) {
        buffer[15 - i] = (v & 1) ? '1' : '0';
        v >>= 1;
    }
    return std::string(buffer);
}

std::string Strings::bin(uint64_t v, int bit_width) {
    std::string b;
    for (int i = bit_width - 1; i >= 0; --i) {
        b += ((v >> i) & 1) ? '1' : '0';
        if (i > 0 && i % 8 == 0)
            b += " ";
    }
    return b;
}

size_t Strings::length(const std::string& s, bool visible) {
    if (!visible) return s.length();
    size_t len = 0;
    bool in_esc = false;
    for (char c : s) {
        if (c == '\033')
            in_esc = true;
        if (in_esc) {
            if (c == 'm' || c == 'K')
                in_esc = false;
        } else
            len++;
    }
    return len;
}

std::string Strings::padding(const std::string& s, size_t width, char fill) {
    size_t vis = length(s);
    if (vis >= width)
        return s;
    return s + std::string(width - vis, fill);
}

std::string Strings::truncate(const std::string& s, size_t width) {
    if (length(s) <= width)
        return s;
    size_t target_len = (width > 3) ? width - 3 : 0;
    std::string clipped;
    size_t visible = 0;
    bool in_esc = false;
    for (char c : s) {
        if (c == '\033')
            in_esc = true;
        if (in_esc) {
            clipped += c;
            if (c == 'm' || c == 'K')
                in_esc = false;
        } else {
            if (visible < target_len) {
                clipped += c;
                visible++;
            } else
                break;
        }
    }
    return clipped + "\033[0m...";
}

bool Strings::parse_integer(const std::string& s, int32_t& out_value) {
    std::string str = s;
    const char* whitespace = " \t";
    str.erase(0, str.find_first_not_of(whitespace));
    str.erase(str.find_last_not_of(whitespace) + 1);
    if (str.empty())
        return false;
    const char* start = str.data();
    const char* end = str.data() + str.size();
    bool is_negative = false;
    if (start < end && *start == '-') {
        is_negative = true;
        start++;
    } else if (start < end && *start == '+')
        start++;
    int base = 10;
    if ((end - start) > 2 && (*start == '0' && (*(start + 1) == 'x' || *(start + 1) == 'X'))) {
        start += 2;
        base = 16;
    } else if ((end - start) > 2 && (*start == '0' && (*(start + 1) == 'b' || *(start + 1) == 'B'))) {
        start += 2;
        base = 2;
    } else if ((end - start) > 1 && *start == '$') {
        start += 1;
        base = 16;
    } else if ((end - start) > 1 && *start == '%') {
        start += 1;
        base = 2;
    } else if ((end - start) > 0) {
        char last_char = *(end - 1);
        if (last_char == 'H' || last_char == 'h') {
            end -= 1;
            base = 16;
        } else if (last_char == 'B' || last_char == 'b') {
            end -= 1;
            base = 2;
        }
    }
    if (start == end)
        return false;
    auto result = std::from_chars(start, end, out_value, base);
    bool success = (result.ec == std::errc() && result.ptr == end);
    if (success && is_negative)
        out_value = -out_value;
    return success;
}

bool Strings::parse_double(const std::string& s, double& out_value) {
    int32_t i_val;
    if (parse_integer(s, i_val)) {
        out_value = static_cast<double>(i_val);
        return true;
    }
    std::string str = s;
    const char* whitespace = " \t";
    str.erase(0, str.find_first_not_of(whitespace));
    str.erase(str.find_last_not_of(whitespace) + 1);
    if (str.empty())
        return false;
    try {
        size_t idx;
        out_value = std::stod(str, &idx);
        return idx == str.length();
    } catch (...) {
        return false;
    }
}

std::string Strings::upper(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),[](unsigned char c){ return std::toupper(c); });
    return result;
}

std::string Strings::lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c){ return std::tolower(c); });
    return result;
}

std::string Strings::trim(const std::string& s) {
    auto start = std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); });
    auto end = std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base();
    return (start < end) ? std::string(start, end) : "";
}

std::vector<std::string> Strings::split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        if (!token.empty())
            tokens.push_back(token);
    }
    return tokens;
}

std::pair<std::string, std::string> Strings::split_once(const std::string& s, char delimiter) {
    size_t pos = s.find(delimiter);
    if (pos == std::string::npos)
        return {s, ""};
    return {s.substr(0, pos), s.substr(pos + 1)};
}

std::pair<std::string, std::string> Strings::split_once(const std::string& s, const std::string& delimiters) {
    size_t pos = s.find_first_of(delimiters);
    if (pos == std::string::npos)
        return {s, ""};
    return {s.substr(0, pos), s.substr(pos + 1)};
}

void Strings::find_opener(const std::string& input, char& opener, size_t& opener_pos) {
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

Strings::ParamInfo Strings::analyze_params(const std::string& input, size_t opener_pos, int max_args) {
    ParamInfo info;
    info.last_comma_pos = opener_pos;
    int depth = 0;
    for (size_t i = opener_pos + 1; i < input.length(); ++i) {
        char c = input[i];
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

bool Strings::is_assignment(const std::string& expr) {
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

std::string Strings::find_preceding_word(const std::string& input, size_t pos) {
    if (pos == 0)
        return "";
    size_t end = find_last_non_space(input, pos - 1);
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

bool Strings::is_identifier(const std::string& s) {
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return false;
    }
    return true;
}

size_t Strings::find_first_non_space(const std::string& s, size_t pos) {
    return s.find_first_not_of(" \t", pos);
}

size_t Strings::find_last_non_space(const std::string& s, size_t pos) {
    return s.find_last_not_of(" \t", pos);
}