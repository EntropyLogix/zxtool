#include "Strings.h"
#include <sstream>
#include <iomanip>
#include <type_traits>
#include <charconv>

template <typename T>
std::string Strings::format_hex(T value, int width) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(width);
    if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t>) {
        ss << static_cast<unsigned int>(value);
    } else {
        ss << value;
    }
    return ss.str();
}

template std::string Strings::format_hex<uint16_t>(uint16_t, int);
template std::string Strings::format_hex<int>(int, int);
template std::string Strings::format_hex<uint8_t>(uint8_t, int);

std::string Strings::hex8(uint8_t v) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)v;
    return ss.str();
}

std::string Strings::hex16(uint16_t v) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << (int)v;
    return ss.str();
}

size_t Strings::length(const std::string& s, bool visible) {
    if (!visible) return s.length();
    size_t len = 0;
    bool in_esc = false;
    for (char c : s) {
        if (c == '\033') in_esc = true;
        else if (in_esc && c == 'm') in_esc = false;
        else if (!in_esc) len++;
    }
    return len;
}

std::string Strings::padding(const std::string& s, size_t width, char fill) {
    size_t vis = length(s);
    if (vis >= width) return s;
    return s + std::string(width - vis, fill);
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
    if (str.empty()) return false;

    try {
        size_t idx;
        out_value = std::stod(str, &idx);
        return idx == str.length();
    } catch (...) {
        return false;
    }
}