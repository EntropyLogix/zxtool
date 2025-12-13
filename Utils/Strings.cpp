#include "Strings.h"
#include <sstream>
#include <iomanip>
#include <type_traits>

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

size_t Strings::ansi_len(const std::string& s) {
    size_t len = 0;
    bool in_esc = false;
    for (char c : s) {
        if (c == '\033') in_esc = true;
        else if (in_esc && c == 'm') in_esc = false;
        else if (!in_esc) len++;
    }
    return len;
}

std::string Strings::pad_ansi(const std::string& s, size_t width, char fill) {
    size_t vis = ansi_len(s);
    if (vis >= width) return s;
    return s + std::string(width - vis, fill);
}