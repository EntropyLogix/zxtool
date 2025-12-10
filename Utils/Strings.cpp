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