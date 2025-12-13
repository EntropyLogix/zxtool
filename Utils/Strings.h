#ifndef __STRINGS_H__
#define __STRINGS_H__

#include <string>
#include <cstdint>

class Strings {
public:
    template <typename T> static std::string format_hex(T value, int width);
    static std::string hex8(uint8_t v);
    static std::string hex16(uint16_t v);
    static size_t ansi_len(const std::string& s);
    static std::string pad_ansi(const std::string& s, size_t width, char fill = ' ');
};

#endif//__STRINGS_H__