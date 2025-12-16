#ifndef __STRINGS_H__
#define __STRINGS_H__

#include <string>
#include <cstdint>

class Strings {
public:
    template <typename T> static std::string format_hex(T value, int width);
    static std::string hex8(uint8_t v);
    static std::string hex16(uint16_t v);
    static size_t length(const std::string& s, bool visible = true);
    static std::string padding(const std::string& s, size_t width, char fill = ' ');
    static std::string truncate(const std::string& s, size_t width);
    static bool parse_integer(const std::string& s, int32_t& out_value);
    static bool parse_double(const std::string& s, double& out_value);
};

#endif//__STRINGS_H__