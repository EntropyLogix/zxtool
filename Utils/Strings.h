#ifndef __STRINGS_H__
#define __STRINGS_H__

#include <string>
#include <cstdint>

class Strings {
public:
    static std::string hex(uint8_t v);
    static std::string hex(uint16_t v);
    static std::string bin(uint8_t v);
    static std::string bin(uint16_t v);

    static size_t length(const std::string& s, bool visible = true);
    static std::string padding(const std::string& s, size_t width, char fill = ' ');
    static std::string truncate(const std::string& s, size_t width);
    static std::string upper(const std::string& s);

    static bool parse_integer(const std::string& s, int32_t& out_value);
    static bool parse_double(const std::string& s, double& out_value);
    static void trim(std::string& s);
};

#endif//__STRINGS_H__