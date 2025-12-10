#ifndef __STRINGS_H__
#define __STRINGS_H__

#include <string>
#include <cstdint>

class Strings {
public:
    template <typename T> static std::string format_hex(T value, int width);
};

#endif//__STRINGS_H__