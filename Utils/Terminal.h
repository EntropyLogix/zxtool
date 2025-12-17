#ifndef __TERMINAL_H__
#define __TERMINAL_H__

#include <string>
#include <cstdint>

class Terminal {
public:
    static std::string RESET;
    static std::string BOLD;
    static std::string DIM;
    static std::string CLEAR;

    static std::string rgb_fg(uint8_t r, uint8_t g, uint8_t b);
    static std::string rgb_bg(uint8_t r, uint8_t g, uint8_t b);
};

#endif // __TERMINAL_H__