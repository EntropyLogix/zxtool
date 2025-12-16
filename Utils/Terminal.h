#ifndef __TERMINAL_H__
#define __TERMINAL_H__

#include <string>
#include <cstdint>

class Terminal {
public:
    static std::string RESET;
    static std::string BOLD;
    static std::string DIM;
    static std::string COLOR_RED;
    static std::string COLOR_GREEN;
    static std::string COLOR_YELLOW;
    static std::string COLOR_BLUE;
    static std::string COLOR_MAGENTA;
    static std::string COLOR_CYAN;
    static std::string COLOR_WHITE;
    static std::string COLOR_GRAY;
    static std::string COLOR_HI_RED;
    static std::string COLOR_HI_GREEN;
    static std::string COLOR_HI_YELLOW;
    static std::string COLOR_HI_BLUE;
    static std::string COLOR_HI_MAGENTA;
    static std::string COLOR_HI_CYAN;
    static std::string COLOR_HI_WHITE;
    static std::string COLOR_BG_DARK_GRAY;
    static std::string CLEAR;

    static std::string rgb_fg(uint8_t r, uint8_t g, uint8_t b);
    static std::string rgb_bg(uint8_t r, uint8_t g, uint8_t b);
};

#endif // __TERMINAL_H__