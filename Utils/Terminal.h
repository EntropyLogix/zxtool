#ifndef __TERMINAL_H__
#define __TERMINAL_H__

#include <string>
#include <cstdint>

class Terminal {
public:
    static std::string RESET;
    static std::string BOLD;
    static std::string DIM;
    static std::string RED;
    static std::string GREEN;
    static std::string YELLOW;
    static std::string BLUE;
    static std::string MAGENTA;
    static std::string CYAN;
    static std::string WHITE;
    static std::string GRAY;
    static std::string HI_RED;
    static std::string HI_GREEN;
    static std::string HI_YELLOW;
    static std::string HI_BLUE;
    static std::string HI_MAGENTA;
    static std::string HI_CYAN;
    static std::string HI_WHITE;
    static std::string BG_DARK_GRAY;

    static void clear();
    static std::string yellow(const std::string& s);
    static void print_byte_smart(uint8_t b);
};

#endif // __TERMINAL_H__