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

    enum class Key {
        NONE,
        CHAR,
        UP, DOWN, LEFT, RIGHT,
        HOME, END,
        BACKSPACE, DEL,
        TAB,
        ENTER,
        ESC
    };

    struct Input {
        Key key;
        char c;
    };

    static void enable_raw_mode();
    static void disable_raw_mode();
    static Input read_key();
    static bool kbhit();
};

#endif // __TERMINAL_H__