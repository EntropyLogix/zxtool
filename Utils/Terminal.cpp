#include "Terminal.h"

std::string Terminal::RESET = "\033[0m";
std::string Terminal::BOLD  = "\033[1m";
std::string Terminal::DIM   = "\033[2m";
std::string Terminal::CLEAR = "\033[H\033[2J\033[3J";

std::string Terminal::rgb_fg(uint8_t r, uint8_t g, uint8_t b) {
    return "\033[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}

std::string Terminal::rgb_bg(uint8_t r, uint8_t g, uint8_t b) {
    return "\033[48;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}