#include "Terminal.h"
#include <iostream>

std::string Terminal::RESET   = "\033[0m";
std::string Terminal::BOLD    = "\033[1m";
std::string Terminal::DIM     = "\033[2m";
std::string Terminal::CLEAR      = "\033[H\033[2J\033[3J";

std::string Terminal::COLOR_RED     = "\033[31m";
std::string Terminal::COLOR_GREEN   = "\033[32m";
std::string Terminal::COLOR_YELLOW  = "\033[33m";
std::string Terminal::COLOR_BLUE    = "\033[34m";
std::string Terminal::COLOR_MAGENTA = "\033[35m";
std::string Terminal::COLOR_CYAN    = "\033[36m";
std::string Terminal::COLOR_WHITE   = "\033[37m";
std::string Terminal::COLOR_GRAY    = "\033[90m";
std::string Terminal::COLOR_HI_RED     = "\033[91m";
std::string Terminal::COLOR_HI_GREEN   = "\033[92m";
std::string Terminal::COLOR_HI_YELLOW  = "\033[93m";
std::string Terminal::COLOR_HI_BLUE    = "\033[94m";
std::string Terminal::COLOR_HI_MAGENTA = "\033[95m";
std::string Terminal::COLOR_HI_CYAN    = "\033[96m";
std::string Terminal::COLOR_HI_WHITE   = "\033[97m";
std::string Terminal::COLOR_BG_DARK_GRAY = "\033[100m";

std::string Terminal::rgb_fg(uint8_t r, uint8_t g, uint8_t b) {
    return "\033[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}

std::string Terminal::rgb_bg(uint8_t r, uint8_t g, uint8_t b) {
    return "\033[48;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}