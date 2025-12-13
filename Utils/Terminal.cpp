#include "Terminal.h"
#include "Strings.h"
#include <iostream>

std::string Terminal::RESET   = "\033[0m";
std::string Terminal::BOLD    = "\033[1m";
std::string Terminal::DIM     = "\033[2m";
std::string Terminal::RED     = "\033[31m";
std::string Terminal::GREEN   = "\033[32m";
std::string Terminal::YELLOW  = "\033[33m";
std::string Terminal::BLUE    = "\033[34m";
std::string Terminal::MAGENTA = "\033[35m";
std::string Terminal::CYAN    = "\033[36m";
std::string Terminal::WHITE   = "\033[37m";
std::string Terminal::GRAY    = "\033[90m";
std::string Terminal::HI_RED     = "\033[91m";
std::string Terminal::HI_GREEN   = "\033[92m";
std::string Terminal::HI_YELLOW  = "\033[93m";
std::string Terminal::HI_BLUE    = "\033[94m";
std::string Terminal::HI_MAGENTA = "\033[95m";
std::string Terminal::HI_CYAN    = "\033[96m";
std::string Terminal::HI_WHITE   = "\033[97m";
std::string Terminal::BG_DARK_GRAY = "\033[100m";

void Terminal::clear() {
    std::cout << "\033[H\033[2J\033[3J";
}

std::string Terminal::yellow(const std::string& s) {
    return "\033[1;33m" + s + "\033[0m";
}

void Terminal::print_byte_smart(uint8_t b) {
    if (b == 0) {
        std::cout << GRAY << "00" << RESET;
    } else {
        std::cout << HI_WHITE << Strings::hex8(b) << RESET;
    }
}