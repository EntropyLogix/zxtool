#include "Terminal.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

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

#ifdef _WIN32
static HANDLE hStdin;
static DWORD orig_mode;
static bool raw_enabled = false;
#else
static struct termios orig_termios;
static bool raw_enabled = false;
#endif

void Terminal::enable_raw_mode() {
    if (raw_enabled) return;
#ifdef _WIN32
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &orig_mode);
    DWORD mode = orig_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hStdin, mode);
#else
    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1) return;
    struct termios raw = orig_termios;
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0; 
    raw.c_cc[VTIME] = 1; 
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
#endif
    raw_enabled = true;
}

void Terminal::disable_raw_mode() {
    if (!raw_enabled) return;
#ifdef _WIN32
    SetConsoleMode(hStdin, orig_mode);
#else
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
#endif
    raw_enabled = false;
}

Terminal::Input Terminal::read_key() {
    Input input = {Key::NONE, 0};
#ifdef _WIN32
    if (_kbhit()) {
        int c = _getch();
        if (c == 0 || c == 0xE0) {
            int sc = _getch();
            switch (sc) {
                case 72: input.key = Key::UP; break;
                case 80: input.key = Key::DOWN; break;
                case 77: input.key = Key::RIGHT; break;
                case 75: input.key = Key::LEFT; break;
                case 71: input.key = Key::HOME; break;
                case 79: input.key = Key::END; break;
                case 83: input.key = Key::DEL; break;
            }
        } else {
            if (c == 8) input.key = Key::BACKSPACE;
            else if (c == 9) input.key = Key::TAB;
            else if (c == 13) input.key = Key::ENTER;
            else if (c == 27) input.key = Key::ESC;
            else {
                input.key = Key::CHAR;
                input.c = (char)c;
            }
        }
    }
#else
    char c;
    if (read(STDIN_FILENO, &c, 1) == 1) {
        if (c == '\x1b') {
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) {
                input.key = Key::ESC;
                return input;
            }
            if (read(STDIN_FILENO, &seq[1], 1) != 1) {
                input.key = Key::ESC;
                return input;
            }
            if (seq[0] == '[') {
                switch (seq[1]) {
                    case 'A': input.key = Key::UP; break;
                    case 'B': input.key = Key::DOWN; break;
                    case 'C': input.key = Key::RIGHT; break;
                    case 'D': input.key = Key::LEFT; break;
                    case 'H': input.key = Key::HOME; break;
                    case 'F': input.key = Key::END; break;
                    case '3': 
                        if (read(STDIN_FILENO, &c, 1) == 1 && c == '~') input.key = Key::DEL; 
                        break;
                }
            } else if (seq[0] == 'O') {
                switch (seq[1]) {
                    case 'H': input.key = Key::HOME; break;
                    case 'F': input.key = Key::END; break;
                }
            }
        } else if (c == 127) {
            input.key = Key::BACKSPACE;
        } else if (c == '\t') {
            input.key = Key::TAB;
        } else if (c == '\n' || c == '\r') {
            input.key = Key::ENTER;
        } else {
            input.key = Key::CHAR;
            input.c = c;
        }
    }
#endif
    return input;
}