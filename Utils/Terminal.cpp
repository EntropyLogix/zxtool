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
    if (raw_enabled)
        return;
#ifdef _WIN32
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &orig_mode);
    DWORD mode = orig_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(hStdin, mode);
#else
    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1)
        return;
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
    if (!raw_enabled)
        return;
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
                case 72:
                    input.key = Key::UP;
                    break;
                case 80:
                    input.key = Key::DOWN;
                    break;
                case 77:
                    input.key = Key::RIGHT;
                    break;
                case 75:
                    input.key = Key::LEFT;
                    break;
                case 71:
                    input.key = Key::HOME;
                    break;
                case 79:
                    input.key = Key::END;
                    break;
                case 83:
                    input.key = Key::DEL;
                    break;
            }
        } else {
            if (c == 8)
                input.key = Key::BACKSPACE;
            else if (c == 9) {
                if (GetKeyState(VK_SHIFT) & 0x8000)
                    input.key = Key::SHIFT_TAB;
                else
                    input.key = Key::TAB;
            }
            else if (c == 13)
                input.key = Key::ENTER;
            else if (c == 27)
                input.key = Key::ESC;
            else {
                input.key = Key::CHAR;
                input.c = (char)c;
            }
        }
    } else
        Sleep(10);
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
                    case 'A':
                        input.key = Key::UP;
                        break;
                    case 'B':
                        input.key = Key::DOWN;
                        break;
                    case 'C':
                        input.key = Key::RIGHT;
                        break;
                    case 'D':
                        input.key = Key::LEFT;
                        break;
                    case 'H':
                        input.key = Key::HOME;
                        break;
                    case 'F':
                        input.key = Key::END;
                        break;
                    case '3': 
                        if (read(STDIN_FILENO, &c, 1) == 1 && c == '~')
                            input.key = Key::DEL; 
                        break;
                    case 'Z':
                        input.key = Key::SHIFT_TAB;
                        break;
                }
            } else if (seq[0] == 'O') {
                switch (seq[1]) {
                    case 'H':
                        input.key = Key::HOME;
                        break;
                    case 'F':
                        input.key = Key::END;
                        break;
                }
            }
        } else if (c == 127)
            input.key = Key::BACKSPACE;
        else if (c == '\t')
            input.key = Key::TAB;
        else if (c == '\n' || c == '\r')
            input.key = Key::ENTER;
        else {
            input.key = Key::CHAR;
            input.c = c;
        }
    }
#endif
    return input;
}

Terminal::LineEditor::LineEditor() {
    m_hint_color = Terminal::DIM;
}

void Terminal::LineEditor::history_load(const std::string& filename) {
    if (FILE* f = fopen(filename.c_str(), "r")) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), f)) {
            std::string s(buf);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
                s.pop_back();
            if (!s.empty())
                m_history.push_back(s);
        }
        fclose(f);
    }
}

void Terminal::LineEditor::history_save(const std::string& filename) {
    if (FILE* f = fopen(filename.c_str(), "w")) {
        for(const auto& h : m_history)
            fprintf(f, "%s\n", h.c_str());
        fclose(f);
    }
}

void Terminal::LineEditor::history_add(const std::string& line) {
    if (!line.empty()) {
        if (m_history.empty() || m_history.back() != line)
            m_history.push_back(line);
    }
    m_history_pos = -1;
}

void Terminal::LineEditor::set_completion_callback(CompletionCallback cb) {
    m_completion_cb = cb;
}

void Terminal::LineEditor::set_hint_callback(HintCallback cb) {
    m_hint_cb = cb;
}

void Terminal::LineEditor::update_hint() {
    if (m_hint_cb)
        m_current_hint = m_hint_cb(m_buffer, m_hint_color, m_error_pos);
    else
        m_current_hint.clear();
}

void Terminal::LineEditor::clear() {
    m_buffer.clear();
    m_cursor_pos = 0;
    m_current_hint.clear();
    m_error_pos = -1;
    m_last_completion.candidates.clear();
    m_completion_index = -1;
}

Terminal::LineEditor::Result Terminal::LineEditor::on_key(const Input& in) {
    if (in.key != Key::TAB) {
        m_last_completion.candidates.clear();
        m_completion_index = -1;
    }
    if (in.key == Key::ESC) {
        if (!m_buffer.empty()) {
            clear();
            return Result::CONTINUE;
        }
        return Result::IGNORED;
    } else if (in.key == Key::UP) {
        if (!m_history.empty()) {
            if (m_history_pos == -1)
                m_history_pos = (int)m_history.size() - 1;
            else if (m_history_pos > 0)
                m_history_pos--;
            m_buffer = m_history[m_history_pos];
            m_cursor_pos = m_buffer.length();
            update_hint();
        }
        return Result::CONTINUE;
    } else if (in.key == Key::DOWN) {
        if (m_history_pos != -1) {
            if (m_history_pos < (int)m_history.size() - 1) {
                m_history_pos++;
                m_buffer = m_history[m_history_pos];
            } else {
                m_history_pos = -1;
                m_buffer.clear();
            }
            m_cursor_pos = m_buffer.length();
            update_hint();
        }
        return Result::CONTINUE;
    } else if (in.key == Key::RIGHT) {
        if (m_cursor_pos < (int)m_buffer.length())
            m_cursor_pos++;
        else if (!m_current_hint.empty()) {
            m_buffer += m_current_hint;
            m_cursor_pos += m_current_hint.length();
            update_hint();
        }
        return Result::CONTINUE;
    } else if (in.key == Key::LEFT) {
        if (m_cursor_pos > 0)
            m_cursor_pos--;
        return Result::CONTINUE;
    } else if (in.key == Key::TAB) {
        if (m_buffer.empty())
            return Result::IGNORED;
        if (m_last_completion.candidates.empty() && m_completion_cb) {
            m_completion_original = m_buffer;
            m_last_completion = m_completion_cb(m_buffer);
            m_completion_index = -1;
        }
        if (!m_last_completion.candidates.empty()) {
            m_completion_index = (m_completion_index + 1) % m_last_completion.candidates.size();
            std::string match = m_last_completion.candidates[m_completion_index];
            if (m_last_completion.replace_pos >= 0 && m_last_completion.replace_pos <= (int)m_completion_original.length())
                m_buffer = m_completion_original.substr(0, m_last_completion.replace_pos) + match;
            m_cursor_pos = m_buffer.length();
            update_hint();
        } else if (!m_current_hint.empty() && (m_current_hint == ")" || m_current_hint == "]" || m_current_hint == "}")) {
            m_buffer += m_current_hint;
            m_cursor_pos += m_current_hint.length();
            update_hint();
        }
        return Result::CONTINUE;
    } else if (in.key == Key::BACKSPACE) {
        if (m_cursor_pos > 0) {
            m_buffer.erase(m_cursor_pos - 1, 1);
            m_cursor_pos--;
            update_hint();
        }
        return Result::CONTINUE;
    } else if (in.key == Key::ENTER) {
        std::cout << "\r\n";
        return Result::SUBMIT;
    } else if (in.key == Key::CHAR) {
        m_buffer.insert(m_cursor_pos, 1, in.c);
        m_cursor_pos++;
        update_hint();
        return Result::CONTINUE;
    }
    return Result::CONTINUE;
}

void Terminal::LineEditor::draw(const std::string& prompt) {
    std::cout << "\r\x1b[K" << prompt;
    if (m_error_pos != -1 && m_error_pos < (int)m_buffer.length()) {
        std::cout << m_buffer.substr(0, m_error_pos);
        std::cout << Terminal::rgb_fg(255, 100, 100) << m_buffer.substr(m_error_pos) << Terminal::RESET;
    } else
        std::cout << m_buffer;
    if (!m_current_hint.empty() && m_cursor_pos == (int)m_buffer.length()) {
        std::cout << m_hint_color << m_current_hint << Terminal::RESET;
        std::cout << "\x1b[" << m_current_hint.length() << "D";
    } else if (m_cursor_pos < (int)m_buffer.length())
        std::cout << "\x1b[" << (m_buffer.length() - m_cursor_pos) << "D";
    std::cout << std::flush;
}