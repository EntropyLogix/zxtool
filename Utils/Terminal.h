#ifndef __TERMINAL_H__
#define __TERMINAL_H__

#include <string>
#include <cstdint>
#include <vector>
#include <functional>

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

    struct Completion {
        std::vector<std::string> candidates;
        int replace_pos = -1;
        std::string prefix;
        bool is_custom_context = false;
    };

    class LineEditor {
    public:
        enum class Result {
            CONTINUE,
            SUBMIT,
            IGNORED
        };

        using CompletionCallback = std::function<Completion(const std::string&)>;
        using HintCallback = std::function<std::string(const std::string&, std::string& color, int& error_pos)>;

        LineEditor();
        void history_load(const std::string& filename);
        void history_save(const std::string& filename);
        void history_add(const std::string& line);

        void set_completion_callback(CompletionCallback cb);
        void set_hint_callback(HintCallback cb);

        Result on_key(const Input& key);
        void draw(const std::string& prompt);
        
        std::string get_line() const { return m_buffer; }
        void clear();

    private:
        std::string m_buffer;
        int m_cursor_pos = 0;
        std::vector<std::string> m_history;
        int m_history_pos = -1;
        
        CompletionCallback m_completion_cb;
        HintCallback m_hint_cb;
        
        Completion m_last_completion;
        int m_completion_index = -1;
        std::string m_completion_original;
        
        std::string m_current_hint;
        std::string m_hint_color;
        int m_error_pos = -1;

        void update_hint();
    };
};

#endif // __TERMINAL_H__