#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <string>
#include <vector>

class Commands {
public:
    struct ParamInfo {
        int count = 0;
        size_t last_comma_pos = 0;
        size_t error_comma_pos = std::string::npos;
        bool current_has_text = false;
    };

    static void find_opener(const std::string& input, char& opener, size_t& opener_pos);
    static ParamInfo analyze_params(const std::string& input, size_t opener_pos, int max_args = -1);
    static bool is_assignment(const std::string& expr);
    static std::string find_preceding_word(const std::string& input, size_t pos);
    static void get_current_arg(const std::string& input, int& arg_index, size_t& arg_start);
    static bool is_identifier(const std::string& s);
    static int find_matching_bracket(const std::string& input, int pos);
};

#endif // __COMMANDS_H__