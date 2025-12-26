#ifndef __STRINGS_H__
#define __STRINGS_H__

#include <string>
#include <cstdint>
#include <vector>
#include <utility>

class Strings {
public:
    struct ParamInfo {
        int count = 0;
        size_t last_comma_pos = 0;
        size_t error_comma_pos = std::string::npos;
        bool current_has_text = false;
    };

    static std::string hex(uint8_t v);
    static std::string hex(uint16_t v);
    static std::string hex(uint64_t v, int bit_width);
    static std::string bin(uint8_t v);
    static std::string bin(uint16_t v);
    static std::string bin(uint64_t v, int bit_width);

    static size_t length(const std::string& s, bool visible = true);
    static std::string padding(const std::string& s, size_t width, char fill = ' ');
    static std::string truncate(const std::string& s, size_t width);
    static std::string upper(const std::string& s);
    static std::string lower(const std::string& s);

    static bool parse_integer(const std::string& s, int32_t& out_value);
    static bool parse_double(const std::string& s, double& out_value);
    static std::string trim(const std::string& s);
    static std::vector<std::string> split(const std::string& s, char delimiter = ' ');
    static std::pair<std::string, std::string> split_once(const std::string& s, char delimiter);
    static std::pair<std::string, std::string> split_once(const std::string& s, const std::string& delimiters);

    static void find_opener(const std::string& input, char& opener, size_t& opener_pos);
    static ParamInfo analyze_params(const std::string& input, size_t opener_pos, int max_args = -1);
    static bool is_assignment(const std::string& expr);
    static std::string find_preceding_word(const std::string& input, size_t pos);
    static bool is_identifier(const std::string& s);
};

#endif//__STRINGS_H__