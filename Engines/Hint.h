#ifndef __HINT_H__
#define __HINT_H__

#include <string>
#include "../Utils/Terminal.h"
#include "../Utils/Commands.h"

class Dashboard;

class Hint {
public:
    Hint(Dashboard& dashboard);
    std::string calculate(const std::string& input, std::string& color, int& error_pos);

private:
    Dashboard& m_dashboard;
    std::string get_command_syntax_hint(const std::string& input);
    std::string get_completion_hint(const Terminal::Completion& completion);
    std::string get_operator_hint(const std::string& input);
    std::string get_function_hint(const std::string& input, size_t opener_pos, std::string& hint_color, int& error_pos);
    std::string get_context_hint(const std::string& input, std::string& hint_color, int& error_pos);
    std::string get_collection_hint(const std::string& input, const Commands::ParamInfo& info, char opener, const std::string& type_prefix);
};

#endif // __HINT_H__