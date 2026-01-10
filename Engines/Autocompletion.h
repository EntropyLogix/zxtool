#ifndef __AUTOCOMPLETION_H__
#define __AUTOCOMPLETION_H__

#include <string>
#include "../Utils/Terminal.h"

class Dashboard;

class Autocompletion {
public:
    Autocompletion(Dashboard& dashboard);
    Terminal::Completion get(const std::string& input);
    void complete_options(const std::string& full_input, int param_index, const std::string& args, Terminal::Completion& result);

private:
    Dashboard& m_dashboard;
    std::string find_matching_command(const std::string& input);
    void complete_expression(const std::string& full_input, const std::string& arguments_part, size_t current_argument_offset, Terminal::Completion& result);
    void complete_symbol(const std::string& full_input, const std::string& arguments_part, size_t current_argument_offset, Terminal::Completion& result);
    void complete_command_name(const std::string& input, Terminal::Completion& result);
};

#endif // __AUTOCOMPLETION_H__