#ifndef __COMMANDLINE_H__
#define __COMMANDLINE_H__

#include <string>
#include <vector>

#include "Options.h"
class CommandLine {
public:
    CommandLine() {}
    bool parse(int argc, char* argv[]);
    const Options& get_options() const { return options; }
private:
    void print_usage() const;
    bool is_valid_address(const std::string& s);

    Options options;
};

#endif//__COMMANDLINE_H__