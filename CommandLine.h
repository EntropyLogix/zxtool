#ifndef __COMMANDLINE_H__
#define __COMMANDLINE_H__

#include <string>
#include <vector>

struct Options; // Forward declaration

class CommandLine {
public:
    CommandLine();
    bool parse(int argc, char* argv[], Options& options);

private:
    void print_usage() const;
};

#endif//__COMMANDLINE_H__