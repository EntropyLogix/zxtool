#include "Z80Analyze.h"
#include "Z80Assemble.h"

#include "Cmd/CommandLine.h"
#include "Core/Tool.h" 

int main(int argc, char* argv[]) {
    CommandLine commandLine;
    if (!commandLine.parse(argc, argv))
        return 1;
    Tool tool;
    return tool.run(commandLine);
}