#include "Z80Analyze.h"
#include "Z80Assemble.h"

#include "Cmd/CommandLine.h"
#include "Core/Application.h" 
#include <iostream>
#include <stdexcept>

int main(int argc, char* argv[]) {
    try {
        CommandLine commandLine;
        if (!commandLine.parse(argc, argv))
            return 1;
        Application app;
        return app.run(commandLine);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}