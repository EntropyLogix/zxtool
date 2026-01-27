#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

struct Options {
    enum class ToolMode { Assemble, Disassemble, Run, Debug, Profile, Unknown };
    ToolMode mode = ToolMode::Unknown;

    // Common
    std::vector<std::pair<std::string, uint16_t>> inputFiles;
    bool verbose = false;

    // Global/Misc
    std::string orgStr = "0x0000";
    std::vector<std::string> mapFiles, ctlFiles;

    struct Assemble {
        std::string outputFile;
        std::string outputFormat;
        std::string mapFile;
        std::string listingFile;
        bool generateMap = false;
        bool generateListing = false;
    } asm_;

    struct Disassemble {
        enum class Mode { Heuristic, Raw, Execute };
        Mode mode = Mode::Execute;
        std::string outputFile;
        std::string entryPointStr;
    } disasm;

    struct Run {
        std::string entryPointStr;
        long long steps = 0;
        long long ticks = 0;
        long long timeout = 0;
        bool runUntilReturn = false;
        bool dumpRegs = false;
        std::string dumpCodeStr;
        std::string dumpMemStr;
    } run;

    struct Profile : public Run {
        int hotspots = 20;
        std::string exportFile;
    } profile;

    struct Debug {
        std::string entryPointStr;
        std::string scriptFile;
    } debug;
};

#endif // __OPTIONS_H__