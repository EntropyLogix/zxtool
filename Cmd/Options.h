#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

struct Options {
    enum class ToolMode { Assemble, Disassemble, Run, Debug, Unknown };
    enum class DisasmMode { Heuristic, Raw, Execute };

    ToolMode mode = ToolMode::Unknown;
    std::vector<std::pair<std::string, uint16_t>> inputFiles;
    std::string outputFile;
    std::string outputFormat;
    std::string mapFile;
    std::string listingFile;
    std::string orgStr = "0x0000";
    std::string entryPointStr;
    std::string dumpMemStr;
    std::string scriptFile;
    long long runTicks = 0, runSteps = 0;
    long long timeout = 0;
    std::vector<std::string> mapFiles, ctlFiles;
    bool verbose = false;
    bool generateMap = false;
    bool generateListing = false;
    bool dumpRegs = false;
    std::string dumpCodeStr;
    bool autoLabels = false;
    DisasmMode disasmMode = DisasmMode::Execute;
};

#endif // __OPTIONS_H__