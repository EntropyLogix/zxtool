#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <string>
#include <vector>

struct Options {
    enum class ToolMode {Assemble, Run, Unknown };

    ToolMode mode = ToolMode::Unknown;
    std::string inputFile, outputBinFile, outputHexFile, outputMapFile;
    std::string memDumpAddrStr, disasmAddrStr, orgStr = "0x0000";
    size_t memDumpSize = 0, disasmLines = 0;
    long long runTicks = 0, runSteps = 0;
    std::vector<std::string> mapFiles, ctlFiles;
    bool regDumpAction = false;
    std::string regDumpFormat;
    bool verbose = false;

    // Convenience getters to match previous usage
    ToolMode getMode() const { return mode; }
    const std::string& getInputFile() const { return inputFile; }
    const std::string& getOutputBinFile() const { return outputBinFile; }
    const std::string& getOutputHexFile() const { return outputHexFile; }
    const std::string& getOutputMapFile() const { return outputMapFile; }
};

#endif // __OPTIONS_H__