#include "Z80Analyze.h"
#include "Z80Assemble.h"
#include <algorithm>

#include "CommandLine.h"
#include "Options.h"
#include "AssembleEngine.h"
#include "RunEngine.h"
#include "Files.h"

class ZXTool {
public:
    ZXTool() : m_cpu(&m_bus), m_analyzer(&m_bus, &m_cpu, &m_label_handler), m_assembler(&m_bus, &m_file_provider) {}
    int run(int argc, char* argv[]) {
        CommandLine commandLine;
        Options options;
        if (!commandLine.parse(argc, argv, options))
            return 1;
        try {
            // Smart input for run/debug: if input is .asm, assemble it first.
            std::string ext;
            size_t dot_pos = options.inputFile.rfind('.');
            if (dot_pos != std::string::npos) {
                ext = options.inputFile.substr(dot_pos + 1);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            }

            if (ext == "asm" && (options.mode == Options::ToolMode::Run || options.mode == Options::ToolMode::Debug)) {
                std::cout << "--- Auto-assembling " << options.inputFile << " in memory ---\n";
                AssembleEngine assembleEngine(m_bus, m_cpu, m_label_handler, m_analyzer, m_assembler, options);
                if (assembleEngine.execute() != 0) {
                    throw std::runtime_error("Assembly failed, cannot proceed to run/debug.");
                }
            }

            switch (options.mode) {
            case Options::ToolMode::Assemble: {
                AssembleEngine assembleEngine(m_bus, m_cpu, m_label_handler, m_analyzer, m_assembler, options);
                return assembleEngine.execute();
            }
            case Options::ToolMode::Run: {
                RunEngine runEngine(m_bus, m_cpu, m_label_handler, m_analyzer, options);
                return runEngine.execute();
            }
            case Options::ToolMode::Disassemble:
                std::cout << "Disassemble mode is not yet implemented.\n";
                break;
            case Options::ToolMode::Debug:
                std::cout << "Debug mode is not yet implemented.\n";
                break;
            case Options::ToolMode::Unknown:
                // Should be caught by parser, but as a safeguard:
                throw std::runtime_error("Unknown tool mode.");
            }

        } catch (const std::exception& e) {
            std::cerr << "\nError: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }
private:
    Z80DefaultBus m_bus;
    Files m_file_provider;
    Z80DefaultLabels m_label_handler;
    Z80<> m_cpu;
    Z80Analyzer<Z80DefaultBus, Z80<>, Z80DefaultLabels> m_analyzer;
    Z80Assembler<Z80DefaultBus> m_assembler;
};

int main(int argc, char* argv[]) {
    ZXTool tool;
    return tool.run(argc, argv);
}