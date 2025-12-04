#include "Z80Analyze.h"
#include "Z80Assemble.h"

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
            if (options.getMode() == Options::ToolMode::Assemble) { 
                AssembleEngine assembleEngine(m_bus, m_cpu, m_label_handler, m_analyzer, m_assembler, options);
                assembleEngine.execute();
            }
            else {
                RunEngine runEngine(m_bus, m_cpu, m_label_handler, m_analyzer, options);
                runEngine.execute();
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