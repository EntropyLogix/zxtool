#include "Tool.h"
#include <vector> // For std::vector
#include "../Files/FileProcessor.h"
#include "../Cmd/CommandLine.h"
#include "../Cmd/Options.h"
#include "../Files/FileSaver.h"


Tool::Tool() : m_memory(), m_cpu(&m_memory), m_analyzer(&m_memory, nullptr), m_assembler(&m_memory, &m_file_provider) {
}

int Tool::run(CommandLine& commands) {
    const auto& options = commands.get_options();
    FileProcessor file_processor(*this);

    std::vector<File> files_to_process;
    for (const auto& file_arg : options.inputFiles) {
        size_t colon_pos = file_arg.find(':');
        std::string path = file_arg;
        uint16_t address = 0;

        if (colon_pos != std::string::npos) {
            path = file_arg.substr(0, colon_pos);
            std::string addr_str = file_arg.substr(colon_pos + 1);
            address = this->resolve_address(addr_str);
        }
        files_to_process.push_back({path, address});
    }
    m_blocks = file_processor.process(files_to_process, options.verbose);

    if (!options.outputFile.empty()) {
        FileSaver file_saver(*this);
        file_saver.save(options.outputFile, options.outputFormat, m_blocks);
    }
    return 0;
}

uint16_t Tool::resolve_address(const std::string& addr_str) {
    if (addr_str.empty()) throw std::runtime_error("Address argument is empty.");
    try {
        std::string upper_str = addr_str;
        std::transform(upper_str.begin(), upper_str.end(), upper_str.begin(), ::toupper);
        if (upper_str.size() > 2 && upper_str.substr(0, 2) == "0X") return std::stoul(upper_str.substr(2), nullptr, 16);
        if (upper_str.back() == 'H') return std::stoul(upper_str.substr(0, upper_str.length() - 1), nullptr, 16);
        bool is_numeric = true;
        for(char c : addr_str) if (!std::isdigit(c)) { is_numeric = false; break; }
        if (is_numeric) return std::stoul(addr_str, nullptr, 10);
    } catch (const std::invalid_argument&) {}
    throw std::runtime_error("Invalid address or label name: " + addr_str);
}