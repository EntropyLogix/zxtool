#include "Application.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <memory>
#include "Expression.h"
#include "../Cmd/CommandLine.h"
#include "../Cmd/Options.h"
#include "../Engines/Engine.h"
#include "../Engines/AssembleEngine.h"
#include "../Engines/RunEngine.h"
//#include "../Engines/DisassembleEngine.h"
#include "../Engines/DebugEngine.h"
#include "../Engines/ProfileEngine.h"
#include "../Utils/Strings.h"
#include <filesystem>

Application::Application() : m_core(), m_options(nullptr) {
}

int Application::run(CommandLine& commands) {
    try {
        m_options = &commands.get_options();
        const auto& options = *m_options;

        load_input_files();

        std::unique_ptr<Engine> engine;

        switch (options.mode) {
            case Options::ToolMode::Assemble:
                engine = std::make_unique<AssembleEngine>(m_core, options);
                break;

            case Options::ToolMode::Run:
                engine = std::make_unique<RunEngine>(m_core, options);
                break;

            //case Options::ToolMode::Disassemble:
            //    engine = std::make_unique<DisassembleEngine>(m_core, options);
            //    break;

            case Options::ToolMode::Debug:
                engine = std::make_unique<DebugEngine>(m_core, options);
                break;

            case Options::ToolMode::Profile:
                engine = std::make_unique<ProfileEngine>(m_core, options);
                break;

            case Options::ToolMode::Unknown:
            default:
                // Na razie brak silnika dla tych trybów
                std::cerr << "Error: Tool mode not supported yet." << std::endl;
                return 1;
        }

        if (engine) {
            return engine->run();
        }
    } catch (const Expression::Error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 1;
}

void Application::load_input_files() {
    if (!m_options) return;
    const auto& options = *m_options;
    
    // Project handles parsing "file:addr" strings and loading sidecars
    m_core.load_input_files(options.inputFiles);

    if (options.asm_.generateListing) {
        const auto& listing = m_core.get_assembler().get_listing();
        if (!listing.empty()) {
            std::string filename = options.asm_.listingFile;
            if (filename.empty() && !options.inputFiles.empty()) {
                std::filesystem::path p(options.inputFiles[0].first);
                filename = p.replace_extension(".lst").string();
            }
            if (filename.empty()) filename = "out.lst";

            std::ofstream file(filename);
            if (file) {
                for (const auto& line : listing) {
                    file << std::setw(4) << line.source_line.line_number << " ";
                    file << Strings::hex(line.address) << " ";
                    std::string bytes_str;
                    for (size_t i = 0; i < line.bytes.size() && i < 4; ++i) {
                        bytes_str += Strings::hex(line.bytes[i]) + " ";
                    }
                    file << std::left << std::setw(13) << bytes_str << line.source_line.content << "\n";
                    if (line.bytes.size() > 4) {
                        for (size_t i = 4; i < line.bytes.size(); i += 4) {
                            file << "     " << "     " << " ";
                            bytes_str = "";
                            for (size_t j = 0; j < 4 && (i + j) < line.bytes.size(); ++j) bytes_str += Strings::hex(line.bytes[i+j]) + " ";
                            file << std::left << std::setw(13) << bytes_str << "\n";
                        }
                    }
                }
                std::cout << "Listing saved to " << filename << std::endl;
            }
        }
    }
}