#include "Application.h"
#include <iostream>
#include <memory>
#include "../Cmd/CommandLine.h"
#include "../Cmd/Options.h"
#include "../Engines/Engine.h"
#include "../Engines/AssembleEngine.h"
#include "../Engines/RunEngine.h"
#include "../Engines/DisassembleEngine.h"
#include "../Engines/DebugEngine.h"

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

            case Options::ToolMode::Disassemble:
                engine = std::make_unique<DisassembleEngine>(m_core, options);
                break;

            case Options::ToolMode::Debug:
                engine = std::make_unique<DebugEngine>(m_core, options);
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
}