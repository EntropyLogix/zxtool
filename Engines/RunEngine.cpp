#include "RunEngine.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include "../Utils/Strings.h"
#include "../Core/Expression.h"

RunEngine::RunEngine(Core& core, const Options& options) : m_core(core), m_options(options) {}

int RunEngine::run() {
    auto& m_cpu = m_core.get_cpu();
    auto& m_memory = m_core.get_memory();
    auto& m_analyzer = m_core.get_analyzer();

    long long runSteps = m_options.runSteps;
    if (!m_options.entryPointStr.empty()) {
        std::string ep = m_options.entryPointStr;
        size_t colon = ep.find(':');
        if (colon != std::string::npos) {
            try {
                long long s = std::stoll(ep.substr(colon + 1));
                if (runSteps == 0)
                    runSteps = s;
            } catch (...) {
            }
            ep = ep.substr(0, colon);
        }
        try {
            Expression eval(m_core);
            uint16_t val = (uint16_t)eval.evaluate(ep).get_scalar(m_core);
            m_cpu.set_PC(val);
        } catch (const std::exception& e) {
            std::cerr << "Error evaluating entry point '" << ep << "': " << e.what() << "\n";
            return 1;
        }
    }

    auto start_time = std::chrono::steady_clock::now();
    uint64_t start_ticks = m_cpu.get_ticks();

    if (m_options.runUntilReturn) {
        uint16_t initial_sp = m_cpu.get_SP();
        long long steps = 0;
        while (true) {
            auto line = m_analyzer.parse_instruction(m_cpu.get_PC());
            bool is_ret = line.has_flag(Analyzer::CodeLine::Type::RETURN);

            m_cpu.step();
            steps++;

            if (is_ret && m_cpu.get_SP() > initial_sp)
                break;

            if (runSteps > 0 && steps >= runSteps) break;
            if (m_options.timeout > 0 && (steps % 10000 == 0)) {
                if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count() >= m_options.timeout)
                    break;
            }
            if (m_cpu.is_halted()) break;
        }
    } else if (runSteps > 0) {
        for (long long i = 0; i < runSteps; ++i) {
            m_cpu.step();
            if (m_options.timeout > 0 && (i % 10000 == 0)) {
                if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count() >= m_options.timeout)
                    break;
            }
        }
    } else if (m_options.runTicks > 0)
        m_cpu.run(m_options.runTicks);
    else if (m_options.timeout > 0) {
        while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count() < m_options.timeout)
            m_cpu.run(m_cpu.get_ticks() + 100000);
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    uint64_t total_ticks = m_cpu.get_ticks() - start_ticks;

    bool has_output = m_options.dumpRegs || !m_options.dumpCodeStr.empty() || !m_options.dumpMemStr.empty();
    if (m_options.verbose || !has_output) {
        std::cout << "Execution Statistics:\n";
        std::cout << "  Duration: " << duration_ms << " ms\n";
        std::cout << "  T-States: " << total_ticks << "\n";
        if (duration_ms > 0) {
            double mhz = (double)total_ticks / (double)duration_ms / 1000.0;
            std::cout << "  Speed:    " << std::fixed << std::setprecision(3) << mhz << " MHz\n";
        }
        std::cout << "------------------------------------------------------------\n";
    }

    if (m_options.dumpRegs) {
        std::cout << "PC: " << Strings::hex(m_cpu.get_PC()) << " SP: " << Strings::hex(m_cpu.get_SP()) << "\n";
        std::cout << "AF: " << Strings::hex(m_cpu.get_AF()) << " BC: " << Strings::hex(m_cpu.get_BC()) << "\n";
        std::cout << "DE: " << Strings::hex(m_cpu.get_DE()) << " HL: " << Strings::hex(m_cpu.get_HL()) << "\n";
        std::cout << "AF': " << Strings::hex(m_cpu.get_AFp()) << " BC': " << Strings::hex(m_cpu.get_BCp()) << "\n";
        std::cout << "DE': " << Strings::hex(m_cpu.get_DEp()) << " HL': " << Strings::hex(m_cpu.get_HLp()) << "\n";
        std::cout << "IX: " << Strings::hex(m_cpu.get_IX()) << " IY: " << Strings::hex(m_cpu.get_IY()) << "\n";
        uint8_t f = m_cpu.get_AF() & 0xFF;
        std::cout << "Flags: " << ((f & 0x80) ? 'S' : '-') << ((f & 0x40) ? 'Z' : '-') << ((f & 0x20) ? '5' : '-') << ((f & 0x10) ? 'H' : '-')
                  << ((f & 0x08) ? '3' : '-') << ((f & 0x04) ? 'P' : '-') << ((f & 0x02) ? 'N' : '-') << ((f & 0x01) ? 'C' : '-') << "\n";
    }
    if (!m_options.dumpCodeStr.empty()) {
        auto print_line = [](const auto& line){
            std::cout << Strings::hex(line.address) << ": " << line.mnemonic;
            if (!line.operands.empty()) {
                std::cout << " ";
                using Operand = typename std::decay_t<decltype(line)>::Operand;
                for (size_t i = 0; i < line.operands.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    const auto& op = line.operands[i];
                    switch (op.type) {
                        case Operand::REG8: case Operand::REG16: case Operand::CONDITION:
                            std::cout << op.s_val; break;
                        case Operand::IMM8:
                            std::cout << Strings::hex((uint8_t)op.num_val); break;
                        case Operand::IMM16:
                            std::cout << Strings::hex((uint16_t)op.num_val); break;
                        case Operand::MEM_IMM16:
                            std::cout << "(" << Strings::hex((uint16_t)op.num_val) << ")"; break;
                        case Operand::MEM_REG16:
                            std::cout << "(" << op.s_val << ")"; break;
                        case Operand::MEM_INDEXED:
                            std::cout << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
                        default: break;
                    }
                }
            }
            std::cout << "\n";
        };

        if (m_options.dumpCodeStr == "ALL") {
            for (const auto& block : m_core.get_blocks()) {
                uint16_t addr = block.start_address;
                uint16_t end_addr = addr + block.size;
                std::cout << "--- Code Dump from " << Strings::hex(addr) << " (" << std::dec << block.size << " bytes) ---\n";
                while (addr < end_addr) {
                    uint16_t temp_pc = addr;
                    auto line = m_analyzer.parse_instruction(temp_pc);
                    print_line(line);
                    if (!line.bytes.empty()) addr += line.bytes.size();
                    else addr++;
                }
                std::cout << "\n";
            }
        } else {
            uint16_t addr = 0;
            size_t count = 16;
            size_t colon_pos = m_options.dumpCodeStr.find(':');
            if (colon_pos != std::string::npos) {
                int32_t val = 0;
                Strings::parse_integer(m_options.dumpCodeStr.substr(0, colon_pos), val);
                addr = (uint16_t)val;
                count = std::stoul(m_options.dumpCodeStr.substr(colon_pos + 1), nullptr, 0);
            } else {
                int32_t val = 0;
                Strings::parse_integer(m_options.dumpCodeStr, val);
                addr = (uint16_t)val;
            }
            for (size_t i = 0; i < count; ++i) {
                uint16_t temp_pc = addr;
                auto line = m_analyzer.parse_instruction(temp_pc);
                print_line(line);
                if (!line.bytes.empty()) addr += line.bytes.size();
                else addr++;
            }
        }
    }

    if (!m_options.dumpMemStr.empty()) {
        if (m_options.dumpMemStr == "ALL") {
            std::cout << "File loaded successfully.\n";
            for (const auto& block : m_core.get_blocks()) {
                uint16_t addr = block.start_address;
                size_t len = block.size;
                std::cout << "--- Memory Dump from " << Strings::hex(addr) << " (" << std::dec << len << " bytes) ---\n";
                for (size_t i = 0; i < len; i += 16) {
                    std::cout << Strings::hex((uint16_t)(addr + i)) << ": ";
                    for (size_t j = 0; j < 16; ++j) {
                        if (i + j < len) std::cout << Strings::hex(m_memory.read(addr + i + j)) << " ";
                        else std::cout << "   ";
                    }
                    std::cout << " ";
                    for (size_t j = 0; j < 16; ++j) {
                        if (i + j < len) {
                            uint8_t val = m_memory.read(addr + i + j);
                            std::cout << (std::isprint(val) ? (char)val : '.');
                        }
                    }
                    std::cout << "\n";
                }
                std::cout << "\n";
            }
            return 0;
        }

        size_t colon_pos = m_options.dumpMemStr.find(':');
        uint16_t addr = 0;
        size_t len = 256;

        if (colon_pos != std::string::npos) {
            int32_t val = 0;
            Strings::parse_integer(m_options.dumpMemStr.substr(0, colon_pos), val);
            addr = (uint16_t)val;
            len = std::stoul(m_options.dumpMemStr.substr(colon_pos + 1), nullptr, 0);
        } else {
            int32_t val = 0;
            Strings::parse_integer(m_options.dumpMemStr, val);
            addr = (uint16_t)val;
        }

        std::cout << "File loaded successfully.\n";
        std::cout << "--- Memory Dump from " << Strings::hex(addr) << " (" << std::dec << len << " bytes) ---\n";
        for (size_t i = 0; i < len; i += 16) {
            std::cout << Strings::hex((uint16_t)(addr + i)) << ": ";
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < len) std::cout << Strings::hex(m_memory.read(addr + i + j)) << " ";
                else std::cout << "   ";
            }
            std::cout << " ";
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < len) {
                    uint8_t val = m_memory.read(addr + i + j);
                    std::cout << (std::isprint(val) ? (char)val : '.');
                }
            }
            std::cout << "\n";
        }
    }
    return 0;
}