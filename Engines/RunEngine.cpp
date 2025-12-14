#include "RunEngine.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <stdexcept>
#include "../Utils/Strings.h"

RunEngine::RunEngine(Core& core, const Options& options)
    : m_core(core), m_options(options) {}

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
                if (runSteps == 0) runSteps = s;
            } catch (...) {}
            ep = ep.substr(0, colon);
        }
        m_cpu.set_PC(m_core.parse_address(ep));
    }

    if (runSteps > 0) {
        for (long long i = 0; i < runSteps; ++i) {
            m_cpu.step();
        }
    } else if (m_options.runTicks > 0) {
        m_cpu.run(m_options.runTicks);
    } else if (m_options.timeout > 0) {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < m_options.timeout) {
            m_cpu.run(m_cpu.get_ticks() + 100000);
        }
    }

    if (m_options.dumpRegs) {
        std::cout << "PC: " << Strings::format_hex(m_cpu.get_PC(), 4) << " SP: " << Strings::format_hex(m_cpu.get_SP(), 4) << "\n";
        std::cout << "AF: " << Strings::format_hex(m_cpu.get_AF(), 4) << " BC: " << Strings::format_hex(m_cpu.get_BC(), 4) << "\n";
        std::cout << "DE: " << Strings::format_hex(m_cpu.get_DE(), 4) << " HL: " << Strings::format_hex(m_cpu.get_HL(), 4) << "\n";
        std::cout << "AF': " << Strings::format_hex(m_cpu.get_AFp(), 4) << " BC': " << Strings::format_hex(m_cpu.get_BCp(), 4) << "\n";
        std::cout << "DE': " << Strings::format_hex(m_cpu.get_DEp(), 4) << " HL': " << Strings::format_hex(m_cpu.get_HLp(), 4) << "\n";
        std::cout << "IX: " << Strings::format_hex(m_cpu.get_IX(), 4) << " IY: " << Strings::format_hex(m_cpu.get_IY(), 4) << "\n";
        uint8_t f = m_cpu.get_AF() & 0xFF;
        std::cout << "Flags: " << ((f & 0x80) ? 'S' : '-') << ((f & 0x40) ? 'Z' : '-') << ((f & 0x20) ? '5' : '-') << ((f & 0x10) ? 'H' : '-')
                  << ((f & 0x08) ? '3' : '-') << ((f & 0x04) ? 'P' : '-') << ((f & 0x02) ? 'N' : '-') << ((f & 0x01) ? 'C' : '-') << "\n";
    }

    if (!m_options.dumpCodeStr.empty()) {
        auto print_line = [](const auto& line){
            std::cout << Strings::format_hex(line.address, 4) << ": " << line.mnemonic;
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
                            std::cout << Strings::format_hex(op.num_val, 2); break;
                        case Operand::IMM16:
                            std::cout << Strings::format_hex(op.num_val, 4); break;
                        case Operand::MEM_IMM16:
                            std::cout << "(" << Strings::format_hex(op.num_val, 4) << ")"; break;
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
                std::cout << "--- Code Dump from " << Strings::format_hex(addr, 4) << " (" << std::dec << block.size << " bytes) ---\n";
                while (addr < end_addr) {
                    uint16_t temp_pc = addr;
                    auto line = m_analyzer.parse_instruction(temp_pc);
                    print_line(line);
                    if (temp_pc <= addr) temp_pc = addr + 1;
                    addr = temp_pc;
                }
                std::cout << "\n";
            }
        } else {
            uint16_t addr = 0;
            size_t count = 16;
            size_t colon_pos = m_options.dumpCodeStr.find(':');
            if (colon_pos != std::string::npos) {
                addr = m_core.parse_address(m_options.dumpCodeStr.substr(0, colon_pos));
                count = std::stoul(m_options.dumpCodeStr.substr(colon_pos + 1), nullptr, 0);
            } else {
                addr = m_core.parse_address(m_options.dumpCodeStr);
            }
            for (size_t i = 0; i < count; ++i) {
                uint16_t temp_pc = addr;
                auto line = m_analyzer.parse_instruction(temp_pc);
                print_line(line);
                if (temp_pc <= addr) temp_pc = addr + 1;
                addr = temp_pc;
            }
        }
    }

    if (!m_options.dumpMemStr.empty()) {
        if (m_options.dumpMemStr == "ALL") {
            std::cout << "File loaded successfully.\n";
            for (const auto& block : m_core.get_blocks()) {
                uint16_t addr = block.start_address;
                size_t len = block.size;
                std::cout << "--- Memory Dump from " << Strings::format_hex(addr, 4) << " (" << std::dec << len << " bytes) ---\n";
                for (size_t i = 0; i < len; i += 16) {
                    std::cout << Strings::format_hex((uint16_t)(addr + i), 4) << ": ";
                    for (size_t j = 0; j < 16; ++j) {
                        if (i + j < len) std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)m_memory.read(addr + i + j) << " ";
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
            addr = m_core.parse_address(m_options.dumpMemStr.substr(0, colon_pos));
            len = std::stoul(m_options.dumpMemStr.substr(colon_pos + 1), nullptr, 0);
        } else {
            addr = m_core.parse_address(m_options.dumpMemStr);
        }

        std::cout << "File loaded successfully.\n";
        std::cout << "--- Memory Dump from " << Strings::format_hex(addr, 4) << " (" << std::dec << len << " bytes) ---\n";
        for (size_t i = 0; i < len; i += 16) {
            std::cout << Strings::format_hex((uint16_t)(addr + i), 4) << ": ";
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < len) std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)m_memory.read(addr + i + j) << " ";
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