#include "DisassembleEngine.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <vector>
#include "../Utils/Strings.h"

DisassembleEngine::DisassembleEngine(VirtualMachine& vm, const Options& options)
    : m_vm(vm), m_options(options)
{
}

int DisassembleEngine::run() {
    auto& analyzer = m_vm.get_analyzer();
    
    std::ofstream file_out;
    std::streambuf* buf = std::cout.rdbuf();
    if (!m_options.outputFile.empty()) {
        file_out.open(m_options.outputFile);
        if (file_out) buf = file_out.rdbuf();
    }
    std::ostream out(buf);
    
    struct DisasmJob {
        uint16_t start;
        uint32_t end;
        bool use_end;
        size_t limit;
        std::string title;
    };
    std::vector<DisasmJob> jobs;

    bool has_entry = !m_options.entryPointStr.empty();
    bool has_steps = m_options.runSteps > 0;

    if (!has_entry && !has_steps) {
        const auto& blocks = m_vm.get_blocks();
        if (blocks.empty()) {
             jobs.push_back({0, 0, false, 20, ""});
        } else {
            for (const auto& b : blocks) {
                jobs.push_back({b.start_address, static_cast<uint32_t>(b.start_address + b.size), true, 0, 
                    "--- Disassembly of " + b.description + " (" + Strings::format_hex(b.start_address, 4) + ") ---"});
            }
        }
    } else {
        uint16_t pc = 0;
        size_t count = 20;
        if (has_entry) {
            std::string ep = m_options.entryPointStr;
            size_t colon = ep.find(':');
            if (colon != std::string::npos) {
                try { count = std::stoul(ep.substr(colon + 1)); } catch (...) {}
                ep = ep.substr(0, colon);
            }
            try {
                pc = m_vm.parse_address(ep);
            } catch (const std::exception& e) { std::cerr << "Invalid entry point: " << ep << " (" << e.what() << ")\n"; }
        }
        if (has_steps) count = m_options.runSteps;
        jobs.push_back({pc, 0, false, count, ""});
    }

    for (const auto& job : jobs) {
        if (!job.title.empty()) out << job.title << "\n";
        uint16_t pc = job.start;
        size_t lines_printed = 0;

        while (true) {
            if (job.use_end && pc >= job.end) break;
            if (job.limit > 0 && lines_printed >= job.limit) break;

            size_t batch = 50;
            if (job.limit > 0) {
                size_t remain = job.limit - lines_printed;
                if (batch > remain) batch = remain;
            }

            uint16_t prev_pc = pc;
            auto lines = analyzer.parse_code(pc, batch);
            if (lines.empty()) break;

            for (const auto& line : lines) {
                if (job.use_end && line.address >= job.end) {
                    pc = line.address;
                    break;
                }

                out << Strings::format_hex(line.address, 4) << "  ";
                std::stringstream bytes_ss;
                for (size_t i = 0; i < line.bytes.size() && i < 4; ++i) {
                    bytes_ss << Strings::format_hex(line.bytes[i], 2) << " ";
                }
                out << std::setfill(' ') << std::setw(13) << std::left << bytes_ss.str();
                std::string label_part = line.label.empty() ? "" : (line.label + ":");
                out << std::setw(12) << label_part;
                out << std::setw(6) << line.mnemonic << " ";
                if (!line.operands.empty()) {
                    using Operand = typename std::decay_t<decltype(line)>::Operand;
                    for (size_t i = 0; i < line.operands.size(); ++i) {
                        if (i > 0) out << ", ";
                        const auto& op = line.operands[i];
                        switch (op.type) {
                            case Operand::REG8: case Operand::REG16: case Operand::CONDITION: out << op.s_val; break;
                            case Operand::IMM8: out << Strings::format_hex(op.num_val, 2); break;
                            case Operand::IMM16: out << Strings::format_hex(op.num_val, 4); break;
                            case Operand::MEM_IMM16: out << "(" << Strings::format_hex(op.num_val, 4) << ")"; break;
                            case Operand::MEM_REG16: out << "(" << op.s_val << ")"; break;
                            case Operand::MEM_INDEXED: out << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << std::dec << (int)op.offset << ")"; break;
                            case Operand::STRING: out << "\"" << op.s_val << "\""; break;
                            default: break;
                        }
                    }
                }
                out << std::endl;
                lines_printed++;
                if (job.limit > 0 && lines_printed >= job.limit) break;
            }
            if (pc <= prev_pc) break;
        }
        if (!job.title.empty()) out << "\n";
    }
    return 0;
}