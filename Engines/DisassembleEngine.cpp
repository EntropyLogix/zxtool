#include "DisassembleEngine.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <type_traits>
#include "../Utils/Strings.h"

DisassembleEngine::DisassembleEngine(Core& core, const Options& options)
    : m_core(core), m_options(options)
{
}

int DisassembleEngine::run() {
    auto& analyzer = m_core.get_analyzer();
    
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
        const auto& blocks = m_core.get_blocks();
        if (blocks.empty()) {
             jobs.push_back({0, 0, false, 20, ""});
        } else {
            for (const auto& b : blocks) {
                jobs.push_back({b.start_address, static_cast<uint32_t>(b.start_address + b.size), true, 0, 
                    "--- Disassembly of " + b.description + " (" + Strings::hex(b.start_address) + ") ---"});
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
            int32_t val = 0;
            if (Strings::parse_integer(ep, val)) {
                pc = (uint16_t)val;
            } else { std::cerr << "Invalid entry point: " << ep << "\n"; }
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
            auto lines = analyzer.parse_code(pc, batch, nullptr);
            if (lines.empty()) break;

            for (const auto& line : lines) {
                if (job.use_end && line.address >= job.end) {
                    pc = line.address;
                    break;
                }

                using AnalyzerType = std::decay_t<decltype(analyzer)>;
                using CodeLine = typename AnalyzerType::CodeLine;
                using Operand = typename CodeLine::Operand;
                using Type = typename CodeLine::Type;

                out << Strings::hex(line.address) << "  ";
                std::stringstream bytes_ss;
                for (size_t i = 0; i < line.bytes.size() && i < 4; ++i) {
                    bytes_ss << Strings::hex(line.bytes[i]) << " ";
                }
                out << std::setfill(' ') << std::setw(13) << std::left << bytes_ss.str();
                std::string label_part = line.label.empty() ? "" : (line.label + ":");
                out << std::setw(12) << label_part;
                out << std::setw(6) << line.mnemonic << " ";
                if (!line.operands.empty()) {
                    for (size_t i = 0; i < line.operands.size(); ++i) {
                        if (i > 0) out << ", ";
                        const auto& op = line.operands[i];
                        switch (op.type) {
                            case Operand::REG8: 
                            case Operand::REG16: 
                            case Operand::CONDITION: 
                                out << op.s_val; 
                                break;
                            case Operand::IMM8: 
                                out << "$" << Strings::hex((uint8_t)op.num_val); 
                                break;
                            case Operand::IMM16: 
                                out << "$" << Strings::hex((uint16_t)op.num_val); 
                                break;
                            case Operand::MEM_IMM16: 
                                out << "($" << Strings::hex((uint16_t)op.num_val) << ")"; 
                                break;
                            case Operand::PORT_IMM8: 
                                out << "($" << Strings::hex((uint8_t)op.num_val) << ")"; 
                                break;
                            case Operand::MEM_REG16: 
                                out << "(" << op.s_val << ")"; 
                                break;
                            case Operand::MEM_INDEXED: 
                                out << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << std::dec << (int)op.offset << ")"; 
                                break;
                            case Operand::STRING: 
                                out << "\"" << op.s_val << "\""; 
                                break;
                            case Operand::CHAR_LITERAL: 
                                out << "'" << (char)op.num_val << "'"; 
                                break;
                            default: 
                                break;
                        }
                    }
                }
                out << std::endl;
                lines_printed++;

                bool is_ret = (line.type & Type::RETURN);
                bool is_uncond_jump = (line.type & Type::JUMP) && 
                                      line.mnemonic != "DJNZ" && 
                                      (line.operands.empty() || line.operands[0].type != Operand::CONDITION);

                if (is_ret || is_uncond_jump) {
                    out << "\n";
                }

                if (job.limit > 0 && lines_printed >= job.limit) break;
            }
            if (pc <= prev_pc) break;
        }
        if (!job.title.empty()) out << "\n";
    }
    return 0;
}