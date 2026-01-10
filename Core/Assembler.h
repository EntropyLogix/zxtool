#ifndef __ASSEMBLER_H__
#define __ASSEMBLER_H__

#include "CoreIncludes.h"

#include "Memory.h"
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <stdexcept>

class LineAssemblerMemory {
public:
    std::vector<uint8_t>* m_output = nullptr;
    uint8_t peek(uint16_t address) const {
        return 0;
    }
    void poke(uint16_t address, uint8_t value) {
        if (m_output)
            m_output->push_back(value);
    }
};

class LineAssembler : public Z80Assembler<LineAssemblerMemory> {
public:
    LineAssembler() : Z80Assembler(&m_memory, &m_file_provider) {}

    void assemble(const std::string& code, const std::map<std::string, uint16_t>& symbols, uint16_t pc, std::vector<uint8_t>& output) {
        m_memory.m_output = &output;
        
        std::string full_code = " ORG " + std::to_string(pc) + "\n";
        m_line_offset = 1;
        for (const auto& pair : symbols) {
            full_code += pair.first + " EQU " + std::to_string(pair.second) + "\n";
            m_line_offset++;
        }
        full_code += code;
        m_file_provider.set_code(full_code);
        this->custom_constants.clear();
        try {
            compile("code_line");
        } catch (...) {
            m_memory.m_output = nullptr;
            throw;
        }
        m_memory.m_output = nullptr;
    }

    bool is_reserved(const std::string& name) {
        return this->m_keywords.is_reserved(name);
    }

protected:
    [[noreturn]] void report_error(const std::string& message) const override {
        std::stringstream error_stream;
        if (this->m_context.source.source_location) {
            size_t line = this->m_context.source.source_location->line_number;
            if (line >= m_line_offset)
                error_stream << "Line " << (line - m_line_offset + 1) << ": ";
            else
                error_stream << "Internal(" << (line + 1) << "): ";
        }
        error_stream << "error: " << message;
        
        if (this->m_context.source.source_location)
             error_stream << "\n    " << this->m_context.source.source_location->content;

        throw std::runtime_error(error_stream.str());
    }

private:
    class StringFileProvider : public IFileProvider {
    public:
        void set_code(const std::string& code) { m_code = code; }
        bool read_file(const std::string& identifier, std::vector<uint8_t>& data) override {
            if (identifier == "code_line") { data.assign(m_code.begin(), m_code.end()); return true; }
            return false;
        }
        size_t file_size(const std::string& identifier) override { return (identifier == "code_line") ? m_code.size() : 0; }
        bool exists(const std::string& identifier) override { return identifier == "code_line"; }
    private:
        std::string m_code;
    };

    LineAssemblerMemory m_memory;
    StringFileProvider m_file_provider;
    size_t m_line_offset = 0;
};

class ToolAssembler : public Z80Assembler<Memory>
{
public:
    ToolAssembler(Memory* memory, IFileProvider* source_provider, const typename Z80Assembler<Memory>::Config& config = Z80Assembler<Memory>::get_default_config())
        : Z80Assembler<Memory>(memory, source_provider, config) {}
};

#endif//__ASSEMBLER_H__