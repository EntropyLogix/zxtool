#ifndef __ASSEMBLER_H__
#define __ASSEMBLER_H__

#include "CoreIncludes.h"

#include "Memory.h"
#include <vector>
#include <string>
#include <map>

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
        for (const auto& pair : symbols)
            full_code += pair.first + " EQU " + std::to_string(pair.second) + "\n";
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
};

class ToolAssembler : public Z80Assembler<Memory>
{
public:
    ToolAssembler(Memory* memory, IFileProvider* source_provider, const typename Z80Assembler<Memory>::Options& options = Z80Assembler<Memory>::get_default_options())
        : Z80Assembler<Memory>(memory, source_provider, options) {}
};

#endif//__ASSEMBLER_H__