#ifndef __SYMBOLFILE_H__
#define __SYMBOLFILE_H__

#include <string>
#include "../Core/Analyzer.h"
#include "File.h"

class SymbolFormat : public FileFormat {
public:
    explicit SymbolFormat(Analyzer& analyzer) : m_analyzer(analyzer) {}

    // Format: "LABEL EQU VALUE" (PASMO/TASM style)
    void load_sym(const std::string& filename);

    // Format: "VALUE LABEL" (Simple map)
    void load_map(const std::string& filename);

    // FileFormat implementation
    // Bridge for legacy implementation in .cpp
    bool load(const std::string& filename);
    bool load_metadata(const std::string& filename) override { return load(filename); }
    uint32_t get_capabilities() const override { return LoadMetadata; }

    std::vector<std::string> get_extensions() const override;

private:
    Analyzer& m_analyzer;
};

#endif // __SYMBOLFILE_H__
