#ifndef __SYMBOLFILE_H__
#define __SYMBOLFILE_H__

#include <string>
#include "../Core/Analyzer.h"
#include "File.h"

class SymbolFile : public IAuxiliaryFile {
public:
    explicit SymbolFile(Analyzer& analyzer) : m_analyzer(analyzer) {}

    // Format: "LABEL EQU VALUE" (PASMO/TASM style)
    void load_sym(const std::string& filename);

    // Format: "VALUE LABEL" (Simple map)
    void load_map(const std::string& filename);

    // IFile implementation
    bool load(const std::string& filename) override;
    std::vector<std::string> get_extensions() const override;

private:
    Analyzer& m_analyzer;
};

#endif // __SYMBOLFILE_H__
