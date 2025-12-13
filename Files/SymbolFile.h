#ifndef __SYMBOLFILE_H__
#define __SYMBOLFILE_H__

#include <string>
#include "../Core/Analyzer.h"

class SymbolFile {
public:
    explicit SymbolFile(Analyzer& analyzer) : m_analyzer(analyzer) {}

    // Format: "LABEL EQU VALUE" (PASMO/TASM style)
    void load_sym(const std::string& filename);

    // Format: "VALUE LABEL" (Simple map)
    void load_map(const std::string& filename);

private:
    Analyzer& m_analyzer;
};

#endif // __SYMBOLFILE_H__
