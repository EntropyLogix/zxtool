#ifndef __CONTROLFILE_H__
#define __CONTROLFILE_H__

#include <string>
#include "../Core/Analyzer.h"

class ControlFile {
public:
    explicit ControlFile(Analyzer& analyzer) : m_analyzer(analyzer) {}

    // Format: SkoolKit CTL
    void load(const std::string& filename);

private:
    Analyzer& m_analyzer;
};

#endif // __CONTROLFILE_H__
