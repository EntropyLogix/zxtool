#ifndef __CONTROLFILE_H__
#define __CONTROLFILE_H__

#include <string>
#include "../Core/Analyzer.h"
#include "File.h"

class ControlFile : public IAuxiliaryFile {
public:
    explicit ControlFile(Analyzer& analyzer) : m_analyzer(analyzer) {}

    // IFile implementation
    bool load(const std::string& filename) override;
    std::vector<std::string> get_extensions() const override;

private:
    Analyzer& m_analyzer;
};

#endif // __CONTROLFILE_H__
