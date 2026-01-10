#ifndef __ASSEMBLEENGINE_H__
#define __ASSEMBLEENGINE_H__

#include "Engine.h"
#include "../Core/Core.h"

class AssembleEngine : public Engine {
public:
    AssembleEngine(Core& core, const Options& options);
    int run() override;

private:
    void save_output_file(const std::string& outputFile, const std::string& format, const std::vector<Core::Block>& blocks);
    void save_bin(const std::string& outputFile, const std::vector<Core::Block>& blocks);

    Core& m_core;
    const Options& m_options;
};

#endif // __ASSEMBLEENGINE_H__