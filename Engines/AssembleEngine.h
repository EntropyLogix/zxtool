#ifndef __ASSEMBLEENGINE_H__
#define __ASSEMBLEENGINE_H__

#include "Engine.h"

class AssembleEngine : public Engine {
public:
    AssembleEngine(VirtualMachine& vm, const Options& options);
    int run() override;

private:
    void save_output_file(const std::string& outputFile, const std::string& format, const std::vector<VirtualMachine::Block>& blocks);
    void save_bin(const std::string& outputFile, const std::vector<VirtualMachine::Block>& blocks);

    VirtualMachine& m_vm;
    const Options& m_options;
};

#endif // __ASSEMBLEENGINE_H__