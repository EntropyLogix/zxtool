#ifndef __SKOOLFILE_H__
#define __SKOOLFILE_H__

#include "File.h"
#include "../Core/Core.h"
#include <string>
#include <vector>

class SkoolFile : public IBinaryFile, public IAuxiliaryFile {
public:
    SkoolFile(Core& core);

    // IBinaryFile implementation (Build & Load)
    LoadResult load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) override;

    // IAuxiliaryFile implementation (Metadata only)
    bool load(const std::string& filename) override;

    std::vector<std::string> get_extensions() const override;

private:
    Core& m_core;

    void parse_and_process(const std::string& filename, bool generate_asm, std::string& out_asm);
};

#endif // __SKOOLFILE_H__