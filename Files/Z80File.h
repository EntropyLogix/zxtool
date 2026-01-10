#pragma once
#include <string>
#include "File.h"

class Core;

class Z80File : public IBinaryFile {
public:
    Z80File(Core& vm);

    LoadResult load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) override;
    static bool load(Core& vm, const std::string& filename);

    std::vector<std::string> get_extensions() const override;

private:
    Core& m_core;
};

namespace Files { using ::Z80File; }