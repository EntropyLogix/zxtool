#pragma once
#include <string>
#include "FileFormat.h"

class Core;

class Z80Format : public FileFormat {
public:
    Z80Format(Core& vm);

    bool load_binary(const std::string& filename, std::vector<Block>& blocks, uint16_t address) override;
    uint32_t get_capabilities() const override { return LoadBinary; }

    static bool load(Core& vm, const std::string& filename);

    std::vector<std::string> get_extensions() const override;

private:
    Core& m_core;
};