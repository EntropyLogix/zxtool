#ifndef __SKOOLFILE_H__
#define __SKOOLFILE_H__

#include "File.h"
#include "../Core/Core.h"
#include <string>
#include <vector>

class SkoolFormat : public FileFormat {
public:
    SkoolFormat(Core& core);

    // FileFormat implementation (Build & Load)
    bool load_binary(const std::string& filename, std::vector<Block>& blocks, uint16_t address) override;

    // FileFormat implementation (Metadata only)
    bool load_metadata(const std::string& filename) override;

    uint32_t get_capabilities() const override { return LoadBinary | LoadMetadata; }

    std::vector<std::string> get_extensions() const override;

private:
    Core& m_core;

    void parse_and_process(const std::string& filename, bool generate_asm, std::string& out_asm);
    bool parse_control_file(const std::string& filename);
};

#endif // __SKOOLFILE_H__