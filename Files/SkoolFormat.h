#ifndef __SKOOLFORMAT_H__
#define __SKOOLFORMAT_H__

#include "FileFormat.h"
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

    uint16_t parse_addr_from_string(const std::string& s);
    int parse_int_len(const std::string& s);
    std::string clean_skool_tags(const std::string& text);
};

#endif //__SKOOLFORMAT_H__