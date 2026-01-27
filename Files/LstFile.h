#ifndef __LSTFILE_H__
#define __LSTFILE_H__

#include "File.h"
#include "../Core/Core.h"

class ListingFormat : public FileFormat {
public:
    ListingFormat(Core& core);
    virtual ~ListingFormat() = default;

    bool load_binary(const std::string& path, std::vector<Block>& blocks, uint16_t load_address) override;
    bool load_metadata(const std::string& path) override;
    uint32_t get_capabilities() const override { return LoadBinary | LoadMetadata; }
    std::vector<std::string> get_extensions() const override;
private:
    bool assemble_source(const std::string& path, std::ifstream& file, std::vector<Block>& blocks, uint16_t load_address);
    bool verify_assembly(const std::vector<uint8_t>& memory_backup);
    void import_results(bool update_map);
    bool parse_listing_content(std::ifstream& file, std::vector<Block>& blocks);
    void extract_label(uint16_t addr, const std::string& source);
    bool parse_hex_address(const std::string& token, uint16_t& addr);
    bool handle_incbin(const std::string& src, const std::string& bytes_str, std::stringstream& out_source, bool& inside_incbin);
    std::string format_bytes(const std::string& raw);
    
    Core& m_core;
};

#endif // __LSTFILE_H__