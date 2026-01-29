#ifndef __LISTINGFORMAT_H__
#define __LISTINGFORMAT_H__

#include "FileFormat.h"
#include "../Core/Core.h"

class ListingFormat : public FileFormat {
public:
    ListingFormat(Core& core);
    virtual ~ListingFormat() = default;

    bool load_binary(const std::string& path, std::vector<Block>& blocks, uint16_t load_address) override;
    bool load_metadata(const std::string& path) override;
    uint32_t get_capabilities() const override { return LoadBinary | LoadMetadata; }
    std::vector<std::string> get_extensions() const override;

    static bool parse_hex_address(const std::string& token, uint16_t& addr);

    struct LstLine {
        int line_num = 0;
        uint16_t address = 0;
        std::vector<uint8_t> bytes;
        std::string source;
        std::string comment;
        bool valid = false;
    };

    LstLine read_lst_line(std::ifstream& file);

private:
    bool parse_line_strict(const std::string& line, LstLine& result);
    bool parse_line_fallback(const std::string& line, LstLine& result);
    void extract_comment(std::string& source, std::string& comment);
    Core& m_core;
    std::string m_pending_line;
};

#endif //__LISTINGFORMAT_H__