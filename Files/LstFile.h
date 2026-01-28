#ifndef __LSTFILE_H__
#define __LSTFILE_H__

#include "File.h"
#include "../Core/Core.h"
#include <regex>

class ListingFormat : public FileFormat {
public:
    ListingFormat(Core& core);
    virtual ~ListingFormat() = default;

    bool load_binary(const std::string& path, std::vector<Block>& blocks, uint16_t load_address) override;
    bool load_metadata(const std::string& path) override;
    uint32_t get_capabilities() const override { return LoadBinary | LoadMetadata; }
    std::vector<std::string> get_extensions() const override;

    enum class LoadMode {
        None,
        Compilation,
        Hex,
        SymbolsOnly
    };

    LoadMode get_load_mode() const { return m_load_mode; }

    static bool parse_hex_address(const std::string& token, uint16_t& addr);

private:
    struct LstLine {
        int line_num = -1;
        bool has_line_num = false;
        uint16_t address = 0;
        bool has_address = false;
        std::vector<std::string> hex_bytes;
        std::string source;
    };

    LstLine parse_lst_line(const std::string& line);
    bool is_include_directive(const std::string& source);
    bool assemble_source(const std::string& path, std::ifstream& file, std::vector<Block>& blocks, uint16_t load_address);
    bool verify_assembly(const std::vector<uint8_t>& memory_backup);
    void import_results(bool update_map);
    bool parse_listing_content(std::ifstream& file, std::vector<Block>& blocks);
    void extract_label(uint16_t addr, const std::string& source);
    void parse_equ(const std::string& label, const std::string& operand);
    bool handle_incbin(const std::string& src, const std::string& bytes_str, std::stringstream& out_source, bool& inside_incbin);
    bool handle_include(const std::string& src, std::stringstream& out_source);
    std::string format_bytes(const std::string& raw);
    bool assemble_hex(const std::string& path, std::ifstream& file, std::vector<Block>& blocks, uint16_t load_address);
    
    Core& m_core;
    LoadMode m_load_mode = LoadMode::None;
};

#endif // __LSTFILE_H__