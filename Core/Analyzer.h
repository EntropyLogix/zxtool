#ifndef __SMART_Z80_ANALYZE_H__
#define __SMART_Z80_ANALYZE_H__

#include "Z80Analyze.h"
#include "Memory.h"
#include <string>
#include <vector>
#include <map>

// ---------------------------------------------------------
// Kontekst Projektu: Symbole, Komentarze, Metadane
// ---------------------------------------------------------
class ProjectContext : public ILabels {
public:
    struct MetaInfo {
        std::string block_description; // "D" - opis nad blokiem
        std::string inline_comment;    // "C" - komentarz po instrukcji
    };

    std::map<uint16_t, std::string> labels;
    std::map<uint16_t, MetaInfo> metadata;

    // --- ILabels Interface Implementation ---
    std::string get_label(uint16_t address) const override;
    void add_label(uint16_t address, const std::string& label) override;

    // --- Helpers for Metadata ---
    void add_block_desc(uint16_t addr, const std::string& desc);
    void add_inline_comment(uint16_t addr, const std::string& comment);
    std::string get_inline_comment(uint16_t addr);
    std::string get_block_desc(uint16_t addr);
};

// ---------------------------------------------------------
// Smart Analyzer
// ---------------------------------------------------------
class Analyzer : public Z80Analyzer<Memory> {
public:
    // Używamy typów z klasy bazowej
    using Z80Analyzer<Memory>::CodeMap;
    using Z80Analyzer<Memory>::CodeLine;
    using Z80Analyzer<Memory>::MapFlags;

    // Rozszerzone flagi dla CodeMap (Bity 5-7)
    // Mapowanie BlockType z CTL na bity w mapie
    enum ExtendedFlags : uint8_t {
        TYPE_MASK = 0xE0,
        TYPE_SHIFT = 5,
        
        TYPE_UNKNOWN = 0,
        TYPE_CODE    = 1, // c
        TYPE_BYTE    = 2, // b
        TYPE_WORD    = 3, // w
        TYPE_TEXT    = 4, // t/z
        TYPE_IGNORE  = 5  // i/s
    };

    ProjectContext context;
    CodeMap m_map;

    Analyzer(Memory* memory);
    
    // Helper do ustawiania bitów typu w mapie (nie ruszając flag profilera)
    void set_map_type(CodeMap& map, uint16_t addr, ExtendedFlags type);
    ExtendedFlags get_map_type(const CodeMap& map, uint16_t addr);

protected:
    // --- Override głównej pętli generowania ---
    // Tu integrujemy wiedzę z CTL z logiką disassemblera
    std::vector<CodeLine> generate_listing(CodeMap& map, uint16_t& start_address, size_t instruction_limit, bool use_map) override;
};

#endif