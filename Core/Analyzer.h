#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include "CoreIncludes.h"

#include "Memory.h"
#include "Disassembler.h"
#include "Z80Decoder.h"
#include <string>
#include <vector>
#include <map>
#include <functional>

class Context;

// ---------------------------------------------------------
// Smart Analyzer
// ---------------------------------------------------------
class Analyzer /*: public Disassembler*/ {
public:
    // Używamy typów z klasy bazowej
    using CodeLine = Z80Decoder<Memory>::CodeLine;
    using CodeMap = Memory::Map;
    //using MapFlags = Disassembler::CodeMap::MapFlags;

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

    Context& context;
    CodeMap m_map;
    std::vector<std::pair<uint16_t, uint16_t>> m_valid_ranges;
    Memory* m_memory;
    Z80Decoder<Memory> m_decoder;

    Analyzer(Memory* memory, Context* ctx);
    
    // Helper do ustawiania bitów typu w mapie (nie ruszając flag profilera)
    void set_map_type(Memory::Map& map, uint16_t addr, ExtendedFlags type);
    ExtendedFlags get_map_type(const Memory::Map& map, uint16_t addr);
    void set_valid_ranges(const std::vector<std::pair<uint16_t, uint16_t>>& ranges) { m_valid_ranges = ranges; }

    // Overload to support lambda validator (compatibility wrapper)
    std::vector<CodeLine> parse_code(uint16_t& start_address, size_t instruction_limit, Memory::Map* external_code_map, bool use_execution = false, bool use_heuristic = false, size_t max_data_group = 16, std::function<bool(uint16_t)> validator = nullptr);

    // Wrappers for Z80Decoder methods
    CodeLine parse_instruction(uint16_t address);
    CodeLine parse_db(uint16_t address, size_t count = 1);
    CodeLine parse_dw(uint16_t address, size_t count = 1);
    uint16_t parse_instruction_backwards(uint16_t target_addr, CodeMap* map = nullptr);

protected:
    // --- Override głównej pętli generowania ---
    // Tu integrujemy wiedzę z CTL z logiką disassemblera
    //std::vector<CodeLine> generate_listing(Disassembler::CodeMap& map, uint16_t& start_address, size_t instruction_limit, bool use_map, size_t max_data_group) override;
};

#endif