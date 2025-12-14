#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "Z80Analyze.h"
#include <map>
#include <string>
#include <cstdint>
#include <utility>

// ---------------------------------------------------------
// Kontekst Projektu: Symbole, Komentarze, Metadane
// ---------------------------------------------------------
class Context : public ILabels {
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

    enum class SymbolResult { Created, Updated };
    struct SymbolUpdateInfo {
        SymbolResult result;
        uint16_t old_address;
    };
    SymbolUpdateInfo add_or_update_symbol(const std::string& label, uint16_t address);
    bool remove_symbol(const std::string& label);

    // Finds the symbol at or immediately preceding the address
    std::pair<std::string, uint16_t> find_nearest_symbol(uint16_t address) const;

    // --- Helpers for Metadata ---
    void add_block_desc(uint16_t addr, const std::string& desc);
    void add_inline_comment(uint16_t addr, const std::string& comment);
    std::string get_inline_comment(uint16_t addr);
    std::string get_block_desc(uint16_t addr);
};

#endif // __CONTEXT_H__