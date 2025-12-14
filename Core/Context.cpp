#include "Context.h"

// ---------------------------------------------------------
// Context Implementation
// ---------------------------------------------------------

std::string Context::get_label(uint16_t address) const {
    auto it = labels.find(address);
    return (it != labels.end()) ? it->second : "";
}

void Context::add_label(uint16_t address, const std::string& label) {
    // Nie nadpisuj istniejących etykiet (priorytet mają te z plików)
    if (labels.find(address) == labels.end()) {
        labels[address] = label;
    }
}

Context::SymbolUpdateInfo Context::add_or_update_symbol(const std::string& label, uint16_t address) {
    // Check if symbol exists (reverse lookup by name)
    for (auto it = labels.begin(); it != labels.end(); ++it) {
        if (it->second == label) {
            uint16_t old_addr = it->first;
            // Remove old mapping
            labels.erase(it);
            // Add new mapping
            labels[address] = label;
            return {SymbolResult::Updated, old_addr};
        }
    }

    // New symbol
    // Check if address already has a label, if so, overwrite it (or maybe we want multiple labels per address? 
    // For now, let's assume one label per address for simplicity in reverse lookup, but map supports unique keys only)
    // Actually std::map<uint16_t, string> supports one label per address.
    // If we want to support aliases, we might need a different structure.
    // But based on "Update" scenario, we are moving the label to a new address.
    
    labels[address] = label;
    return {SymbolResult::Created, 0};
}

bool Context::remove_symbol(const std::string& label) {
    for (auto it = labels.begin(); it != labels.end(); ++it) {
        if (it->second == label) {
            labels.erase(it);
            return true;
        }
    }
    return false;
}

std::pair<std::string, uint16_t> Context::find_nearest_symbol(uint16_t address) const {
    if (labels.empty()) return {"", 0};
    auto it = labels.upper_bound(address); // First element strictly > address
    if (it == labels.begin()) {
        return {"", 0}; // All symbols are after this address
    }
    --it; // Now points to element <= address
    return {it->second, it->first};
}

void Context::add_block_desc(uint16_t addr, const std::string& desc) {
    if (!metadata[addr].block_description.empty()) metadata[addr].block_description += "\n";
    metadata[addr].block_description += "; " + desc;
}

void Context::add_inline_comment(uint16_t addr, const std::string& comment) {
    metadata[addr].inline_comment = comment;
}

std::string Context::get_inline_comment(uint16_t addr) {
    if (metadata.count(addr)) return metadata[addr].inline_comment;
    return "";
}

std::string Context::get_block_desc(uint16_t addr) {
    if (metadata.count(addr)) return metadata[addr].block_description;
    return "";
}