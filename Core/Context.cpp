#include "Context.h"

// ---------------------------------------------------------
// Context Implementation
// ---------------------------------------------------------

std::string Context::get_label(uint16_t address) const {
    const Symbol* s = symbols.find(address);
    return s ? s->getName() : "";
}

void Context::add_label(uint16_t address, const std::string& label) {
    // Nie nadpisuj istniejących etykiet (priorytet mają te z plików)
    if (!symbols.find(address)) {
        symbols.add(Symbol(label, address, Symbol::Type::Label));
    }
}

Context::SymbolUpdateInfo Context::add_or_update_symbol(const std::string& label, uint16_t address) {
    // Check if symbol exists (reverse lookup by name)
    const Symbol* existing = symbols.find(label);
    if (existing) {
        uint16_t old_addr = existing->read();
        symbols.remove(label);
        symbols.add(Symbol(label, address, Symbol::Type::Label));
        return {SymbolResult::Updated, old_addr};
    }

    // New symbol
    symbols.add(Symbol(label, address, Symbol::Type::Label));
    return {SymbolResult::Created, 0};
}

bool Context::remove_symbol(const std::string& label) {
    return symbols.remove(label);
}

std::pair<std::string, uint16_t> Context::find_nearest_symbol(uint16_t address) const {
    return symbols.find_nearest(address);
}

void Context::add_block_desc(uint16_t addr, const std::string& desc) {
    const Comment* existing = comments.find(addr, Comment::Type::Block);
    std::string text = existing ? existing->getText() : "";
    if (!text.empty()) text += "\n";
    text += "; " + desc;
    comments.add(Comment(addr, text, Comment::Type::Block));
}

void Context::add_inline_comment(uint16_t addr, const std::string& comment) {
    comments.add(Comment(addr, comment, Comment::Type::Inline));
}

std::string Context::get_inline_comment(uint16_t addr) {
    const Comment* c = comments.find(addr, Comment::Type::Inline);
    return c ? c->getText() : "";
}

std::string Context::get_block_desc(uint16_t addr) {
    const Comment* c = comments.find(addr, Comment::Type::Block);
    return c ? c->getText() : "";
}