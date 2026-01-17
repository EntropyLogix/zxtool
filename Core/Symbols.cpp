#include "Symbols.h"

void Symbols::add(const Symbol& s) {
    m_by_name[s.getName()] = s;
    if (s.getType() == Symbol::Type::Label || s.getType() == Symbol::Type::Constant) {
        m_by_addr[s.read()] = s;
    }
}

bool Symbols::remove(const std::string& name) {
    auto it = m_by_name.find(name);
    if (it != m_by_name.end()) {
        uint16_t addr = it->second.read();
        auto it_addr = m_by_addr.find(addr);
        if (it_addr != m_by_addr.end() && it_addr->second.getName() == name) {
            m_by_addr.erase(it_addr);
        }
        m_by_name.erase(it);
        return true;
    }
    return false;
}

void Symbols::clear() {
    m_by_name.clear();
    m_by_addr.clear();
}

const Symbol* Symbols::find(const std::string& name) const {
    auto it = m_by_name.find(name);
    if (it != m_by_name.end())  
        return &it->second;
    return nullptr;
}

const Symbol* Symbols::find(uint16_t addr) const {
    auto it = m_by_addr.find(addr);
    if (it != m_by_addr.end())
        return &it->second;
    return nullptr;
}

std::pair<std::string, uint16_t> Symbols::find_nearest(uint16_t address) const {
    if (m_by_addr.empty())
        return {"", 0};
    auto it = m_by_addr.upper_bound(address);
    if (it == m_by_addr.begin())
        return {"", 0};
    --it;
    return {it->second.getName(), it->first};
}

std::string Symbols::get_label(uint16_t address) const {
    const Symbol* s = find(address);
    return s ? s->getName() : "";
}

void Symbols::add_label(uint16_t address, const std::string& label) {
    add(Symbol(label, address, Symbol::Type::Label));
}
