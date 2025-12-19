#include "Variables.h"

Variables::Variables() {
    // Dodanie przykładowych zmiennych
    add(Variable("SCREEN_WIDTH", 256, "32 * 8"));
    add(Variable("SCREEN_HEIGHT", 192, "24 * 8"));
    add(Variable("ATTR_START", 22528, "16384 + 6144"));
}

void Variables::add(const Variable& v) {
    m_by_name[v.getName()] = v;
}

bool Variables::remove(const std::string& name) {
    return m_by_name.erase(name) > 0;
}

void Variables::clear() {
    m_by_name.clear();
}

const Variable* Variables::find(const std::string& name) const {
    auto it = m_by_name.find(name);
    if (it != m_by_name.end())
        return &it->second;
    return nullptr;
}

Variable* Variables::find(const std::string& name) {
    auto it = m_by_name.find(name);
    if (it != m_by_name.end())
        return &it->second;
    return nullptr;
}