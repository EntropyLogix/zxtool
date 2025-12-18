#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

#include "Symbol.h"
#include <map>
#include <string>
#include <vector>

class Symbols {
public:
    void add(const Symbol& s);
    bool remove(const std::string& name);
    void clear();
    
    const Symbol* find(const std::string& name) const;
    const Symbol* find(uint16_t addr) const;
    
    std::pair<std::string, uint16_t> find_nearest(uint16_t address) const;

    const std::map<uint16_t, Symbol>& by_address() const { return m_by_addr; }

private:
    std::map<std::string, Symbol> m_by_name;
    std::map<uint16_t, Symbol> m_by_addr;
};

#endif//__SYMBOLS_H__