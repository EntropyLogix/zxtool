#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

class Symbols {
public:
    struct Symbol {
        std::string name;
        uint16_t value;
        bool isLabel; // true = adres, false = stała
    };
    void add(const Symbol& s);
    std::string getName(uint16_t addr);
    uint16_t getValue(std::string name);

private:
    std::map<uint16_t, Symbol> addrToSymbol;
    std::map<std::string, Symbol> nameToSymbol;
};

#endif//__SYMBOLS_H__