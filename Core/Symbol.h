#ifndef __SYMBOL_H__
#define __SYMBOL_H__

#include <string>
#include <cstdint>

class Symbol {
public:
    enum class Type {
        Label,
        Constant,
        Variable
    };

    Symbol() = default;
    Symbol(const std::string& name, uint16_t value, Type type = Type::Label) 
        : m_name(name), m_value(value), m_type(type) {}

    const std::string& getName() const { return m_name; }
    
    uint16_t read() const { return m_value; }
    void write(uint16_t value) { m_value = value; }
    
    Type getType() const { return m_type; }

private:
    std::string m_name;
    uint16_t m_value = 0;
    Type m_type = Type::Label;
};

#endif // __SYMBOL_H__