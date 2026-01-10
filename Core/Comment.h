#ifndef __COMMENT_H__
#define __COMMENT_H__

#include <string>
#include <cstdint>

class Comment {
public:
    enum class Type {
        Inline,
        Block
    };

    Comment() = default;
    Comment(uint16_t address, const std::string& text, Type type) 
        : m_address(address), m_text(text), m_type(type) {}

    uint16_t getAddress() const { return m_address; }
    
    const std::string& getText() const { return m_text; }
    Type getType() const { return m_type; }

private:
    uint16_t m_address = 0;
    std::string m_text;
    Type m_type = Type::Inline;
};

#endif // __COMMENT_H__