#include "Comments.h"

void Comments::add(const Comment& c) {
    if (c.getType() == Comment::Type::Inline) {
        m_inline_comments[c.getAddress()] = c;
    } else {
        m_block_comments[c.getAddress()] = c;
    }
}

bool Comments::remove(uint16_t addr, Comment::Type type) {
    if (type == Comment::Type::Inline) {
        return m_inline_comments.erase(addr) > 0;
    } else {
        return m_block_comments.erase(addr) > 0;
    }
}

void Comments::clear() {
    m_inline_comments.clear();
    m_block_comments.clear();
}

const Comment* Comments::find(uint16_t addr, Comment::Type type) const {
    if (type == Comment::Type::Inline) {
        auto it = m_inline_comments.find(addr);
        if (it != m_inline_comments.end()) return &it->second;
    } else {
        auto it = m_block_comments.find(addr);
        if (it != m_block_comments.end()) return &it->second;
    }
    return nullptr;
}