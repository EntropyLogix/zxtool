#ifndef __COMMENTS_H__
#define __COMMENTS_H__

#include "Comment.h"
#include <map>

class Comments {
public:
    void add(const Comment& c);
    bool remove(uint16_t addr, Comment::Type type);
    void clear();
    
    const Comment* find(uint16_t addr, Comment::Type type) const;

private:
    std::map<uint16_t, Comment> m_inline_comments;
    std::map<uint16_t, Comment> m_block_comments;
};

#endif//__COMMENTS_H__