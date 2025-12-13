#ifndef __SOURCE_H__
#define __SOURCE_H__

struct LineInfo {
    std::string inlineComment; // np. "; Loop counter"
    std::string blockDescription; // np. "--- Main Loop ---"
};

class Source {
    std::map<uint16_t, LineInfo> metadata;
public:
    void addComment(uint16_t addr, std::string comment);
    const LineInfo* get(uint16_t addr);
};

#endif//__SOURCE_H__