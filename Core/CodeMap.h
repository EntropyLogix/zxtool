#ifndef __CODEMAP_H__
#define __CODEMAP_H__

#include <vector>
#include <cstdint>
#include "Z80Analyze.h"
#include "Memory.h"

class CodeMap : public std::vector<uint8_t> {
public:
    CodeMap(size_t size, uint8_t val) : std::vector<uint8_t>(size, val) {}

    void invalidate_region(uint16_t start, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            (*this)[(uint16_t)(start + i)] &= ~(Z80Analyzer<Memory>::FLAG_CODE_START | Z80Analyzer<Memory>::FLAG_CODE_INTERIOR);
        }
        uint16_t tail = (uint16_t)(start + length);
        while ((*this)[tail] & Z80Analyzer<Memory>::FLAG_CODE_INTERIOR) {
            (*this)[tail] &= ~(Z80Analyzer<Memory>::FLAG_CODE_START | Z80Analyzer<Memory>::FLAG_CODE_INTERIOR);
            tail++;
            if (tail == start) break;
        }
    }
};

#endif