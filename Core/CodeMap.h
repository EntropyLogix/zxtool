#ifndef __CODEMAP_H__
#define __CODEMAP_H__

#include "CoreIncludes.h"

#include <vector>
#include <cstdint>
#include "Z80Disassembler.h"
#include "Z80Decoder.h"
#include "Memory.h"

class CodeMap : public Z80Disassembler<Memory>::CodeMap {
public:
    CodeMap(size_t size, uint8_t val) : Z80Disassembler<Memory>::CodeMap(size, val) {}

    void invalidate_region(uint16_t start, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            (*this)[(uint16_t)(start + i)] &= ~(FLAG_CODE_START | FLAG_CODE_INTERIOR);
        }
        uint16_t tail = (uint16_t)(start + length);
        while ((*this)[tail] & FLAG_CODE_INTERIOR) {
            (*this)[tail] &= ~(FLAG_CODE_START | FLAG_CODE_INTERIOR);
            tail++;
            if (tail == start) break;
        }
    }
};

#endif