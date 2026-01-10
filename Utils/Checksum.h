#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include <cstdint>
#include <vector>
#include <cstddef>

class Checksum {
public:
    static constexpr uint32_t CRC32_START = 0xFFFFFFFF;

    static uint32_t crc32_update(uint32_t crc, uint8_t b);
    static uint32_t crc32_finalize(uint32_t crc);
    static uint32_t crc32(const std::vector<uint8_t>& data);
    static uint32_t checksum(const std::vector<uint8_t>& data);
};

#endif // __CHECKSUM_H__