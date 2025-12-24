#include "Checksum.h"

uint32_t Checksum::crc32_update(uint32_t crc, uint8_t b) {
    crc ^= b;
    for (int k = 0; k < 8; k++)
        crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : (crc >> 1);
    return crc;
}

uint32_t Checksum::crc32_finalize(uint32_t crc) {
    return ~crc;
}

uint32_t Checksum::crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = CRC32_START;
    for (uint8_t b : data) {
        crc = crc32_update(crc, b);
    }
    return crc32_finalize(crc);
}

uint32_t Checksum::checksum(const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (uint8_t b : data) sum += b;
    return sum;
}