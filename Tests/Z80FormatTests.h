#ifndef Z80_FORMAT_TESTS_H
#define Z80_FORMAT_TESTS_H

void test_z80_load_v1_simple();
void test_z80_load_v1_compressed();
void test_z80_load_file_not_found();
void test_z80_load_too_small();
void test_z80_load_v2_minimal();
void test_z80_load_v2_truncated_header();
void test_z80_load_v2_truncated_ext_header();
void test_z80_load_v1_corrupt_compressed();

#endif // Z80_FORMAT_TESTS_H