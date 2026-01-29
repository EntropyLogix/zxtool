#ifndef BINARY_FORMAT_TESTS_H
#define BINARY_FORMAT_TESTS_H

void test_bin_load_simple();
void test_bin_load_file_not_found();
void test_bin_save_and_load();
void test_bin_load_offset();
void test_bin_load_empty();
void test_bin_load_overwrite();
void test_bin_load_wrap_around();

#endif // BINARY_FORMAT_TESTS_H