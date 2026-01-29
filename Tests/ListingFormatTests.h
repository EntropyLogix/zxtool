#ifndef LISTING_FORMAT_TESTS_H
#define LISTING_FORMAT_TESTS_H

void test_lst_load_binary_simple();
void test_lst_load_binary_comments();
void test_lst_load_metadata();
void test_lst_parse_hex_address();
void test_lst_load_binary_only_comments();
void test_lst_load_binary_file_not_found();
void test_lst_load_binary_garbage();
void test_lst_load_binary_invalid_asm();
void test_lst_load_binary_labels_only();
void test_lst_load_binary_multiline_ds();
void test_lst_load_binary_malformed_hex();
void test_lst_load_binary_tight_layout();
void test_lst_load_binary_mixed_columns();
void test_lst_include_handling();
void test_lst_macro_skip();
void test_lst_hex_continuation();

#endif // LISTING_FORMAT_TESTS_H