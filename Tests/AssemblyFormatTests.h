#ifndef ASSEMBLY_FORMAT_TESTS_H
#define ASSEMBLY_FORMAT_TESTS_H

void test_load_binary_simple();
void test_load_binary_comments();
void test_load_binary_fail();
void test_load_binary_file_not_found();
void test_load_binary_labels();
void test_load_binary_data_directives();
void test_load_binary_constants();
void test_load_binary_multiple_org();
void test_load_binary_syntax_error();
void test_load_binary_unknown_mnemonic();
void test_load_binary_invalid_directive();
void test_asm_load_metadata_simple();
void test_asm_load_binary_c_style_comments();
void test_asm_quotes_protection();

#endif // ASSEMBLY_FORMAT_TESTS_H