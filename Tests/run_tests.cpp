/*
 * Unit tests runner
 */

#include <iostream>
#include "AssemblyFormatTests.h"
#include "ListingFormatTests.h"
#include "BinaryFormatTests.h"
#include "Z80FormatTests.h"
#include "SymbolFormatTests.h"
#include "SkoolFormatTests.h"

static int tests_run = 0;
static int tests_passed = 0;

void run_test(void (*test_func)(), const char* test_name) {
    tests_run++;
    std::cout << "Running " << test_name << "..." << std::endl;
    test_func();
    tests_passed++;
    std::cout << "Passed." << std::endl;
}

int main() {
    std::cout << "=== Running tests from AssemblyFormatTests.cpp ===" << std::endl;
    run_test(test_load_binary_simple, "test_load_binary_simple");
    run_test(test_load_binary_comments, "test_load_binary_comments");
    run_test(test_load_binary_fail, "test_load_binary_fail");
    run_test(test_load_binary_file_not_found, "test_load_binary_file_not_found");
    run_test(test_load_binary_labels, "test_load_binary_labels");
    run_test(test_load_binary_data_directives, "test_load_binary_data_directives");
    run_test(test_load_binary_constants, "test_load_binary_constants");
    run_test(test_load_binary_multiple_org, "test_load_binary_multiple_org");
    run_test(test_load_binary_syntax_error, "test_load_binary_syntax_error");
    run_test(test_load_binary_unknown_mnemonic, "test_load_binary_unknown_mnemonic");
    run_test(test_load_binary_invalid_directive, "test_load_binary_invalid_directive");
    run_test(test_asm_load_metadata_simple, "test_asm_load_metadata_simple");
    run_test(test_asm_load_binary_c_style_comments, "test_asm_load_binary_c_style_comments");
    run_test(test_asm_quotes_protection, "test_asm_quotes_protection");
    
    std::cout << "=== Running tests from ListingFormatTests.cpp ===" << std::endl;
    run_test(test_lst_load_binary_simple, "test_lst_load_binary_simple");
    run_test(test_lst_load_binary_comments, "test_lst_load_binary_comments");
    run_test(test_lst_load_metadata, "test_lst_load_metadata");
    run_test(test_lst_parse_hex_address, "test_lst_parse_hex_address");
    run_test(test_lst_load_binary_only_comments, "test_lst_load_binary_only_comments");
    run_test(test_lst_load_binary_file_not_found, "test_lst_load_binary_file_not_found");
    run_test(test_lst_load_binary_garbage, "test_lst_load_binary_garbage");
    run_test(test_lst_load_binary_invalid_asm, "test_lst_load_binary_invalid_asm");
    run_test(test_lst_load_binary_labels_only, "test_lst_load_binary_labels_only");
    run_test(test_lst_load_binary_multiline_ds, "test_lst_load_binary_multiline_ds");
    run_test(test_lst_load_binary_malformed_hex, "test_lst_load_binary_malformed_hex");
    run_test(test_lst_load_binary_tight_layout, "test_lst_load_binary_tight_layout");
    run_test(test_lst_load_binary_mixed_columns, "test_lst_load_binary_mixed_columns");
    run_test(test_lst_include_handling, "test_lst_include_handling");
    run_test(test_lst_macro_skip, "test_lst_macro_skip");
    run_test(test_lst_hex_continuation, "test_lst_hex_continuation");

    std::cout << "=== Running tests from BinaryFormatTests.cpp ===" << std::endl;
    run_test(test_bin_load_simple, "test_bin_load_simple");
    run_test(test_bin_load_file_not_found, "test_bin_load_file_not_found");
    run_test(test_bin_save_and_load, "test_bin_save_and_load");
    run_test(test_bin_load_offset, "test_bin_load_offset");
    run_test(test_bin_load_empty, "test_bin_load_empty");
    run_test(test_bin_load_overwrite, "test_bin_load_overwrite");
    run_test(test_bin_load_wrap_around, "test_bin_load_wrap_around");

    std::cout << "=== Running tests from Z80FormatTests.cpp ===" << std::endl;
    run_test(test_z80_load_v1_simple, "test_z80_load_v1_simple");
    run_test(test_z80_load_v1_compressed, "test_z80_load_v1_compressed");
    run_test(test_z80_load_file_not_found, "test_z80_load_file_not_found");
    run_test(test_z80_load_too_small, "test_z80_load_too_small");
    run_test(test_z80_load_v2_minimal, "test_z80_load_v2_minimal");
    run_test(test_z80_load_v2_truncated_header, "test_z80_load_v2_truncated_header");
    run_test(test_z80_load_v2_truncated_ext_header, "test_z80_load_v2_truncated_ext_header");
    run_test(test_z80_load_v1_corrupt_compressed, "test_z80_load_v1_corrupt_compressed");

    std::cout << "=== Running tests from SymbolFormatTests.cpp ===" << std::endl;
    run_test(test_sym_load_simple, "test_sym_load_simple");
    run_test(test_sym_load_comments, "test_sym_load_comments");
    run_test(test_map_load_simple, "test_map_load_simple");
    run_test(test_sym_load_formats, "test_sym_load_formats");

    std::cout << "=== Running tests from SkoolFormatTests.cpp ===" << std::endl;
    run_test(test_skool_load_simple, "test_skool_load_simple");
    run_test(test_skool_load_file_not_found, "test_skool_load_file_not_found");
    run_test(test_skool_load_metadata_comments, "test_skool_load_metadata_comments");
    run_test(test_skool_load_binary_data, "test_skool_load_binary_data");
    run_test(test_skool_ctl_labels, "test_skool_ctl_labels");
    run_test(test_skool_ctl_block_types, "test_skool_ctl_block_types");
    run_test(test_skool_directives, "test_skool_directives");
    run_test(test_skool_invalid_org, "test_skool_invalid_org");
    run_test(test_skool_invalid_defb, "test_skool_invalid_defb");

    std::cout << "\n----------------------------------------\n";
    std::cout << "Test summary: " << tests_passed << " of " << tests_run << " passed." << std::endl;
    std::cout << "----------------------------------------\n" << std::endl;

    return (tests_run == tests_passed) ? 0 : 1;
}