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
#include "CoreTests.h"
#include "CommandLineTests.h"
#include "ExpressionTests.h"

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

    std::cout << "=== Running tests from CoreTests.cpp ===" << std::endl;
    run_test(test_core_load_explicit_metadata, "test_core_load_explicit_metadata");
    run_test(test_core_load_binary_and_sidecar, "test_core_load_binary_and_sidecar");
    run_test(test_core_virtual_files, "test_core_virtual_files");
    run_test(test_core_load_multiple_binaries, "test_core_load_multiple_binaries");
    
    std::cout << "=== Running tests from CommandLineTests.cpp ===" << std::endl;
    run_test(test_cmd_no_args, "test_cmd_no_args");
    run_test(test_cmd_help, "test_cmd_help");
    run_test(test_cmd_version, "test_cmd_version");
    run_test(test_cmd_unknown_command, "test_cmd_unknown_command");
    run_test(test_cmd_build_simple, "test_cmd_build_simple");
    run_test(test_cmd_build_options, "test_cmd_build_options");
    run_test(test_cmd_asm_alias, "test_cmd_asm_alias");
    run_test(test_cmd_dasm_options, "test_cmd_dasm_options");
    run_test(test_cmd_run_options, "test_cmd_run_options");
    run_test(test_cmd_profile_options, "test_cmd_profile_options");
    run_test(test_cmd_debug_options, "test_cmd_debug_options");
    run_test(test_cmd_input_files, "test_cmd_input_files");
    run_test(test_cmd_missing_args, "test_cmd_missing_args");
    run_test(test_cmd_invalid_values, "test_cmd_invalid_values");
    run_test(test_cmd_build_no_input, "test_cmd_build_no_input");
    run_test(test_cmd_unknown_option, "test_cmd_unknown_option");
    run_test(test_cmd_run_dump_implicit_all, "test_cmd_run_dump_implicit_all");
    run_test(test_cmd_verbose_flag, "test_cmd_verbose_flag");
    run_test(test_cmd_dasm_modes, "test_cmd_dasm_modes");
    run_test(test_cmd_profile_inherited_options, "test_cmd_profile_inherited_options");
    run_test(test_cmd_no_input_with_flags, "test_cmd_no_input_with_flags");
    run_test(test_cmd_input_file_invalid_addr, "test_cmd_input_file_invalid_addr");
    run_test(test_cmd_run_dump_formats, "test_cmd_run_dump_formats");
    run_test(test_cmd_numeric_parsing_errors, "test_cmd_numeric_parsing_errors");

    std::cout << "=== Running tests from ExpressionTests.cpp ===" << std::endl;
    run_test(test_expr_arithmetic, "test_expr_arithmetic");
    run_test(test_expr_bitwise, "test_expr_bitwise");
    run_test(test_expr_logical, "test_expr_logical");
    run_test(test_expr_comparison, "test_expr_comparison");
    run_test(test_expr_functions_math, "test_expr_functions_math");
    run_test(test_expr_functions_string, "test_expr_functions_string");
    run_test(test_expr_variables, "test_expr_variables");
    run_test(test_expr_collections, "test_expr_collections");
    run_test(test_expr_assignment, "test_expr_assignment");
    run_test(test_expr_errors, "test_expr_errors");
    run_test(test_expr_asm, "test_expr_asm");
    run_test(test_expr_registers, "test_expr_registers");
    run_test(test_expr_complex, "test_expr_complex");
    run_test(test_expr_precedence, "test_expr_precedence");
    run_test(test_expr_functions_extra, "test_expr_functions_extra");
    run_test(test_expr_functions_stats, "test_expr_functions_stats");
    run_test(test_expr_checksums, "test_expr_checksums");
    run_test(test_expr_conversion, "test_expr_conversion");
    run_test(test_expr_advanced_collections, "test_expr_advanced_collections");
    run_test(test_expr_memory_access, "test_expr_memory_access");
    run_test(test_expr_boolean_logic, "test_expr_boolean_logic");
    run_test(test_expr_type_checks, "test_expr_type_checks");
    run_test(test_expr_string_manipulation, "test_expr_string_manipulation");
    run_test(test_expr_asm_advanced, "test_expr_asm_advanced");
    run_test(test_expr_collection_logic, "test_expr_collection_logic");
    run_test(test_expr_unary_collection, "test_expr_unary_collection");
    run_test(test_expr_literals, "test_expr_literals");
    run_test(test_expr_collection_arithmetic_advanced, "test_expr_collection_arithmetic_advanced");
    run_test(test_expr_memory_fill, "test_expr_memory_fill");
    run_test(test_expr_asm_labels, "test_expr_asm_labels");
    run_test(test_expr_string_escapes, "test_expr_string_escapes");
    run_test(test_expr_empty_collections, "test_expr_empty_collections");
    run_test(test_expr_nested_collections, "test_expr_nested_collections");
    run_test(test_expr_asm_variables, "test_expr_asm_variables");
    run_test(test_expr_mixed_string_concat, "test_expr_mixed_string_concat");
    run_test(test_expr_case_insensitivity, "test_expr_case_insensitivity");
    run_test(test_expr_address_validation, "test_expr_address_validation");
    run_test(test_expr_bitwise_negative, "test_expr_bitwise_negative");
    run_test(test_expr_predefined_vars, "test_expr_predefined_vars");
    run_test(test_expr_syntax_errors, "test_expr_syntax_errors");
    run_test(test_expr_math_edge_cases, "test_expr_math_edge_cases");
    run_test(test_expr_system_vars_syntax, "test_expr_system_vars_syntax");
    run_test(test_expr_collection_invalid_ops, "test_expr_collection_invalid_ops");
    run_test(test_expr_string_assignment, "test_expr_string_assignment");
    run_test(test_expr_collection_functions, "test_expr_collection_functions");
    run_test(test_expr_collection_indexing_list, "test_expr_collection_indexing_list");
    run_test(test_expr_unary_address, "test_expr_unary_address");
    run_test(test_expr_words_concat, "test_expr_words_concat");
    run_test(test_expr_misc_coverage, "test_expr_misc_coverage");
    run_test(test_expr_remaining_coverage, "test_expr_remaining_coverage");
    run_test(test_expr_final_coverage, "test_expr_final_coverage");
    run_test(test_expr_edge_cases_2, "test_expr_edge_cases_2");
    run_test(test_expr_gap_coverage, "test_expr_gap_coverage");
    run_test(test_expr_final_edge_cases, "test_expr_final_edge_cases");
    run_test(test_expr_negative_cases, "test_expr_negative_cases");

    std::cout << "\n----------------------------------------\n";
    std::cout << "Test summary: " << tests_passed << " of " << tests_run << " passed." << std::endl;
    std::cout << "----------------------------------------\n" << std::endl;

    return (tests_run == tests_passed) ? 0 : 1;
}