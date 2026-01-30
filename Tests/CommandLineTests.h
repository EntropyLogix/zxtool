#ifndef COMMANDLINE_TESTS_H
#define COMMANDLINE_TESTS_H

void test_cmd_no_args();
void test_cmd_help();
void test_cmd_version();
void test_cmd_unknown_command();
void test_cmd_build_simple();
void test_cmd_build_options();
void test_cmd_asm_alias();
void test_cmd_dasm_options();
void test_cmd_run_options();
void test_cmd_profile_options();
void test_cmd_debug_options();
void test_cmd_input_files();
void test_cmd_missing_args();
void test_cmd_invalid_values();
void test_cmd_build_no_input();
void test_cmd_unknown_option();
void test_cmd_run_dump_implicit_all();
void test_cmd_verbose_flag();
void test_cmd_dasm_modes();
void test_cmd_profile_inherited_options();
void test_cmd_no_input_with_flags();
void test_cmd_input_file_invalid_addr();
void test_cmd_run_dump_formats();
void test_cmd_numeric_parsing_errors();

#endif // COMMANDLINE_TESTS_H