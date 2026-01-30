#include "ExpressionTests.h"
#include "../Core/Core.h"
#include "../Core/Expression.h"
#include <cassert>
#include <iostream>
#include <cmath>
#include <vector>

static void check_eval(Core& core, const std::string& expr, double expected) {
    Expression e(core);
    auto val = e.evaluate(expr);
    assert(val.is_scalar());
    double res = val.get_scalar(core);
    if (std::abs(res - expected) >= 0.0001) {
        std::cerr << "Eval failed for '" << expr << "': expected " << expected << ", got " << res << std::endl;
        assert(false);
    }
}

static void check_eval_str(Core& core, const std::string& expr, const std::string& expected) {
    Expression e(core);
    auto val = e.evaluate(expr);
    assert(val.is_string());
    if (val.string() != expected) {
        std::cerr << "Eval failed for '" << expr << "': expected \"" << expected << "\", got \"" << val.string() << "\"" << std::endl;
        assert(false);
    }
}

void test_expr_arithmetic() {
    Core core;
    check_eval(core, "1 + 2", 3.0);
    check_eval(core, "10 - 4", 6.0);
    check_eval(core, "3 * 4", 12.0);
    check_eval(core, "12 / 3", 4.0);
    check_eval(core, "10 % 3", 1.0);
    check_eval(core, "2 + 3 * 4", 14.0);
    check_eval(core, "(2 + 3) * 4", 20.0);
    check_eval(core, "-5 + 2", -3.0);
    check_eval(core, "+5 + 2", 7.0);
    check_eval(core, "10 / 0.5", 20.0);
}

void test_expr_bitwise() {
    Core core;
    check_eval(core, "0x0F & 0x03", 3.0);
    check_eval(core, "0x0F | 0xF0", 255.0);
    check_eval(core, "0x0F ^ 0xFF", 240.0);
    check_eval(core, "~0", 65535.0); 
    check_eval(core, "1 << 2", 4.0);
    check_eval(core, "8 >> 2", 2.0);
}

void test_expr_logical() {
    Core core;
    check_eval(core, "1 && 1", 1.0);
    check_eval(core, "1 && 0", 0.0);
    check_eval(core, "1 || 0", 1.0);
    check_eval(core, "0 || 0", 0.0);
    check_eval(core, "!1", 0.0);
    check_eval(core, "!0", 1.0);
    check_eval(core, "TRUE", 1.0);
    check_eval(core, "FALSE", 0.0);
}

void test_expr_comparison() {
    Core core;
    check_eval(core, "1 == 1", 1.0);
    check_eval(core, "1 != 2", 1.0);
    check_eval(core, "1 < 2", 1.0);
    check_eval(core, "2 > 1", 1.0);
    check_eval(core, "1 <= 1", 1.0);
    check_eval(core, "1 >= 1", 1.0);
    check_eval(core, "\"abc\" == \"abc\"", 1.0);
    check_eval(core, "\"abc\" != \"def\"", 1.0);
}

void test_expr_functions_math() {
    Core core;
    check_eval(core, "ABS(-10)", 10.0);
    check_eval(core, "SIGN(-5)", -1.0);
    check_eval(core, "SQRT(16)", 4.0);
    check_eval(core, "MIN(1, 2, 3)", 1.0);
    check_eval(core, "MAX(1, 2, 3)", 3.0);
    check_eval(core, "CLAMP(10, 0, 5)", 5.0);
    check_eval(core, "POW2(3)", 8.0);
    check_eval(core, "ALIGN(13, 4)", 16.0);
    check_eval(core, "WRAP(257, 256)", 1.0);
    check_eval(core, "INT(3.7)", 3.0);
    check_eval(core, "ROUND(3.7)", 4.0);
    check_eval(core, "CEIL(3.1)", 4.0);
    check_eval(core, "SIN(0)", 0.0);
    check_eval(core, "COS(0)", 1.0);
}

void test_expr_functions_string() {
    Core core;
    check_eval_str(core, "UPPER(\"abc\")", "ABC");
    check_eval_str(core, "LOWER(\"ABC\")", "abc");
    check_eval(core, "LEN(\"abc\")", 3.0);
    check_eval_str(core, "STR(123)", "123");
    check_eval(core, "VAL(\"123\")", 123.0);
    check_eval_str(core, "HEX(255)", "FF");
    check_eval_str(core, "BIN(5)", "101");
    
    // String concatenation
    check_eval_str(core, "\"Hello\" + \" \" + \"World\"", "Hello World");
    // String repetition
    check_eval_str(core, "\"A\" * 3", "AAA");
}

void test_expr_variables() {
    Core core;
    Expression e(core);
    e.assign("@myvar", Expression::Value(42.0));
    check_eval(core, "@myvar", 42.0);
    
    e.assign("@str", Expression::Value(std::string("test")));
    check_eval_str(core, "@str", "test");
}

void test_expr_collections() {
    Core core;
    Expression e(core);
    
    // Range
    auto v = e.evaluate("[1..3]");
    assert(v.is_address());
    assert(v.address().size() == 3);
    assert(v.address()[0] == 1);
    assert(v.address()[2] == 3);

    // Step
    v = e.evaluate("[1..5]:2");
    assert(v.address().size() == 3); // 1, 3, 5
    assert(v.address()[1] == 3);

    // Repeat
    v = e.evaluate("{0xAA} x 3");
    assert(v.is_bytes());
    assert(v.bytes().size() == 3);
    assert(v.bytes()[0] == 0xAA);

    // Indexing
    v = e.evaluate("[10, 20, 30][1]");
    assert(v.is_number());
    assert(v.number() == 20.0);
    
    // String indexing
    v = e.evaluate("\"ABC\"[1]");
    assert(v.is_number());
    assert(v.number() == 66.0); // 'B'
    
    // Collection concatenation
    v = e.evaluate("{1, 2} + {3, 4}");
    assert(v.is_bytes());
    assert(v.bytes().size() == 4);
    assert(v.bytes()[3] == 4);
    
    // Words
    v = e.evaluate("W{0x1234, 0x5678}");
    assert(v.is_words());
    assert(v.words().size() == 2);
    assert(v.words()[0] == 0x1234);
    
    // Address arithmetic
    // [10, 20] + 5 -> [15, 25]
    v = e.evaluate("[10, 20] + 5");
    assert(v.is_address());
    assert(v.address().size() == 2);
    assert(v.address()[0] == 15);
}

void test_expr_assignment() {
    Core core;
    Expression e(core);
    
    e.assign("lbl", Expression::Value(0x8000));
    auto sym = core.get_context().getSymbols().find("lbl");
    assert(sym != nullptr);
    assert(sym->read() == 0x8000);
    
    e.assign("@var", Expression::Value(10.0));
    check_eval(core, "@var", 10.0);
    
    // Array assignment
    e.assign("@arr", e.evaluate("{1, 2, 3}"));
    e.assign("@arr[1]", Expression::Value(5.0));
    auto v = e.evaluate("@arr[1]");
    assert(v.number() == 5.0);
    
    // Memory assignment via address list
    // [0x8000, 0x8001] = {0xAA, 0xBB}
    e.assign("[0x8000, 0x8001]", e.evaluate("{0xAA, 0xBB}"));
    assert(core.get_memory().peek(0x8000) == 0xAA);
    assert(core.get_memory().peek(0x8001) == 0xBB);

    // Words to bytes assignment
    e.assign("[0x9000, 0x9001]", e.evaluate("W{0x1234}"));
    assert(core.get_memory().peek(0x9000) == 0x34);
    assert(core.get_memory().peek(0x9001) == 0x12);
}

void test_expr_errors() {
    Core core;
    Expression e(core);
    try { e.evaluate("1 / 0"); assert(false); } catch (const Expression::Error&) {}
    try { e.evaluate("UNKNOWN_FUNC()"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::LOOKUP_UNKNOWN_SYMBOL); }
    try { e.evaluate("(1 + 2"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::SYNTAX_MISMATCHED_PARENTHESES); }
    try { e.evaluate("CLAMP(1)"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_NOT_ENOUGH_ARGUMENTS); }
}

void test_expr_asm() {
    Core core;
    Expression e(core);
    auto v = e.evaluate("ASM(\"NOP\")");
    assert(v.is_bytes());
    assert(v.bytes().size() == 1);
    assert(v.bytes()[0] == 0x00);
    
    v = e.evaluate("ASM(0x8000, \"JP 0\")");
    assert(v.is_bytes());
    assert(v.bytes().size() == 3);
    assert(v.bytes()[0] == 0xC3);
}

void test_expr_memory_access() {
    Core core;
    core.get_memory().poke(0x8000, 0x55);
    core.get_memory().poke(0x8001, 0xAA);
    
    Expression e(core);
    // [0x8000] creates address list.
    // [[0x8000]] dereferences it.
    auto v = e.evaluate("[[0x8000]]");
    assert(v.is_scalar());
    assert(v.get_scalar(core) == 0x55);
    
    // [[0x8000, 0x8001]] -> returns bytes {0x55, 0xAA}
    v = e.evaluate("[[0x8000, 0x8001]]");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
    assert(v.bytes()[0] == 0x55);
    assert(v.bytes()[1] == 0xAA);

    // Register indexing (base + offset)
    core.get_cpu().set_HL(0x8000);
    // HL[1] -> 0x8001 (Address type)
    v = e.evaluate("HL[1]");
    assert(v.is_address());
    assert(v.address()[0] == 0x8001);
    
    // [HL[1]] -> dereference 0x8001 -> 0xAA
    v = e.evaluate("[HL[1]]");
    assert(v.is_scalar());
    assert(v.get_scalar(core) == 0xAA);
}

void test_expr_boolean_logic() {
    Core core;
    check_eval(core, "(1 > 0) * 10 + (1 <= 0) * 20", 10.0);
    check_eval(core, "(0 > 0) * 10 + (0 <= 0) * 20", 20.0);
}

void test_expr_type_checks() {
    Core core;
    Expression e(core);
    
    try {
        e.evaluate("SIN(\"abc\")");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH);
    }
    
    try {
        e.evaluate("ASM(123)");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH);
    }
}

void test_expr_registers() {
    Core core;
    core.get_cpu().set_A(0x55);
    check_eval(core, "A", 85.0);
}

void test_expr_complex() {
    Core core;
    check_eval(core, "(1 + 2) * 3 + LEN(\"ABC\") + [10, 20][1]", 32.0);
}

void test_expr_precedence() {
    Core core;
    check_eval(core, "2 + 3 * 4", 14.0);
    check_eval(core, "(2 + 3) * 4", 20.0);
    // && (30) > || (20) -> 1 || (0 && 0) -> 1 || 0 -> 1
    check_eval(core, "1 || 0 && 0", 1.0);
    // & (60) > | (40) -> 1 | (2 & 4) -> 1 | 0 -> 1
    check_eval(core, "1 | 2 & 4", 1.0);
    // + (80) > << (70) -> (5 + 4) << 1 -> 9 << 1 -> 18
    check_eval(core, "5 + 4 << 1", 18.0);
}

void test_expr_functions_extra() {
    Core core;
    check_eval(core, "LOW(0x1234)", 0x34);
    check_eval(core, "HIGH(0x1234)", 0x12);
    check_eval(core, "BCD(12)", 18.0); // 12 decimal is 0x12 (18) in BCD representation logic here
    check_eval(core, "DEC(0x12)", 12.0);
    check_eval(core, "FLOOR(3.9)", 3.0);

    Expression e(core);
    auto v = e.evaluate("DEG(3.1415926535)");
    assert(std::abs(v.number() - 180.0) < 0.001);

    v = e.evaluate("RAD(180)");
    assert(std::abs(v.number() - 3.1415926535) < 0.001);
}

void test_expr_functions_stats() {
    Core core;
    check_eval(core, "SUM(1, 2, 3, 4)", 10.0);
    check_eval(core, "AVG(2, 4, 6)", 4.0);
    
    // ALL(v1, v2, ..., target) - checks if all values equal target
    check_eval(core, "ALL(1, 1, 1, 1)", 1.0); 
    check_eval(core, "ALL(1, 0, 1, 1)", 0.0);
    
    // ANY(v1, v2, ..., target) - checks if any value equals target
    check_eval(core, "ANY(0, 0, 1, 1)", 1.0);
    check_eval(core, "ANY(0, 0, 0, 1)", 0.0);
}

void test_expr_checksums() {
    Core core;
    check_eval(core, "CHECKSUM(1, 2, 3)", 6.0);
    
    Expression e(core);
    auto v = e.evaluate("CRC(1, 2, 3)");
    assert(v.is_number());
}

void test_expr_conversion() {
    Core core;
    Expression e(core);
    
    auto v = e.evaluate("BYTES(0x1234)");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
    // Little Endian
    assert(v.bytes()[0] == 0x34);
    assert(v.bytes()[1] == 0x12);
    
    v = e.evaluate("WORDS(0x12, 0x34)");
    assert(v.is_words());
    assert(v.words().size() == 2);
    assert(v.words()[0] == 0x12);
    assert(v.words()[1] == 0x34);
    
    v = e.evaluate("COPY({1, 2})");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
}

void test_expr_advanced_collections() {
    Core core;
    Expression e(core);
    
    // Reverse range
    auto v = e.evaluate("[3..1]");
    assert(v.is_address());
    assert(v.address().size() == 3);
    assert(v.address()[0] == 3);
    assert(v.address()[2] == 1);
    
    // Negative step
    v = e.evaluate("[5..1]:-2");
    assert(v.is_address());
    assert(v.address().size() == 3); 
    assert(v.address()[1] == 3);
    
    // Step on bytes
    v = e.evaluate("{10, 20, 30, 40}:2");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2); // 10, 30
    assert(v.bytes()[1] == 30);
}

void test_expr_string_manipulation() {
    Core core;
    check_eval_str(core, "\"ABCDEF\"[0..2]", "ABC");
    check_eval_str(core, "\"ABCDEF\"[5, 4, 3]", "FED");
    check_eval(core, "\"A\"[0]", 65.0);
    check_eval_str(core, "\"AB\" * 3", "ABABAB");
}

void test_expr_asm_advanced() {
    Core core;
    Expression e(core);
    
    // ASM with origin
    // ORG 0x8000; JP 0x8000 -> C3 00 80
    auto v = e.evaluate("ASM(0x8000, \"JP 0x8000\")");
    assert(v.is_bytes());
    assert(v.bytes().size() == 3);
    assert(v.bytes()[0] == 0xC3);
    assert(v.bytes()[1] == 0x00);
    assert(v.bytes()[2] == 0x80);
}

void test_expr_collection_logic() {
    Core core;
    check_eval(core, "ALL({1, 1, 1}, 1)", 1.0);
    check_eval(core, "ALL({1, 0, 1}, 1)", 0.0);
    check_eval(core, "ANY({0, 0, 1}, 1)", 1.0);
    check_eval(core, "ANY({0, 0, 0}, 1)", 0.0);
}

void test_expr_unary_collection() {
    Core core;
    Expression e(core);
    // Negate bytes
    auto v = e.evaluate("-{1, 2}");
    assert(v.is_bytes());
    assert(v.bytes()[0] == 0xFF); // -1
    assert(v.bytes()[1] == 0xFE); // -2
    
    // Negate words
    v = e.evaluate("-W{1, 2}");
    assert(v.is_words());
    assert(v.words()[0] == 0xFFFF);
    assert(v.words()[1] == 0xFFFE);
}

void test_expr_literals() {
    Core core;
    // Hex
    check_eval(core, "$10", 16.0);
    check_eval(core, "$FF", 255.0);
    // Binary
    check_eval(core, "%10", 2.0);
    check_eval(core, "%1111", 15.0);
    // Char
    check_eval(core, "'A'", 65.0);
    check_eval(core, "' '", 32.0);
}

void test_expr_collection_arithmetic_advanced() {
    Core core;
    Expression e(core);
    
    // Scalar + Address
    auto v = e.evaluate("5 + [10, 20]");
    assert(v.is_address());
    assert(v.address()[0] == 15);
    assert(v.address()[1] == 25);
    
    // Address - Scalar
    v = e.evaluate("[10, 20] - 5");
    assert(v.is_address());
    assert(v.address()[0] == 5);
    assert(v.address()[1] == 15);
    
    // Scalar - Address
    v = e.evaluate("20 - [5, 10]");
    assert(v.is_address());
    assert(v.address()[0] == 15);
    assert(v.address()[1] == 10);
    
    // Address + Address
    v = e.evaluate("[10, 20] + [1, 2]");
    assert(v.is_address());
    assert(v.address()[0] == 11);
    assert(v.address()[1] == 22);
    
    // Address - Address
    v = e.evaluate("[10, 20] - [1, 2]");
    assert(v.is_address());
    assert(v.address()[0] == 9);
    assert(v.address()[1] == 18);
}

void test_expr_memory_fill() {
    Core core;
    Expression e(core);
    
    // Fill memory range with pattern
    e.assign("[0x9000..0x9003]", e.evaluate("{0x11, 0x22} x 2"));
    assert(core.get_memory().peek(0x9000) == 0x11);
    assert(core.get_memory().peek(0x9001) == 0x22);
    assert(core.get_memory().peek(0x9002) == 0x11);
    assert(core.get_memory().peek(0x9003) == 0x22);
}

void test_expr_asm_labels() {
    Core core;
    Expression e(core);
    
    // Define a label
    e.assign("my_label", Expression::Value(0x1234));
    
    // Use label in ASM
    auto v = e.evaluate("ASM(0x8000, \"JP my_label\")");
    assert(v.is_bytes());
    assert(v.bytes().size() == 3);
    assert(v.bytes()[0] == 0xC3); // JP
    assert(v.bytes()[1] == 0x34); // Low byte
    assert(v.bytes()[2] == 0x12); // High byte
}

void test_expr_string_escapes() {
    Core core;
    check_eval_str(core, "\"Line1\\nLine2\"", "Line1\nLine2");
    check_eval_str(core, "\"\\\"Quote\\\"\"", "\"Quote\"");
    check_eval_str(core, "\"\\\\\"", "\\");
}

void test_expr_empty_collections() {
    Core core;
    Expression e(core);
    auto v = e.evaluate("{}");
    assert(v.is_bytes());
    assert(v.bytes().empty());

    v = e.evaluate("[]");
    assert(v.is_address());
    assert(v.address().empty());
    
    v = e.evaluate("W{}");
    assert(v.is_words());
    assert(v.words().empty());
}

void test_expr_nested_collections() {
    Core core;
    Expression e(core);
    // Flattening test
    auto v = e.evaluate("{{1, 2}, {3, 4}}");
    assert(v.is_bytes());
    assert(v.bytes().size() == 4);
    assert(v.bytes()[0] == 1);
    assert(v.bytes()[3] == 4);
    
    v = e.evaluate("[{10, 20}, 30]");
    assert(v.is_address());
    assert(v.address().size() == 3);
    assert(v.address()[0] == 10);
    assert(v.address()[2] == 30);
}

void test_expr_asm_variables() {
    Core core;
    Expression e(core);
    e.assign("@val", Expression::Value(10.0));
    // ASM uses variables as symbols with @ prefix
    // "LD A, @val" -> LD A, 10 -> 3E 0A
    auto v = e.evaluate("ASM(\"LD A, @val\")");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
    assert(v.bytes()[0] == 0x3E);
    assert(v.bytes()[1] == 0x0A);
}

void test_expr_mixed_string_concat() {
    Core core;
    check_eval_str(core, "\"Val: \" + 10", "Val: 10");
    check_eval_str(core, "10 + \" items\"", "10 items");
    // A is 0 by default
    check_eval_str(core, "\"Reg A: \" + A", "Reg A: 0"); 
}

void test_expr_case_insensitivity() {
    Core core;
    check_eval(core, "len(\"abc\")", 3.0);
    check_eval(core, "LEN(\"abc\")", 3.0);
    check_eval(core, "LeN(\"abc\")", 3.0);
    
    core.get_cpu().set_A(10);
    check_eval(core, "a", 10.0);
    check_eval(core, "A", 10.0);
}

void test_expr_address_validation() {
    Core core;
    Expression e(core);
    try {
        e.evaluate("[70000]");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING);
    }
    
    try {
        e.evaluate("[-1]");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING);
    }
}

void test_expr_bitwise_negative() {
    Core core;
    // -1 is 0xFFFFFFFF... in 2's complement. Cast to int preserves bits.
    // -1 & 0xFF -> 0xFF
    check_eval(core, "-1 & 0xFF", 255.0);
    check_eval(core, "-2 & 0xFF", 254.0); // ...1110 & 0xFF -> 0xFE
}

void test_expr_predefined_vars() {
    Core core;
    // SCREEN_WIDTH is added in Variables constructor
    check_eval(core, "@SCREEN_WIDTH", 256.0);
}

void test_expr_syntax_errors() {
    Core core;
    Expression e(core);
    try { e.evaluate("\"abc"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::SYNTAX_UNTERMINATED_STRING); }
    try { e.evaluate("1 @ 2"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::SYNTAX_UNEXPECTED_CHARACTER); }
}

void test_expr_math_edge_cases() {
    Core core;
    check_eval(core, "ALIGN(10, 0)", 10.0); // Base 0 -> returns val
    check_eval(core, "WRAP(10, 0)", 0.0);   // Limit 0 -> returns 0
    
    Expression e(core);
    try { e.evaluate("10 % 0"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::GENERIC); } // Div by zero
    try { e.evaluate("[1..10]:0"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING); } // Step 0
}

void test_expr_system_vars_syntax() {
    Core core;
    Expression e(core);
    // Cannot create system variable
    try { 
        e.assign("@@newvar", Expression::Value(1.0)); 
        assert(false); 
    } catch (const Expression::Error& err) { 
        assert(err.code() == Expression::ErrorCode::LOOKUP_UNKNOWN_VARIABLE); 
    }
    
    // Cannot access non-system variable with @@
    e.assign("@myvar", Expression::Value(1.0));
    try { e.evaluate("@@myvar"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::LOOKUP_UNKNOWN_VARIABLE); }
}

void test_expr_collection_invalid_ops() {
    Core core;
    Expression e(core);
    try { e.evaluate("~{1, 2}"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }
    try { e.evaluate("!{1, 2}"); assert(false); } catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }
}

void test_expr_string_assignment() {
    Core core;
    Expression e(core);
    e.assign("@s", Expression::Value(std::string("hello")));
    e.assign("@s[0]", Expression::Value((double)'H'));
    check_eval_str(core, "@s", "Hello");
}

void test_expr_collection_functions() {
    Core core;
    // MIN/MAX on collections (flattening)
    check_eval(core, "MIN({10, 5, 20})", 5.0);
    check_eval(core, "MAX({10, 5, 20})", 20.0);
    
    // CLAMP on collection (mapping)
    Expression e(core);
    auto v = e.evaluate("CLAMP({0, 10, 20}, 5, 15)");
    assert(v.is_bytes());
    assert(v.bytes().size() == 3);
    assert(v.bytes()[0] == 5);
    assert(v.bytes()[1] == 10);
    assert(v.bytes()[2] == 15);
}

void test_expr_collection_indexing_list() {
    Core core;
    Expression e(core);
    // Indexing with list of indices
    auto v = e.evaluate("{10, 20, 30, 40}[0, 2]");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
    assert(v.bytes()[0] == 10);
    assert(v.bytes()[1] == 30);
}

void test_expr_unary_address() {
    Core core;
    Expression e(core);
    auto v = e.evaluate("-[1, 2]");
    assert(v.is_address());
    assert(v.address().size() == 2);
    assert(v.address()[0] == (uint16_t)-1);
    assert(v.address()[1] == (uint16_t)-2);
}

void test_expr_words_concat() {
    Core core;
    Expression e(core);
    auto v = e.evaluate("W{1} + W{2}");
    assert(v.is_words());
    assert(v.words().size() == 2);
    assert(v.words()[0] == 1);
    assert(v.words()[1] == 2);
}

void test_expr_misc_coverage() {
    Core core;
    Expression e(core);

    // 1. Register Assignment
    e.assign("A", Expression::Value(42.0));
    assert(core.get_cpu().get_A() == 42);
    
    // 2. Symbol Redefinition
    e.assign("MyLabel", Expression::Value(100.0));
    check_eval(core, "MyLabel", 100.0);
    e.assign("MyLabel", Expression::Value(200.0));
    check_eval(core, "MyLabel", 200.0);
    
    // 3. Empty function arguments
    check_eval(core, "SUM()", 0.0);
    check_eval(core, "AVG()", 0.0);
    
    // 4. Scalar Repeat Error (10 x 5) - implementation enforces collection on LHS
    try {
        e.evaluate("10 x 5");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH);
    }

    // 5. Empty expression
    check_eval(core, "", 0.0);
    check_eval(core, "   ", 0.0);

    // 6. System variable assignment (Read Only)
    // Note: Variables::add sets up system vars. Assuming they throw on setValue or assign logic handles it.
    // Based on Expression.cpp assign logic, it calls var->setValue(rhs).
    // If Variable implementation forbids it, it throws. We assume standard system vars are protected.
}

void test_expr_remaining_coverage() {
    Core core;
    Expression e(core);

    // 1. Address Assignment Extension (Overflow)
    // [0x8000] has 1 element, but we assign 2 bytes. Should write to 0x8000 and 0x8001.
    e.assign("[0x8000]", e.evaluate("{0x11, 0x22}"));
    assert(core.get_memory().peek(0x8000) == 0x11);
    assert(core.get_memory().peek(0x8001) == 0x22);

    // 2. Repeat Negative Error
    try { e.evaluate("{1} x -1"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING); }

    // 3. Range Errors
    // Out of 16-bit bounds
    try { e.evaluate("[0..70000]"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING); }
    // Range too large (> 65536 items)
    try { e.evaluate("[-32768..32769]"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING); }

    // 4. Range Syntax Error (.. outside collection)
    try { e.evaluate("1..2"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::SYNTAX_UNEXPECTED_CHARACTER); }

    // 5. String Identity and Bin Zero
    check_eval_str(core, "STR(\"abc\")", "abc");
    check_eval_str(core, "BIN(0)", "0");

    // 6. Empty ALL/ANY
    check_eval(core, "ALL()", 0.0);
    check_eval(core, "ANY()", 0.0);

    // 7. Register Indexing with List
    core.get_cpu().set_HL(0x1000);
    auto v = e.evaluate("HL[1, 2]");
    assert(v.is_address());
    assert(v.address().size() == 2);
    assert(v.address()[0] == 0x1001);
    assert(v.address()[1] == 0x1002);

    // 8. Copy String
    check_eval_str(core, "COPY(\"test\")", "test");

    // 9. Assign to empty address list
    try { e.assign("[]", Expression::Value(1.0)); assert(false); }
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING); }
}

void test_expr_final_coverage() {
    Core core;
    Expression e(core);

    // 1. S8 function (Signed 8-bit)
    check_eval(core, "S8(255)", -1.0);
    check_eval(core, "S8(128)", -128.0);
    check_eval(core, "S8(127)", 127.0);

    // 2. Aliases LO/HI
    check_eval(core, "LO(0x1234)", 0x34);
    check_eval(core, "HI(0x1234)", 0x12);

    // 3. Assign non-scalar to register/symbol errors
    try { e.assign("A", e.evaluate("{1, 2}")); assert(false); }
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }
    
    e.assign("MyLbl", Expression::Value(10.0));
    try { e.assign("MyLbl", e.evaluate("{1, 2}")); assert(false); }
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }

    // 4. Assign to read-only system variable
    // @@SCREEN_WIDTH is defined in Variables.cpp
    try { 
        e.assign("@@SCREEN_WIDTH", Expression::Value(100.0)); 
        assert(false); 
    } catch (const std::exception&) { 
        // Variable::setValue throws std::runtime_error for system vars
    }

    // 5. Collection index out of bounds
    try { e.evaluate("{1, 2}[5]"); assert(false); }
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_INVALID_INDEXING); }

    // 6. Unary plus on collection
    auto v = e.evaluate("+{1, 2}");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
    assert(v.bytes()[0] == 1);

    // 7. VAL with invalid string
    check_eval(core, "VAL(\"invalid\")", 0.0);

    // 8. LEN on scalar
    check_eval(core, "LEN(123)", 1.0);
    
    // 9. Assign scalar to memory address list
    e.assign("[0x8000]", Expression::Value(0x55));
    assert(core.get_memory().peek(0x8000) == 0x55);
}

void test_expr_edge_cases_2() {
    Core core;
    Expression e(core);

    // 1. Indexing function result (Implicit index op after RPAREN)
    // BYTES(1, 2) returns {1, 2}. [0] should return 1.
    check_eval(core, "BYTES(1, 2)[0]", 1.0);

    // 2. Empty repeat
    auto v = e.evaluate("{1} x 0");
    assert(v.is_bytes());
    assert(v.bytes().empty());

    // 3. Single item range
    v = e.evaluate("[1..1]");
    assert(v.is_address());
    assert(v.address().size() == 1);
    assert(v.address()[0] == 1);

    // 4. Address slicing (Address type indexing with list)
    v = e.evaluate("[10, 20, 30][0, 2]");
    assert(v.is_address());
    assert(v.address().size() == 2);
    assert(v.address()[0] == 10);
    assert(v.address()[1] == 30);

    // 5. Negative HEX
    // HEX(-1) -> FFFFFFFFFFFFFFFF (64-bit)
    check_eval_str(core, "HEX(-1)", "FFFFFFFFFFFFFFFF");

    // 6. System Variable Access Rules
    // Manually add a system variable to context for testing
    Variable sysVar("SYS", []() { return Expression::Value(99.0); }, "System Var");
    core.get_context().getVariables().add(sysVar);

    // Access with @@ should work
    check_eval(core, "@@SYS", 99.0);

    // Access with @ should fail
    try { e.evaluate("@SYS"); assert(false); }
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::LOOKUP_UNKNOWN_VARIABLE); }
}

void test_expr_gap_coverage() {
    Core core;
    Expression e(core);

    // 1. Accessing non-existent variable
    try {
        e.evaluate("@nonexistent");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::LOOKUP_UNKNOWN_VARIABLE);
    }

    // 2. Address list creation from Words
    auto v = e.evaluate("[W{0x1234, 0x5678}]");
    assert(v.is_address());
    assert(v.address().size() == 2);
    assert(v.address()[0] == 0x1234);
    assert(v.address()[1] == 0x5678);

    // 3. Words collection flattening
    v = e.evaluate("W{ W{1, 2}, 3 }");
    assert(v.is_words());
    assert(v.words().size() == 3);
    assert(v.words()[0] == 1);
    assert(v.words()[2] == 3);

    // 4. Negative step on Words
    v = e.evaluate("W{10, 20, 30}:-1");
    assert(v.is_words());
    assert(v.words().size() == 3);
    assert(v.words()[0] == 30);
    assert(v.words()[2] == 10);

    // 5. Indexing Words
    check_eval(core, "W{10, 20}[1]", 20.0);
    v = e.evaluate("W{10, 20, 30}[0, 2]");
    assert(v.is_words());
    assert(v.words().size() == 2);
    assert(v.words()[0] == 10);
    assert(v.words()[1] == 30);
}

void test_expr_final_edge_cases() {
    Core core;
    Expression e(core);

    // 1. Step operator on scalar (should be error)
    try {
        e.evaluate("10:2");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH);
    }

    // 2. COPY on scalar (identity)
    check_eval(core, "COPY(123)", 123.0);

    // 3. ASM semicolon replacement
    // "NOP; NOP" -> 00 00
    auto v = e.evaluate("ASM(\"NOP; NOP\")");
    assert(v.is_bytes());
    assert(v.bytes().size() == 2);
    assert(v.bytes()[0] == 0x00);
    assert(v.bytes()[1] == 0x00);

    // 4. SIGN of zero
    check_eval(core, "SIGN(0)", 0.0);

    // 5. Partial memory assignment (LHS larger than RHS)
    // [0x9000, 0x9001] = {0x55} -> Only 0x9000 written
    core.get_memory().poke(0x9000, 0x00);
    core.get_memory().poke(0x9001, 0x00);
    e.assign("[0x9000, 0x9001]", e.evaluate("{0x55}"));
    assert(core.get_memory().peek(0x9000) == 0x55);
    assert(core.get_memory().peek(0x9001) == 0x00);

    // 6. Indexing scalar (should be error)
    try {
        e.evaluate("10[0]");
        assert(false);
    } catch (const Expression::Error& err) {
        assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH);
    }
}

void test_expr_negative_cases() {
    Core core;
    Expression e(core);

    // 1. Missing parenthesis after function
    try { e.evaluate("SIN 10"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::SYNTAX_UNEXPECTED_CHARACTER); }

    // 2. Mixed brackets
    try { e.evaluate("[1, 2}"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::SYNTAX_MISMATCHED_PARENTHESES); }

    // 3. Ambiguous result (missing operator)
    try { e.evaluate("1 2"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::GENERIC); }

    // 4. Invalid assignment target
    try { e.assign("10", Expression::Value(20.0)); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }

    // 5. Invalid type in address list
    try { e.evaluate("[\"abc\"]"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }

    // 6. ASM argument count
    try { e.evaluate("ASM()"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }
    try { e.evaluate("ASM(1, 2, 3)"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_TYPE_MISMATCH); }

    // 7. @@ on regular variable
    e.assign("@regvar", Expression::Value(1.0));
    try { e.assign("@@regvar", Expression::Value(2.0)); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::GENERIC); }

    // 8. Not enough operands
    try { e.evaluate("1 +"); assert(false); } 
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_NOT_ENOUGH_OPERANDS); }
    
    // 9. Binary operator at start
    try { e.evaluate("* 1"); assert(false); }
    catch (const Expression::Error& err) { assert(err.code() == Expression::ErrorCode::EVAL_NOT_ENOUGH_OPERANDS); }
}