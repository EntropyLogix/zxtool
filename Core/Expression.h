#ifndef __EXPRESSION_H__
#define __EXPRESSION_H__

#include "CoreIncludes.h"

#include "Symbol.h"
#include "Register.h"
#include <string>
#include <vector>
#include <stack>
#include <stdexcept>
#include <cstdint>
#include <map>
#include <functional>
#include <cmath>
#include <sstream>
#include <iomanip>

class Core;

class Expression {
public:
    enum class ErrorCode {
        LOOKUP_UNKNOWN_VARIABLE,
        LOOKUP_UNKNOWN_SYMBOL,
        SYNTAX_UNTERMINATED_STRING,
        SYNTAX_UNEXPECTED_CHARACTER,
        SYNTAX_MISMATCHED_PARENTHESES,
        EVAL_NOT_ENOUGH_OPERANDS,
        EVAL_NOT_ENOUGH_ARGUMENTS,
        EVAL_MIXING_CONTAINERS,
        EVAL_INVALID_INDEXING,
        EVAL_TYPE_MISMATCH,
        INTERNAL_ERROR,
        GENERIC
    };

    class Error : public std::exception {
    public:
        Error(ErrorCode code, const std::string& detail = "");
        ErrorCode code() const { return m_code; }
        const std::string& detail() const { return m_detail; }
        const char* what() const noexcept override;
    private:
        ErrorCode m_code;
        std::string m_detail;
        std::string m_message;
    };

    class Value {
    public:
        enum class Type { Number, Register, Address, Symbol, String, Bytes, Words };

        Value() = default;
        Value(double d) : m_number(d), m_type(Type::Number) {}
        Value(int i) : m_number(i), m_type(Type::Number) {}
        Value(const Register& reg) : m_reg(reg), m_type(Type::Register) {}
        Value(const Symbol& sym) : m_symbol(sym), m_type(Type::Symbol) {}
        Value(const std::string& s) : m_string(s), m_type(Type::String) {}
        Value(const std::vector<uint16_t>& addrs) : m_address(addrs), m_type(Type::Address) {}
        Value(const std::vector<uint16_t>& words, bool) : m_words(words), m_type(Type::Words) {}
        Value(const std::vector<uint8_t>& bytes) : m_bytes(bytes), m_type(Type::Bytes) {}
        
        bool is_number() const { return m_type == Type::Number; }
        bool is_register() const { return m_type == Type::Register; }
        bool is_address() const { return m_type == Type::Address; }
        bool is_symbol() const { return m_type == Type::Symbol; }
        bool is_string() const { return m_type == Type::String; }
        bool is_bytes() const { return m_type == Type::Bytes; }
        bool is_words() const { return m_type == Type::Words; }
        bool is_scalar() const { return m_type == Type::Number || m_type == Type::Register || m_type == Type::Symbol; }
        bool is_array() const { return m_type == Type::Address || m_type == Type::Bytes || m_type == Type::Words; }
        
        double number() const { return m_number; }
        const Register& reg() const { return m_reg; }
        const Symbol& symbol() const { return m_symbol; }
        const std::string& string() const { return m_string; }
        const std::vector<uint16_t>& address() const { return m_address; }
        const std::vector<uint8_t>& bytes() const { return m_bytes; }
        const std::vector<uint16_t>& words() const { return m_words; }

        Type type() const { return m_type; }
        double get_scalar(Core& core) const;

    private:
        Type m_type = Type::Number;
        double m_number = 0.0;
        Register m_reg;
        std::vector<uint16_t> m_address;
        Symbol m_symbol;
        std::string m_string;
        std::vector<uint8_t> m_bytes;
        std::vector<uint16_t> m_words;
    };

    Expression(Core& core);
    ~Expression() = default;

    Value evaluate(const std::string& expression);

private:
    enum class TokenType {
        UNKNOWN,
        NUMBER,     
        OPERATOR,   
        FUNCTION,
        REGISTER,
        SYMBOL,
        STRING,
        LPAREN,     
        RPAREN,     
        COMMA,
        LBRACKET,
        RBRACKET,
        LBRACE,
        RBRACE,
        ADDRESS,
        BYTES,
        WORDS,
        LBRACE_W
    };
    Core& m_core;
    struct OperatorInfo {
        int precedence;
        bool left_assoc;
        bool is_unary;
        Value (Expression::*apply)(const std::vector<Value>&);
        std::vector<std::vector<Value::Type>> signatures;
        void check(const std::string& name, const std::vector<Value>& args) const {
            check_types(name, args, signatures);
        }
    };
    struct FunctionInfo {
        int num_args;
        Value (Expression::*apply)(const std::vector<Value>&);
        std::vector<std::vector<Value::Type>> signatures;
        void check(const std::string& name, const std::vector<Value>& args) const {
            check_types(name, args, signatures);
        }
    };
    struct Token {
        TokenType type;
        Value value;
        std::string symbol; 
        const OperatorInfo* op_info = nullptr;
        const FunctionInfo* func_info = nullptr;
    };

    static const std::map<std::string, OperatorInfo>& get_operators();
    static const std::map<std::string, FunctionInfo>& get_functions();

    bool parse_operator(const std::string& expr, size_t& index, std::vector<Token>& tokens);
    bool parse_punctuation(const std::string& expr, size_t& index, std::vector<Token>& tokens);
    std::string parse_word(const std::string& expr, size_t& index);
    bool parse_number(const std::string& word, std::vector<Token>& tokens);
    bool parse_register(const std::string& word, std::vector<Token>& tokens);
    bool parse_symbol(const std::string& word, std::vector<Token>& tokens);
    bool parse_variable(const std::string& expr, size_t& index, std::vector<Token>& tokens);
    bool parse_string(const std::string& expr, size_t& index, std::vector<Token>& tokens);
    bool parse_function(const std::string& word, std::vector<Token>& tokens);

    std::vector<Token> tokenize(const std::string& expression);
    std::vector<Token> shunting_yard(const std::vector<Token>& tokens);
    Value execute_rpn(const std::vector<Token>& rpn);

    static void check_types(const std::string& name, const std::vector<Value>& args, const std::vector<std::vector<Value::Type>>& signatures) {
        if (signatures.empty()) return;
        for (const auto& sig : signatures) {
            if (sig.size() != args.size()) continue;
            bool match = true;
            for (size_t i = 0; i < args.size(); ++i) {
                if (args[i].type() != sig[i]) {
                    match = false;
                    break;
                }
            }
            if (match) return;
        }
        throw Error(ErrorCode::EVAL_TYPE_MISMATCH, "Type mismatch for " + name);
    }

    static void syntax_error(ErrorCode code, const std::string& detail = "");

    Value operator_unary_minus(const std::vector<Value>& args);
    Value operator_unary_plus(const std::vector<Value>& args);
    Value operator_plus(const std::vector<Value>& args);
    Value operator_minus(const std::vector<Value>& args);
    Value operator_index(const std::vector<Value>& args);

    Value function_low(const std::vector<Value>& args);
    Value function_high(const std::vector<Value>& args);
    Value function_word(const std::vector<Value>& args);
};

#endif//__EXPRESSION_H__