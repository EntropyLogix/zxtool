#ifndef __EVALUATOR_H__
#define __EVALUATOR_H__

#include "CoreIncludes.h"

#include "Core.h"
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

class Value {
public:
    enum class Type { Number, Register, Address, Symbol, String };

    Value() = default;
    Value(double d) : m_number(d), m_type(Type::Number) {}
    Value(int i) : m_number(i), m_type(Type::Number) {}
    Value(const Register& reg) : m_reg(reg), m_type(Type::Register) {}
    Value(const Symbol& sym) : m_symbol(sym), m_type(Type::Symbol) {}
    Value(const std::string& s) : m_string(s), m_type(Type::String) {}
    Value(const std::vector<uint16_t>& addrs) : m_address(addrs), m_type(Type::Address) {}
    
    bool is_number() const { return m_type == Type::Number; }
    bool is_register() const { return m_type == Type::Register; }
    bool is_address() const { return m_type == Type::Address; }
    bool is_symbol() const { return m_type == Type::Symbol; }
    bool is_string() const { return m_type == Type::String; }
    
    double number() const { return m_number; }
    const Register& reg() const { return m_reg; }
    const Symbol& symbol() const { return m_symbol; }
    const std::string& string() const { return m_string; }
    const std::vector<uint16_t>& address() const { return m_address; }
    
    operator double() const { return m_number; }

private:
    Type m_type = Type::Number;
    double m_number = 0.0;
    Register m_reg;
    std::vector<uint16_t> m_address;
    Symbol m_symbol;
    std::string m_string;
};

class Evaluator {
public:
    Evaluator(Core& core);

    Value evaluate(const std::string& expression);

private:
    enum class TokenType {
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
        LIST
    };

    Core& m_core;

    struct OperatorInfo {
        int precedence;
        bool left_assoc;
        bool is_unary;
        std::function<Value(Core&, const std::vector<Value>&)> apply;
    };

    struct FunctionInfo {
        int num_args;
        std::function<Value(Core&, const std::vector<Value>&)> apply;
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
    bool parse_string(const std::string& expr, size_t& index, std::vector<Token>& tokens);
    bool parse_function(const std::string& word, std::vector<Token>& tokens);

    std::vector<Token> tokenize(const std::string& expression);
    std::vector<Token> shunting_yard(const std::vector<Token>& tokens);
    Value execute_rpn(const std::vector<Token>& rpn);
};

#endif//__EVALUATOR_H__