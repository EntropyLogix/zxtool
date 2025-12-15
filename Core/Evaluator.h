#pragma once
#include "Core.h"
#include <string>
#include <vector>
#include <stack>
#include <stdexcept>
#include <cstdint>
#include <map>
#include <functional>
#include <cmath>
#include <variant>
#include <sstream>
#include <iomanip>

// Define Value type to hold double, string, or array
struct Value {
    std::variant<double, std::string, std::vector<Value>> data;

    Value() : data(0.0) {}
    Value(double d) : data(d) {}
    Value(int i) : data(static_cast<double>(i)) {}
    Value(const std::string& s) : data(s) {}
    Value(const char* s) : data(std::string(s)) {}
    Value(const std::vector<Value>& v) : data(v) {}

    bool is_number() const { return std::holds_alternative<double>(data); }
    bool is_string() const { return std::holds_alternative<std::string>(data); }
    bool is_array() const { return std::holds_alternative<std::vector<Value>>(data); }

    double as_number() const {
        if (is_number()) return std::get<double>(data);
        throw std::runtime_error("Value is not a number");
    }

    std::string as_string() const {
        if (is_string()) return std::get<std::string>(data);
        if (is_number()) {
            std::stringstream ss;
            ss << std::defaultfloat << std::get<double>(data);
            return ss.str();
        }
        throw std::runtime_error("Value is not a string");
    }

    const std::vector<Value>& as_array() const {
        if (is_array()) return std::get<std::vector<Value>>(data);
        throw std::runtime_error("Value is not an array");
    }
};

class Evaluator {
public:
    Evaluator(Core& core);

    // Zwraca Value
    Value evaluate(const std::string& expression);

    // Przyjmuje Value
    void assign(const std::string& target, Value value);

    static bool is_register(const std::string& name);

private:
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

    enum class TokenType {
        NUMBER,     
        OPERATOR,   
        FUNCTION,
        LPAREN,     
        RPAREN,     
        LBRACKET,   
        RBRACKET,
        COMMA,
        LBRACE,      // {
        RBRACE,      // }
        ARRAY_BUILD  // Instrukcja budowania tablicy (wartość to liczba elementów)
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

    std::vector<Token> tokenize(const std::string& expression);
    std::vector<Token> shunting_yard(const std::vector<Token>& tokens);
    Value execute_rpn(const std::vector<Token>& rpn);

    double resolve_symbol(const std::string& name);
    void set_register_value(const std::string& name, Value value);
};