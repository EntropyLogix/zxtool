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

class Evaluator {
public:
    Evaluator(Core& core);

    // Zwraca double (np. 2.5)
    double evaluate(const std::string& expression);

    // Przyjmuje double, ale rzutuje go wewnętrznie na uint16_t przy zapisie
    void assign(const std::string& target, double value);

    static bool is_register(const std::string& name);

private:
    Core& m_core;

    struct OperatorInfo {
        int precedence;
        bool left_assoc;
        bool is_unary;
        std::function<double(Core&, const std::vector<double>&)> apply;
    };

    struct FunctionInfo {
        int num_args;
        std::function<double(Core&, const std::vector<double>&)> apply;
    };

    enum class TokenType {
        NUMBER,     
        OPERATOR,   
        FUNCTION,
        LPAREN,     
        RPAREN,     
        LBRACKET,   
        RBRACKET,
        COMMA
    };

    struct Token {
        TokenType type;
        double value;
        std::string symbol; 
        const OperatorInfo* op_info = nullptr;
        const FunctionInfo* func_info = nullptr;
    };

    static const std::map<std::string, OperatorInfo>& get_operators();
    static const std::map<std::string, FunctionInfo>& get_functions();

    std::vector<Token> tokenize(const std::string& expression);
    std::vector<Token> shunting_yard(const std::vector<Token>& tokens);
    double execute_rpn(const std::vector<Token>& rpn);

    double resolve_symbol(const std::string& name);
    void set_register_value(const std::string& name, double value);
};