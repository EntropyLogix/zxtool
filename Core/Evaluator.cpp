#include "Evaluator.h"
#include "../Utils/Strings.h"
#include <cctype>
#include <algorithm>

Evaluator::Evaluator(Core& core) : m_core(core) {}

const std::map<std::string, Evaluator::OperatorInfo>& Evaluator::get_operators() {
    static const std::map<std::string, OperatorInfo> ops = {
        {"_",   {100, false, true,  [](Core&, const std::vector<Value>& args) { return -args[0].number(); }}},
        {"+",   {80, true,  false, [](Core&, const std::vector<Value>& args) { return Value(args[0].number() + args[1].number()); }}},
        {"-",   {80, true,  false, [](Core&, const std::vector<Value>& args) { return args[0].number() - args[1].number(); }}},
    };
    return ops;
}

const std::map<std::string, Evaluator::FunctionInfo>& Evaluator::get_functions() {
    static const std::map<std::string, FunctionInfo> funcs = {
        {"LOW",  {1, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].number() & 0xFF); }}},
        {"HIGH", {1, [](Core&, const std::vector<Value>& args) { return (double)(((int)args[0].number() >> 8) & 0xFF); }}},
        {"WORD", {2, [](Core&, const std::vector<Value>& args) { return (double)((((int)args[0].number() & 0xFF) << 8) | ((int)args[1].number() & 0xFF)); }}}
    };
    return funcs;
}

Value Evaluator::evaluate(const std::string& expression) {
    if (expression.empty())
        return Value(0.0);
    auto tokens = tokenize(expression);
    auto rpn = shunting_yard(tokens);
    return execute_rpn(rpn);
}

bool Evaluator::parse_operator(const std::string& expr, size_t& i, std::vector<Token>& tokens) {
    auto& ops_map = get_operators();
    std::string matched_op;
    const OperatorInfo* op_info = nullptr;
    for (const auto& pair : ops_map) {
        const std::string& op_sym = pair.first;
        if (expr.substr(i, op_sym.length()) == op_sym) {
            if (op_sym == "-" && (tokens.empty() || tokens.back().type == TokenType::OPERATOR || tokens.back().type == TokenType::LPAREN || tokens.back().type == TokenType::COMMA)) {
                auto it = ops_map.find("_");
                if (it != ops_map.end()) {
                    matched_op = "_";
                    op_info = &it->second;
                }
            }
            else {
                if (op_sym.length() > matched_op.length()) {
                    matched_op = op_sym;
                    op_info = &pair.second;
                }
            }
        }
    }
    if (!matched_op.empty()) {
        size_t consume = (matched_op == "_") ? 1 : matched_op.length();
        tokens.push_back({TokenType::OPERATOR, Value(0.0), matched_op, op_info});
        i += consume;
        return true;
    }
    return false;
}

bool Evaluator::parse_punctuation(const std::string& expr, size_t& i, std::vector<Token>& tokens) {
    char c = expr[i];
    TokenType type;
    switch (c) {
        case '(':
            type = TokenType::LPAREN;
            break;
        case ')':
            type = TokenType::RPAREN;
            break;
        case ',':
            type = TokenType::COMMA;
            break;
        default:
            return false;
    }
    tokens.push_back({type});
    i++;
    return true;
}

std::string Evaluator::parse_word(const std::string& expr, size_t& index) {
    std::string word;
    while (index < expr.length()) {
        char c = expr[index];
        if (std::isalnum(c) || c == '$' || c == '_' || c == '.' || c == '%') {
            word += c;
            index++;
        } else
            break;
    }
    return word;
}

bool Evaluator::parse_number(const std::string& word, std::vector<Token>& tokens) {
    double d_val;
    if (Strings::parse_double(word, d_val)) {
        tokens.push_back({TokenType::NUMBER, Value(d_val)});
        return true;
    }
    return false;
}

bool Evaluator::parse_register(const std::string& word, std::vector<Token>& tokens) {
    std::string upper_word = Strings::upper(word);
    if (Register::is_valid(upper_word)) {
        tokens.push_back({TokenType::REGISTER, Value(Register(upper_word)), upper_word});
        return true;
    }
    return false;
}

bool Evaluator::parse_function(const std::string& word, std::vector<Token>& tokens) {
    std::string upper_word = Strings::upper(word);
    auto& funcs = get_functions();
    auto func_it = funcs.find(upper_word);
    if (func_it != funcs.end()) {
        tokens.push_back({TokenType::FUNCTION, Value(0.0), upper_word, nullptr, &func_it->second});
        return true;
    }
    return false;
}

std::vector<Evaluator::Token> Evaluator::tokenize(const std::string& expr) {
    std::vector<Token> tokens;
    size_t i = 0;
    while (i < expr.length()) {
        if (std::isspace(expr[i])) {
            i++;
            continue;
        }
        if (parse_operator(expr, i, tokens))
            continue;
        if (parse_punctuation(expr, i, tokens))
            continue;
        size_t j = i;
        std::string word = parse_word(expr, j);
        if (!word.empty()) {
            if (parse_number(word, tokens)) {
                i = j;
                continue;
            }
            if (parse_register(word, tokens)) {
                i = j;
                continue;
            }
            if (parse_function(word, tokens)) {
                i = j;
                continue;
            }
            throw std::runtime_error("Unknown token: " + word);
        }
        throw std::runtime_error(std::string("Unexpected character: ") + expr[i]);
    }
    return tokens;
}

std::vector<Evaluator::Token> Evaluator::shunting_yard(const std::vector<Token>& tokens) {
    std::vector<Token> output_queue;
    std::stack<Token> operator_stack;
    TokenType last_type = TokenType::OPERATOR;

    for (const auto& token : tokens) {
        switch (token.type) {
            case TokenType::NUMBER:
            case TokenType::REGISTER:
                output_queue.push_back(token);
                break;
            case TokenType::FUNCTION:
                operator_stack.push(token);
                break;
            case TokenType::COMMA:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LPAREN) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                break;
            case TokenType::OPERATOR:
                while (!operator_stack.empty() && operator_stack.top().type == TokenType::OPERATOR &&
                       ((!token.op_info->left_assoc && operator_stack.top().op_info->precedence > token.op_info->precedence) ||
                        (token.op_info->left_assoc && operator_stack.top().op_info->precedence >= token.op_info->precedence))) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                operator_stack.push(token);
                break;
            case TokenType::LPAREN:
                operator_stack.push(token);
                break;
            case TokenType::RPAREN:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LPAREN) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (!operator_stack.empty()) operator_stack.pop();
                if (!operator_stack.empty() && operator_stack.top().type == TokenType::FUNCTION) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                break;
        }
        last_type = token.type;
    }
    while (!operator_stack.empty()) {
        output_queue.push_back(operator_stack.top());
        operator_stack.pop();
    }
    return output_queue;
}

Value Evaluator::execute_rpn(const std::vector<Token>& rpn) {
    std::vector<Value> stack;

    for (const auto& token : rpn) {
        if (token.type == TokenType::NUMBER) {
            stack.push_back(token.value);
        } 
        else if (token.type == TokenType::REGISTER) {
            stack.push_back(token.value);
        }
        else if (token.type == TokenType::OPERATOR) {
            const auto* info = token.op_info;
            int args_needed = info->is_unary ? 1 : 2;
            
            if (stack.size() < args_needed) throw std::runtime_error("Stack underflow op");
            
            std::vector<Value> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            
            stack.push_back(info->apply(m_core, args));
        }
        else if (token.type == TokenType::FUNCTION) {
            const auto* info = token.func_info;
            int args_needed = info->num_args;
            if (info->num_args == -1)
                args_needed = stack.size();
            if (stack.size() < args_needed) throw std::runtime_error("Stack underflow func");

            std::vector<Value> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            
            stack.push_back(info->apply(m_core, args));
        }
    }
    return stack.empty() ? Value(0.0) : stack.back();
}