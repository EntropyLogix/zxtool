#include "Evaluator.h"
#include "../Utils/Strings.h"
#include <cctype>
#include <algorithm>

Evaluator::Evaluator(Core& core) : m_core(core) {}

static double get_val(Core& core, const Value& v) {
    if (v.is_register()) return v.reg().read(core.get_cpu());
    if (v.is_symbol()) return v.symbol().read();
    return v.number();
}

const std::map<std::string, Evaluator::OperatorInfo>& Evaluator::get_operators() {
    static const std::map<std::string, OperatorInfo> ops = {
        {"_",   {100, false, true,  [](Core& c, const std::vector<Value>& args) { return -get_val(c, args[0]); }}},
        {"+",   {80, true,  false, [](Core& c, const std::vector<Value>& args) { 
            if (args[0].is_string() || args[1].is_string()) {
                auto to_str = [&](const Value& v) {
                    if (v.is_string()) return v.string();
                    double d = get_val(c, v);
                    return (d == (long long)d) ? std::to_string((long long)d) : std::to_string(d);
                };
                return Value(to_str(args[0]) + to_str(args[1]));
            }
            if (args[0].is_address() && args[1].is_address()) {
                std::vector<uint16_t> res;
                const auto& v1 = args[0].address();
                const auto& v2 = args[1].address();
                size_t len = std::min(v1.size(), v2.size());
                for(size_t i=0; i<len; ++i)
                    res.push_back(v1[i] + v2[i]);
                return Value(res);
            }
            if (args[0].is_address() || args[1].is_address()) {
                std::vector<uint16_t> res;
                if (args[0].is_address()) {
                    double val = get_val(c, args[1]);
                    for (auto a : args[0].address()) res.push_back(a + (int)val);
                } else {
                    double val = get_val(c, args[0]);
                    for (auto a : args[1].address()) res.push_back((int)val + a);
                }
                return Value(res);
            }
            return Value(get_val(c, args[0]) + get_val(c, args[1])); 
        }}},
        {"-",   {80, true,  false, [](Core& c, const std::vector<Value>& args) { 
            if (args[0].is_address() && args[1].is_address()) {
                std::vector<uint16_t> res;
                const auto& v1 = args[0].address();
                const auto& v2 = args[1].address();
                size_t len = std::min(v1.size(), v2.size());
                for(size_t i=0; i<len; ++i) res.push_back(v1[i] - v2[i]);
                return Value(res);
            }
            if (args[0].is_address() || args[1].is_address()) {
                std::vector<uint16_t> res;
                if (args[0].is_address()) {
                    double val = get_val(c, args[1]);
                    for (auto a : args[0].address()) res.push_back(a - (int)val);
                } else {
                    // Number - Address (not typical, but mathematically defined)
                    double val = get_val(c, args[0]);
                    for (auto a : args[1].address()) res.push_back((int)val - a);
                }
                return Value(res);
            }
            return Value(get_val(c, args[0]) - get_val(c, args[1])); 
        }}},
    };
    return ops;
}

const std::map<std::string, Evaluator::FunctionInfo>& Evaluator::get_functions() {
    static const std::map<std::string, FunctionInfo> funcs = {
        {"LOW",  {1, [](Core& c, const std::vector<Value>& args) { return (double)((int)get_val(c, args[0]) & 0xFF); }}},
        {"HIGH", {1, [](Core& c, const std::vector<Value>& args) { return (double)(((int)get_val(c, args[0]) >> 8) & 0xFF); }}},
        {"WORD", {2, [](Core& c, const std::vector<Value>& args) { return (double)((((int)get_val(c, args[0]) & 0xFF) << 8) | ((int)get_val(c, args[1]) & 0xFF)); }}}
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
        case '[':
            type = TokenType::LBRACKET;
            break;
        case ']':
            type = TokenType::RBRACKET;
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

bool Evaluator::parse_symbol(const std::string& word, std::vector<Token>& tokens) {
    const Symbol* s = m_core.get_context().symbols.find(word);
    if (s) {
        tokens.push_back({TokenType::SYMBOL, Value(*s), word});
        return true;
    }
    return false;
}

bool Evaluator::parse_string(const std::string& expr, size_t& index, std::vector<Token>& tokens) {
    char quote = expr[index];
    if (quote == '"' || quote == '\'') {
        size_t j = index + 1;
        std::string s;
        while (j < expr.length()) {
            if (expr[j] == quote) {
                tokens.push_back({TokenType::STRING, Value(s)});
                index = j + 1;
                return true;
            }
            s += expr[j];
            j++;
        }
        throw std::runtime_error("Unterminated string literal");
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
        if (parse_string(expr, i, tokens))
            continue;
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
            if (parse_symbol(word, tokens)) {
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
    std::stack<int> arg_counts;

    for (const auto& token : tokens) {
        switch (token.type) {
            case TokenType::NUMBER:
            case TokenType::REGISTER:
            case TokenType::SYMBOL:
            case TokenType::STRING:
                output_queue.push_back(token);
                break;
            case TokenType::FUNCTION:
                operator_stack.push(token);
                break;
            case TokenType::COMMA:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LPAREN && operator_stack.top().type != TokenType::LBRACKET) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (!operator_stack.empty() && operator_stack.top().type == TokenType::LBRACKET) {
                    if (!arg_counts.empty()) arg_counts.top()++;
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
            case TokenType::LBRACKET:
                // Implicit indexing operator if preceded by an operand
                if (last_type == TokenType::NUMBER || last_type == TokenType::REGISTER || 
                    last_type == TokenType::RPAREN || last_type == TokenType::RBRACKET) {
                    
                    static const OperatorInfo index_op = {110, true, false, [](Core& c, const std::vector<Value>& args) {
                        std::vector<uint16_t> res;
                        if (args[1].is_address()) {
                            if (!args[0].is_register()) {
                                throw std::runtime_error("Syntax error: Indexing allowed only on registers.");
                            }
                            double val = get_val(c, args[0]);
                            for (auto a : args[1].address()) res.push_back((int)val + a);
                        } else {
                            throw std::runtime_error("Internal error: Invalid operands for indexing.");
                        }
                        return Value(res);
                    }};

                    Token op_token;
                    op_token.type = TokenType::OPERATOR;
                    op_token.op_info = &index_op;
                    
                    while (!operator_stack.empty() && operator_stack.top().type == TokenType::OPERATOR &&
                           ((!op_token.op_info->left_assoc && operator_stack.top().op_info->precedence > op_token.op_info->precedence) ||
                            (op_token.op_info->left_assoc && operator_stack.top().op_info->precedence >= op_token.op_info->precedence))) {
                        output_queue.push_back(operator_stack.top());
                        operator_stack.pop();
                    }
                    operator_stack.push(op_token);
                }
                operator_stack.push(token);
                arg_counts.push(1);
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
            case TokenType::RBRACKET:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LBRACKET) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (!operator_stack.empty())
                    operator_stack.pop();
                int count = 0;
                if (!arg_counts.empty()) {
                    count = arg_counts.top();
                    arg_counts.pop();
                }
                if (last_type == TokenType::LBRACKET)
                    count = 0;
                output_queue.push_back({TokenType::LIST, Value(count)});
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
        else if (token.type == TokenType::SYMBOL) {
            stack.push_back(token.value);
        }
        else if (token.type == TokenType::STRING) {
            stack.push_back(token.value);
        }
        else if (token.type == TokenType::OPERATOR) {
            const auto* info = token.op_info;
            int args_needed = info->is_unary ? 1 : 2;
            if (stack.size() < args_needed)
                throw std::runtime_error("Not enough operands for operator: " + token.symbol);
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
            if (stack.size() < args_needed)
                throw std::runtime_error("Not enough arguments for function: " + token.symbol);
            std::vector<Value> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            stack.push_back(info->apply(m_core, args));
        }
        else if (token.type == TokenType::LIST) {
            int count = (int)token.value.number();
            std::vector<uint16_t> addrs;
            std::vector<Value> args;
            for(int k = 0; k < count; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            for (const auto& v : args) {
                addrs.push_back((uint16_t)get_val(m_core, v));
            }
            stack.push_back(Value(addrs));
        }
    }
    return stack.empty() ? Value(0.0) : stack.back();
}