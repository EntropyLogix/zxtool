#include "Expression.h"
#include "Core.h"
#include "Variables.h"
#include "../Utils/Strings.h"
#include "Assembler.h"
#include <cctype>
#include <algorithm>

Expression::Error::Error(ErrorCode code, const std::string& detail) : m_code(code), m_detail(detail) {
    switch (code) {
        case ErrorCode::LOOKUP_UNKNOWN_VARIABLE:
            m_message = "Unknown variable";
            break;
        case ErrorCode::LOOKUP_UNKNOWN_SYMBOL:
            m_message = "Unknown symbol";
            break;
        case ErrorCode::SYNTAX_UNTERMINATED_STRING:
            m_message = "Unterminated string";
            break;
        case ErrorCode::SYNTAX_UNEXPECTED_CHARACTER:
            m_message = "Unexpected character";
            break;
        case ErrorCode::SYNTAX_MISMATCHED_PARENTHESES:
            m_message = "Mismatched parentheses";
            break;
        case ErrorCode::EVAL_NOT_ENOUGH_OPERANDS:
            m_message = "Not enough operands";
            break;
        case ErrorCode::EVAL_NOT_ENOUGH_ARGUMENTS:
            m_message = "Not enough arguments";
            break;
        case ErrorCode::EVAL_TYPE_MISMATCH:
            m_message = "Type mismatch";
            break;
        case ErrorCode::EVAL_INVALID_INDEXING:
            m_message = "Invalid indexing";
            break;
        case ErrorCode::INTERNAL_ERROR:
            m_message = "Internal error";
            break;
        case ErrorCode::GENERIC: 
        default:
            m_message = "Expression error";
            break;
    }
    if (!detail.empty())
        m_message += " (" + detail + ")";
}

const char* Expression::Error::what() const noexcept {
    return m_message.c_str();
}

Expression::Expression(Core& core) : m_core(core) {}

void Expression::syntax_error(ErrorCode code, const std::string& detail) {
    throw Error(code, detail);
}

double Expression::Value::get_scalar(Core& core) const {
    if (is_register())
        return reg().read(core.get_cpu());
    if (is_symbol())
        return symbol().read();
    return number();
}

Expression::Value Expression::operator_unary_minus(const std::vector<Value>& args) {
    const auto& v = args[0];
    if (v.is_address()) {
        std::vector<uint16_t> res;
        for (auto a : v.address())
            res.push_back((uint16_t)(-(int)a));
        return Value(res);
    }
    if (v.is_words()) {
        std::vector<uint16_t> res;
        for (auto w : v.words())
            res.push_back((uint16_t)(-(int)w));
        return Value(res, true);
    }
    if (v.is_bytes()) {
        std::vector<uint8_t> res;
        for (auto b : v.bytes())
            res.push_back((uint8_t)(-(int)b));
        return Value(res);
    }
    return -v.get_scalar(m_core);
}

Expression::Value Expression::operator_unary_plus(const std::vector<Value>& args) {
    const auto& v = args[0];
    if (v.is_scalar())
        return Value(v.get_scalar(m_core));
    return v;
}

Expression::Value Expression::operator_plus(const std::vector<Value>& args) {
    if (args[0].is_string() || args[1].is_string()) {
        auto to_str = [&](const Value& v) {
            if (v.is_string())
                return v.string();
            double d = v.get_scalar(m_core);
            return (d == (long long)d) ? std::to_string((long long)d) : std::to_string(d);
        };
        return Value(to_str(args[0]) + to_str(args[1]));
    }
    if (args[0].is_bytes() && args[1].is_bytes()) {
        std::vector<uint8_t> res = args[0].bytes();
        const auto& v2 = args[1].bytes();
        res.insert(res.end(), v2.begin(), v2.end());
        return Value(res);
    }
    if (args[0].is_words() && args[1].is_words()) {
        std::vector<uint16_t> res = args[0].words();
        const auto& v2 = args[1].words();
        res.insert(res.end(), v2.begin(), v2.end());
        return Value(res, true);
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
            double val = args[1].get_scalar(m_core);
            for (auto a : args[0].address())
                res.push_back(a + (int)val);
        } else {
            double val = args[0].get_scalar(m_core);
            for (auto a : args[1].address())
                res.push_back((int)val + a);
        }
        return Value(res);
    }

    return Value(args[0].get_scalar(m_core) + args[1].get_scalar(m_core));
}

Expression::Value Expression::operator_minus(const std::vector<Value>& args) {
    if (args[0].is_address() && args[1].is_address()) {
        std::vector<uint16_t> res;
        const auto& v1 = args[0].address();
        const auto& v2 = args[1].address();
        size_t len = std::min(v1.size(), v2.size());
        for(size_t i=0; i<len; ++i)
            res.push_back(v1[i] - v2[i]);
        return Value(res);
    }
    if (args[0].is_address() || args[1].is_address()) {
        std::vector<uint16_t> res;
        if (args[0].is_address()) {
            double val = args[1].get_scalar(m_core);
            for (auto a : args[0].address())
                res.push_back(a - (int)val);
        } else {
            double val = args[0].get_scalar(m_core);
            for (auto a : args[1].address())
                res.push_back((int)val - a);
        }
        return Value(res);
    }

    return Value(args[0].get_scalar(m_core) - args[1].get_scalar(m_core));
}

Expression::Value Expression::operator_index(const std::vector<Value>& args) {
    auto check_bounds = [&](size_t idx, size_t size) {
        if (idx >= size)
            syntax_error(ErrorCode::EVAL_INVALID_INDEXING, "index out of bounds");
    };

    const auto& indices = args[1].address();
    if (args[0].is_register() || args[0].is_symbol()) {
        std::vector<uint16_t> res;
        double val = args[0].get_scalar(m_core);
        for (auto a : indices)
            res.push_back((uint16_t)((int)val + a));
        return Value(res);
    }
    if (args[0].is_bytes()) {
        const auto& vec = args[0].bytes();
        if (indices.size() == 1) {
            check_bounds(indices[0], vec.size());
            return Value((double)vec[indices[0]]);
        }
        std::vector<uint8_t> res;
        for (auto idx : indices) {
            check_bounds(idx, vec.size());
            res.push_back(vec[idx]);
        }
        return Value(res);
    } else if (args[0].is_words()) {
        const auto& vec = args[0].words();
        if (indices.size() == 1) {
            check_bounds(indices[0], vec.size());
            return Value((double)vec[indices[0]]);
        }
        std::vector<uint16_t> res;
        for (auto idx : indices) {
            check_bounds(idx, vec.size());
            res.push_back(vec[idx]);
        }
        return Value(res, true);
    } else if (args[0].is_address()) {
        const auto& vec = args[0].address();
        if (indices.size() == 1) {
            check_bounds(indices[0], vec.size());
            return Value((double)vec[indices[0]]);
        }
        std::vector<uint16_t> res;
        for (auto idx : indices) {
            check_bounds(idx, vec.size());
            res.push_back(vec[idx]);
        }
        return Value(res);
    } else if (args[0].is_string()) {
        const auto& str = args[0].string();
        if (indices.size() == 1) {
            check_bounds(indices[0], str.size());
            return Value((double)(unsigned char)str[indices[0]]);
        }
        std::string res;
        for (auto idx : indices) {
            check_bounds(idx, str.size());
            res += str[idx];
        }
        return Value(res);
    }
    return Value(0.0);
}

const std::map<std::string, Expression::OperatorInfo>& Expression::get_operators() {
    using T = Expression::Value::Type;
    static const std::map<std::string, OperatorInfo> ops = {
        {"_",   {100, false, true,  &Expression::operator_unary_minus, {
            {T::Number}, {T::Register}, {T::Symbol},
            {T::Address}, {T::Words}, {T::Bytes}
        }}},
        {"#",   {100, false, true,  &Expression::operator_unary_plus, {
            {T::Number}, {T::Register}, {T::Symbol},
            {T::Address}, {T::Words}, {T::Bytes}
        }}},
        {"+",   {80, true,  false, &Expression::operator_plus, {
            // Scalar + Scalar
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol},
            // String combinations
            {T::String, T::String},
            {T::String, T::Number}, {T::String, T::Register}, {T::String, T::Symbol},
            {T::Number, T::String}, {T::Register, T::String}, {T::Symbol, T::String},
            // Containers
            {T::Bytes, T::Bytes}, {T::Words, T::Words}, {T::Address, T::Address},
            // Address + Scalar
            {T::Address, T::Number}, {T::Address, T::Register}, {T::Address, T::Symbol},
            // Scalar + Address
            {T::Number, T::Address}, {T::Register, T::Address}, {T::Symbol, T::Address}
        }}},
        {"-",   {80, true,  false, &Expression::operator_minus, {
            // Scalar - Scalar
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol},
            // Address - Address
            {T::Address, T::Address},
            // Address - Scalar
            {T::Address, T::Number}, {T::Address, T::Register}, {T::Address, T::Symbol},
            // Scalar - Address
            {T::Number, T::Address}, {T::Register, T::Address}, {T::Symbol, T::Address}
        }}},
    };
    return ops;
}

Expression::Value Expression::function_low(const std::vector<Value>& args) {
    return (double)((int)args[0].get_scalar(m_core) & 0xFF);
}

Expression::Value Expression::function_high(const std::vector<Value>& args) {
    return (double)(((int)args[0].get_scalar(m_core) >> 8) & 0xFF);
}

Expression::Value Expression::function_word(const std::vector<Value>& args) {
    return (double)((((int)args[0].get_scalar(m_core) & 0xFF) << 8) | ((int)args[1].get_scalar(m_core) & 0xFF));
}

Expression::Value Expression::function_asm(const std::vector<Value>& args) {
    uint16_t pc = m_core.get_cpu().get_PC();
    std::string code;

    if (args.size() == 1) {
        code = args[0].string();
    } else if (args.size() == 2) {
        pc = (uint16_t)args[0].get_scalar(m_core);
        code = args[1].string();
    } else {
        syntax_error(ErrorCode::EVAL_NOT_ENOUGH_ARGUMENTS, "ASM requires 1 or 2 arguments");
    }

    std::replace(code.begin(), code.end(), ';', '\n');

    std::map<std::string, uint16_t> symbols;
    for (const auto& pair : m_core.get_context().getSymbols().by_name()) {
        symbols[pair.first] = pair.second.read();
    }

    for (const auto& pair : m_core.get_context().getVariables().by_name()) {
        const auto& val = pair.second.getValue();
        if (val.is_scalar()) {
            symbols["@" + pair.first] = (uint16_t)val.get_scalar(m_core);
        }
    }

    std::vector<uint8_t> bytes;
    LineAssembler assembler;
    assembler.assemble(code, symbols, pc, bytes);

    return Value(bytes);
}

const std::map<std::string, Expression::FunctionInfo>& Expression::get_functions() {
    using T = Expression::Value::Type;
    static const std::map<std::string, FunctionInfo> funcs = {
        {"LOW",  {1, &Expression::function_low, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"HIGH", {1, &Expression::function_high, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"WORD", {2, &Expression::function_word, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"ASM", {-1, &Expression::function_asm, {
            {T::String},
            {T::Number, T::String}, {T::Register, T::String}, {T::Symbol, T::String}
        }}}
    };
    return funcs;
}

Expression::Value Expression::evaluate(const std::string& expression) {
    if (expression.empty())
        return Value(0.0);
    auto tokens = tokenize(expression);
    auto rpn = shunting_yard(tokens);
    return execute_rpn(rpn);
}

bool Expression::parse_operator(const std::string& expr, size_t& i, std::vector<Token>& tokens) {
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
            else if (op_sym == "+" && (tokens.empty() || tokens.back().type == TokenType::OPERATOR || tokens.back().type == TokenType::LPAREN || tokens.back().type == TokenType::COMMA)) {
                auto it = ops_map.find("#");
                if (it != ops_map.end()) {
                    matched_op = "#";
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
        size_t consume = (matched_op == "_" || matched_op == "#") ? 1 : matched_op.length();
        tokens.push_back({TokenType::OPERATOR, Value(0.0), matched_op, op_info});
        i += consume;
        return true;
    }
    return false;
}

bool Expression::parse_punctuation(const std::string& expr, size_t& i, std::vector<Token>& tokens) {
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
        case '{':
            type = TokenType::LBRACE;
            break;
        case '}':
            type = TokenType::RBRACE;
            break;
        default:
            return false;
    }
    tokens.push_back({type});
    i++;
    return true;
}

std::string Expression::parse_word(const std::string& expr, size_t& index) {
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

bool Expression::parse_number(const std::string& word, std::vector<Token>& tokens) {
    double number;
    if (Strings::parse_double(word, number)) {
        tokens.push_back({TokenType::NUMBER, Value(number)});
        return true;
    }
    return false;
}

bool Expression::parse_register(const std::string& word, std::vector<Token>& tokens) {
    std::string upper_word = Strings::upper(word);
    if (Register::is_valid(upper_word)) {
        tokens.push_back({TokenType::REGISTER, Value(Register(upper_word)), upper_word});
        return true;
    }
    return false;
}

bool Expression::parse_symbol(const std::string& word, std::vector<Token>& tokens) {
    const Symbol* symbol = m_core.get_context().getSymbols().find(word);
    if (symbol) {
        tokens.push_back({TokenType::SYMBOL, Value(*symbol), word});
        return true;
    }
    return false;
}

bool Expression::parse_variable(const std::string& expr, size_t& index, std::vector<Token>& tokens) {
    if (expr[index] == '@') {
        size_t j = index + 1;
        std::string name;
        while (j < expr.length()) {
            char c = expr[j];
            if (std::isalnum(c) || c == '_') {
                name += c;
                j++;
            } else
                break;
        }
        if (name.empty())
            return false;
        const Variable* var = m_core.get_context().getVariables().find(name);
        if (var) {
            const auto& val = var->getValue();
            TokenType type = TokenType::UNKNOWN;
            if (val.is_number())
                type = TokenType::NUMBER;
            else if (val.is_register())
                type = TokenType::REGISTER;
            else if (val.is_symbol())
                type = TokenType::SYMBOL;
            else if (val.is_string())
                type = TokenType::STRING;
            else if (val.is_address())
                type = TokenType::ADDRESS;
            else if (val.is_bytes())
                type = TokenType::BYTES;
            else if (val.is_words())
                type = TokenType::WORDS;
            if (type != TokenType::UNKNOWN) {
                tokens.push_back({type, val});
                index = j;
                return true;
            }
        }
        syntax_error(ErrorCode::LOOKUP_UNKNOWN_VARIABLE, name);
    }
    return false;
}

bool Expression::parse_string(const std::string& expr, size_t& index, std::vector<Token>& tokens) {
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
            syntax_error(ErrorCode::SYNTAX_UNTERMINATED_STRING);
    }
    return false;
}

bool Expression::parse_function(const std::string& word, std::vector<Token>& tokens) {
    std::string upper_word = Strings::upper(word);
    auto& funcs = get_functions();
    auto func_it = funcs.find(upper_word);
    if (func_it != funcs.end()) {
        tokens.push_back({TokenType::FUNCTION, Value(0.0), upper_word, nullptr, &func_it->second});
        return true;
    }
    return false;
}

std::vector<Expression::Token> Expression::tokenize(const std::string& expr) {
    std::vector<Token> tokens;
    size_t i = 0;
    while (i < expr.length()) {
        if (std::isspace(expr[i])) {
            i++;
            continue;
        }
        if (expr[i] == 'W' && i + 1 < expr.length() && expr[i+1] == '{') {
            tokens.push_back({TokenType::LBRACE_W});
            i += 2;
            continue;
        }
        if (parse_variable(expr, i, tokens))
            continue;
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
            syntax_error(ErrorCode::LOOKUP_UNKNOWN_SYMBOL, word);
        }
        syntax_error(ErrorCode::SYNTAX_UNEXPECTED_CHARACTER, std::string(1, expr[i]));
    }
    return tokens;
}

std::vector<Expression::Token> Expression::shunting_yard(const std::vector<Token>& tokens) {
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
            case TokenType::BYTES:
            case TokenType::WORDS:
            case TokenType::ADDRESS:
                output_queue.push_back(token);
                break;
            case TokenType::FUNCTION:
                operator_stack.push(token);
                break;
            case TokenType::COMMA:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LPAREN && operator_stack.top().type != TokenType::LBRACKET && operator_stack.top().type != TokenType::LBRACE && operator_stack.top().type != TokenType::LBRACE_W) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (!operator_stack.empty() && (operator_stack.top().type == TokenType::LBRACKET || operator_stack.top().type == TokenType::LBRACE || operator_stack.top().type == TokenType::LBRACE_W || operator_stack.top().type == TokenType::LPAREN)) {
                    if (!arg_counts.empty())
                        arg_counts.top()++;
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
                arg_counts.push(1);
                break;
            case TokenType::LBRACKET:
                if (last_type == TokenType::NUMBER || last_type == TokenType::REGISTER ||
                    last_type == TokenType::BYTES || last_type == TokenType::WORDS ||
                    last_type == TokenType::ADDRESS || last_type == TokenType::STRING || last_type == TokenType::SYMBOL ||
                    last_type == TokenType::RPAREN || last_type == TokenType::RBRACKET) {
                    using T = Expression::Value::Type;
                    static const OperatorInfo index_op = {110, true, false, &Expression::operator_index, {
                        {T::Register, T::Address}, {T::Symbol, T::Address},
                        {T::Bytes, T::Address},
                        {T::Words, T::Address},
                        {T::Address, T::Address},
                        {T::String, T::Address}
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
            case TokenType::LBRACE:
                operator_stack.push(token);
                arg_counts.push(1);
                break;
            case TokenType::LBRACE_W:
                operator_stack.push(token);
                arg_counts.push(1);
                break;
            case TokenType::RPAREN: {
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LPAREN) {
                    if (operator_stack.top().type == TokenType::LBRACKET || operator_stack.top().type == TokenType::LBRACE || operator_stack.top().type == TokenType::LBRACE_W)
                        syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, ")");
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (operator_stack.empty())
                    syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, ")");
                operator_stack.pop();
                
                int count = 1;
                if (!arg_counts.empty()) {
                    count = arg_counts.top();
                    arg_counts.pop();
                }
                if (last_type == TokenType::LPAREN) count = 0;

                if (!operator_stack.empty() && operator_stack.top().type == TokenType::FUNCTION) {
                    Token t = operator_stack.top();
                    t.argc = count;
                    output_queue.push_back(t);
                    operator_stack.pop();
                }
                break;
            }
            case TokenType::RBRACKET: {
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LBRACKET) {
                    if (operator_stack.top().type == TokenType::LPAREN || operator_stack.top().type == TokenType::LBRACE || operator_stack.top().type == TokenType::LBRACE_W)
                        syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, "]");
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (operator_stack.empty())
                    syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, "]");
                operator_stack.pop();
                int count = 0;
                if (!arg_counts.empty()) {
                    count = arg_counts.top();
                    arg_counts.pop();
                }
                if (last_type == TokenType::LBRACKET)
                    count = 0;
                output_queue.push_back({TokenType::ADDRESS, Value(count)});
                break;
            }
            case TokenType::RBRACE: {
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LBRACE && operator_stack.top().type != TokenType::LBRACE_W) {
                    if (operator_stack.top().type == TokenType::LPAREN || operator_stack.top().type == TokenType::LBRACKET)
                        syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, "}");
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (operator_stack.empty())
                    syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, "}");
                
                TokenType openType = operator_stack.top().type;
                operator_stack.pop();

                int count = 0;
                if (!arg_counts.empty()) {
                    count = arg_counts.top();
                    arg_counts.pop();
                }
                if (last_type == openType)
                    count = 0;
                if (openType == TokenType::LBRACE)
                    output_queue.push_back({TokenType::BYTES, Value(count)});
                else if (openType == TokenType::LBRACE_W)
                    output_queue.push_back({TokenType::WORDS, Value(count)});
                break;
            }
        }
        last_type = token.type;
    }
    while (!operator_stack.empty()) {
        if (operator_stack.top().type == TokenType::LPAREN || operator_stack.top().type == TokenType::LBRACKET || operator_stack.top().type == TokenType::LBRACE || operator_stack.top().type == TokenType::LBRACE_W)
            syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, "Unclosed parenthesis/bracket");
        output_queue.push_back(operator_stack.top());
        operator_stack.pop();
    }
    return output_queue;
}

Expression::Value Expression::execute_rpn(const std::vector<Token>& rpn) {
    std::vector<Value> stack;
    for (const auto& token : rpn) {
        if (token.type == TokenType::NUMBER)
            stack.push_back(token.value);
        else if (token.type == TokenType::REGISTER)
            stack.push_back(token.value);
        else if (token.type == TokenType::SYMBOL)
            stack.push_back(token.value);
        else if (token.type == TokenType::STRING)
            stack.push_back(token.value);
        else if (token.type == TokenType::OPERATOR) {
            const auto* info = token.op_info;
            int args_needed = info->is_unary ? 1 : 2;
            if (stack.size() < args_needed)
                syntax_error(ErrorCode::EVAL_NOT_ENOUGH_OPERANDS, token.symbol);
            std::vector<Value> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            info->check(token.symbol, args);
            stack.push_back((this->*(info->apply))(args));
        }
        else if (token.type == TokenType::FUNCTION) {
            const auto* info = token.func_info;
            int args_needed = info->num_args;
            if (info->num_args == -1) {
                args_needed = token.argc;
            } else if (token.argc != info->num_args)
                syntax_error(ErrorCode::EVAL_NOT_ENOUGH_ARGUMENTS, token.symbol);
            if (stack.size() < args_needed)
                syntax_error(ErrorCode::EVAL_NOT_ENOUGH_ARGUMENTS, token.symbol);
            std::vector<Value> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            info->check(token.symbol, args);
            stack.push_back((this->*(info->apply))(args));
        }
        else if (token.type == TokenType::ADDRESS) {
            if (token.value.is_address()) {
                stack.push_back(token.value);
            } else {
                int count = (int)token.value.number();
                std::vector<uint16_t> addrs;
                std::vector<Value> args;
                for(int k = 0; k < count; ++k) {
                    args.push_back(stack.back());
                    stack.pop_back();
                }
                std::reverse(args.begin(), args.end());
                for (const auto& v : args)
                    addrs.push_back((uint16_t)v.get_scalar(m_core));
                stack.push_back(Value(addrs));
            }
        }
        else if (token.type == TokenType::BYTES) {
            if (token.value.is_bytes()) {
                stack.push_back(token.value);
            } else {
                int count = (int)token.value.number();
                std::vector<uint8_t> bytes;
                std::vector<Value> args;
                for(int k = 0; k < count; ++k) {
                    args.push_back(stack.back());
                    stack.pop_back();
                }
                std::reverse(args.begin(), args.end());
                for (const auto& v : args) {
                    if (v.is_address())
                        syntax_error(ErrorCode::EVAL_TYPE_MISMATCH);
                    if (v.is_string()) {
                        const std::string& s = v.string();
                        bytes.insert(bytes.end(), s.begin(), s.end());
                    } else if (v.is_bytes()) {
                        const auto& b = v.bytes();
                        bytes.insert(bytes.end(), b.begin(), b.end());
                    } else if (v.is_words()) {
                        for (uint16_t word : v.words()) {
                            bytes.push_back(word & 0xFF);
                            bytes.push_back(word >> 8);
                        }
                    } else {
                        double val = v.get_scalar(m_core);
                        if (v.is_register() && v.reg().is_16bit()) {
                            uint16_t w = (uint16_t)val;
                            bytes.push_back(w & 0xFF);
                            bytes.push_back(w >> 8);
                        } else if (val >= -128 && val <= 255)
                            bytes.push_back((uint8_t)val);
                        else {
                            uint16_t w = (uint16_t)val;
                            bytes.push_back(w & 0xFF);
                            bytes.push_back(w >> 8);
                        }
                    }
                }
                stack.push_back(Value(bytes));
            }
        }
        else if (token.type == TokenType::WORDS) {
            if (token.value.is_words()) {
                stack.push_back(token.value);
            } else {
                int count = (int)token.value.number();
                std::vector<uint16_t> words;
                std::vector<Value> args;
                for(int k = 0; k < count; ++k) {
                    args.push_back(stack.back());
                    stack.pop_back();
                }
                std::reverse(args.begin(), args.end());
                for (const auto& v : args) {
                    if (v.is_address())
                        syntax_error(ErrorCode::EVAL_TYPE_MISMATCH);
                    
                    if (v.is_string()) {
                        const std::string& s = v.string();
                        for (char c : s) words.push_back((uint16_t)(unsigned char)c);
                    } else if (v.is_bytes()) {
                        const auto& b = v.bytes();
                        for (size_t i = 0; i < b.size(); i += 2) {
                            uint16_t word = b[i];
                            if (i + 1 < b.size())
                                word |= (uint16_t)b[i+1] << 8;
                            words.push_back(word);
                        }
                    } else if (v.is_words()) {
                        const auto& w = v.words();
                        words.insert(words.end(), w.begin(), w.end());
                    } else {
                        double val = v.get_scalar(m_core);
                        words.push_back((uint16_t)val);
                    }
                }
                stack.push_back(Value(words, true));
            }
        }
    }
    return stack.empty() ? Value(0.0) : stack.back();
}