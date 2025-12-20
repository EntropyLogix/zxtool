#include "Expression.h"
#include "Core.h"
#include "Variables.h"
#include "../Utils/Strings.h"
#include "Assembler.h"
#include <cctype>
#include <algorithm>
#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

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

Expression::Value Expression::operator_mul(const std::vector<Value>& args) {
    if (args[0].is_string()) {
        std::string s = args[0].string();
        int count = (int)args[1].get_scalar(m_core);
        std::string res;
        for(int i=0; i<count; ++i) res += s;
        return Value(res);
    }
    return Value(args[0].get_scalar(m_core) * args[1].get_scalar(m_core));
}

Expression::Value Expression::operator_div(const std::vector<Value>& args) {
    double div = args[1].get_scalar(m_core);
    if (div == 0.0) syntax_error(ErrorCode::GENERIC, "Division by zero");
    return Value(args[0].get_scalar(m_core) / div);
}

Expression::Value Expression::operator_mod(const std::vector<Value>& args) {
    int div = (int)args[1].get_scalar(m_core);
    if (div == 0) syntax_error(ErrorCode::GENERIC, "Division by zero");
    return Value((double)((int)args[0].get_scalar(m_core) % div));
}

Expression::Value Expression::operator_and(const std::vector<Value>& args) {
    return Value((double)((int)args[0].get_scalar(m_core) & (int)args[1].get_scalar(m_core)));
}

Expression::Value Expression::operator_or(const std::vector<Value>& args) {
    return Value((double)((int)args[0].get_scalar(m_core) | (int)args[1].get_scalar(m_core)));
}

Expression::Value Expression::operator_xor(const std::vector<Value>& args) {
    return Value((double)((int)args[0].get_scalar(m_core) ^ (int)args[1].get_scalar(m_core)));
}

Expression::Value Expression::operator_not(const std::vector<Value>& args) {
    return Value((double)(~(int)args[0].get_scalar(m_core)));
}

Expression::Value Expression::operator_shl(const std::vector<Value>& args) {
    return Value((double)((int)args[0].get_scalar(m_core) << (int)args[1].get_scalar(m_core)));
}

Expression::Value Expression::operator_shr(const std::vector<Value>& args) {
    return Value((double)((int)args[0].get_scalar(m_core) >> (int)args[1].get_scalar(m_core)));
}

Expression::Value Expression::operator_logical_and(const std::vector<Value>& args) {
    return Value((args[0].get_scalar(m_core) != 0.0 && args[1].get_scalar(m_core) != 0.0) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_logical_or(const std::vector<Value>& args) {
    return Value((args[0].get_scalar(m_core) != 0.0 || args[1].get_scalar(m_core) != 0.0) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_logical_not(const std::vector<Value>& args) {
    return Value((args[0].get_scalar(m_core) == 0.0) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_eq(const std::vector<Value>& args) {
    if (args[0].is_string() && args[1].is_string()) {
        return Value(args[0].string() == args[1].string() ? 1.0 : 0.0);
    }
    return Value(args[0].get_scalar(m_core) == args[1].get_scalar(m_core) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_neq(const std::vector<Value>& args) {
    if (args[0].is_string() && args[1].is_string()) {
        return Value(args[0].string() != args[1].string() ? 1.0 : 0.0);
    }
    return Value(args[0].get_scalar(m_core) != args[1].get_scalar(m_core) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_lt(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) < args[1].get_scalar(m_core) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_gt(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) > args[1].get_scalar(m_core) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_lte(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) <= args[1].get_scalar(m_core) ? 1.0 : 0.0);
}

Expression::Value Expression::operator_gte(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) >= args[1].get_scalar(m_core) ? 1.0 : 0.0);
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
        {"*",   {90, true, false, &Expression::operator_mul, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol},
            {T::String, T::Number}
        }}},
        {"/",   {90, true, false, &Expression::operator_div, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"%",   {90, true, false, &Expression::operator_mod, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"<<",  {70, true, false, &Expression::operator_shl, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {">>",  {70, true, false, &Expression::operator_shr, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"==",  {66, true, false, &Expression::operator_eq, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol},
            {T::String, T::String}
        }}},
        {"!=",  {66, true, false, &Expression::operator_neq, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol},
            {T::String, T::String}
        }}},
        {"<",   {68, true, false, &Expression::operator_lt, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {">",   {68, true, false, &Expression::operator_gt, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"<=",  {68, true, false, &Expression::operator_lte, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {">=",  {68, true, false, &Expression::operator_gte, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"&",   {60, true, false, &Expression::operator_and, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"^",   {50, true, false, &Expression::operator_xor, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"|",   {40, true, false, &Expression::operator_or, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"~",   {100, false, true, &Expression::operator_not, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"&&",  {30, true, false, &Expression::operator_logical_and, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"||",  {20, true, false, &Expression::operator_logical_or, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"!",   {100, false, true, &Expression::operator_logical_not, {
            {T::Number}, {T::Register}, {T::Symbol}
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

Expression::Value Expression::function_byte(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    return Value((double)m_core.get_memory().peek(addr));
}

Expression::Value Expression::function_word(const std::vector<Value>& args) {
    if (args.size() == 1) {
        uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
        uint8_t lo = m_core.get_memory().peek(addr);
        uint8_t hi = m_core.get_memory().peek(addr + 1);
        return (double)(lo | (hi << 8));
    }
    return (double)((((int)args[0].get_scalar(m_core) & 0xFF) << 8) | ((int)args[1].get_scalar(m_core) & 0xFF));
}

Expression::Value Expression::function_mem(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    int count = (int)args[1].get_scalar(m_core);
    std::vector<uint8_t> bytes;
    for (int i = 0; i < count; ++i) {
        bytes.push_back(m_core.get_memory().peek(addr + i));
    }
    return Value(bytes);
}

Expression::Value Expression::function_fill(const std::vector<Value>& args) {
    int count = (int)args[0].get_scalar(m_core);
    uint8_t val = (uint8_t)args[1].get_scalar(m_core);
    if (count < 0) count = 0;
    std::vector<uint8_t> bytes((size_t)count, val);
    return Value(bytes);
}

Expression::Value Expression::function_checksum(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    int count = (int)args[1].get_scalar(m_core);
    uint32_t sum = 0;
    for (int i = 0; i < count; ++i) {
        sum += m_core.get_memory().peek(addr + i);
    }
    return Value((double)sum);
}

Expression::Value Expression::function_char(const std::vector<Value>& args) {
    char c = (char)args[0].get_scalar(m_core);
    return Value(std::string(1, c));
}

Expression::Value Expression::function_str(const std::vector<Value>& args) {
    double d = args[0].get_scalar(m_core);
    if (d == (long long)d) {
        return Value(std::to_string((long long)d));
    }
    return Value(std::to_string(d));
}

Expression::Value Expression::function_len(const std::vector<Value>& args) {
    const auto& v = args[0];
    if (v.is_string()) return Value((double)v.string().length());
    if (v.is_bytes()) return Value((double)v.bytes().size());
    if (v.is_words()) return Value((double)v.words().size());
    if (v.is_address()) return Value((double)v.address().size());
    return Value(0.0);
}

Expression::Value Expression::function_substr(const std::vector<Value>& args) {
    const std::string& str = args[0].string();
    int start = (int)args[1].get_scalar(m_core);
    
    if (start < 0) start = 0;
    if ((size_t)start >= str.length()) {
        return Value(std::string(""));
    }

    if (args.size() == 2) {
        return Value(str.substr(start));
    }
    
    int length = (int)args[2].get_scalar(m_core);
    if (length < 0) length = 0;
    return Value(str.substr(start, length));
}

Expression::Value Expression::function_hex(const std::vector<Value>& args) {
    uint32_t val = (uint32_t)args[0].get_scalar(m_core);
    int width = 0;
    if (args.size() > 1) {
        width = (int)args[1].get_scalar(m_core);
    }
    std::stringstream ss;
    ss << std::hex << std::uppercase;
    if (width > 0) ss << std::setw(width) << std::setfill('0');
    ss << val;
    return Value(ss.str());
}

Expression::Value Expression::function_bit(const std::vector<Value>& args) {
    int n = (int)args[0].get_scalar(m_core);
    int val = (int)args[1].get_scalar(m_core);
    return Value((double)((val >> n) & 1));
}

Expression::Value Expression::function_setbit(const std::vector<Value>& args) {
    int n = (int)args[0].get_scalar(m_core);
    int val = (int)args[1].get_scalar(m_core);
    return Value((double)(val | (1 << n)));
}

Expression::Value Expression::function_resbit(const std::vector<Value>& args) {
    int n = (int)args[0].get_scalar(m_core);
    int val = (int)args[1].get_scalar(m_core);
    return Value((double)(val & ~(1 << n)));
}

Expression::Value Expression::function_read_str(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    int len = -1;
    if (args.size() > 1) {
        len = (int)args[1].get_scalar(m_core);
    }

    std::string s;
    if (len >= 0) {
        for (int i = 0; i < len; ++i) {
            s += (char)m_core.get_memory().peek(addr + i);
        }
    } else {
        // C-String (read until 0x00), limit to 256 chars for safety
        for (int i = 0; i < 256; ++i) {
            char c = (char)m_core.get_memory().peek(addr + i);
            if (c == 0) break;
            s += c;
        }
    }
    return Value(s);
}

Expression::Value Expression::function_asc(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    return Value((double)m_core.get_memory().peek(addr));
}

Expression::Value Expression::function_str_p(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    uint8_t len = m_core.get_memory().peek(addr);
    std::string s;
    for (int i = 0; i < len; ++i) {
        s += (char)m_core.get_memory().peek(addr + 1 + i);
    }
    return Value(s);
}

Expression::Value Expression::function_val(const std::vector<Value>& args) {
    double d = 0.0;
    Strings::parse_double(args[0].string(), d);
    return Value(d);
}

Expression::Value Expression::function_bin(const std::vector<Value>& args) {
    uint32_t val = (uint32_t)args[0].get_scalar(m_core);
    std::string s;
    if (val == 0) return Value(std::string("00000000"));
    
    while (val > 0) {
        s = ((val & 1) ? '1' : '0') + s;
        val >>= 1;
    }
    // Pad to 8 bits if small
    while (s.length() < 8) {
        s = '0' + s;
    }
    return Value(s);
}

Expression::Value Expression::function_left(const std::vector<Value>& args) {
    std::string s = args[0].string();
    int len = (int)args[1].get_scalar(m_core);
    if (len < 0) len = 0;
    if ((size_t)len > s.length()) len = (int)s.length();
    return Value(s.substr(0, len));
}

Expression::Value Expression::function_right(const std::vector<Value>& args) {
    std::string s = args[0].string();
    int len = (int)args[1].get_scalar(m_core);
    if (len < 0) len = 0;
    if ((size_t)len > s.length()) len = (int)s.length();
    return Value(s.substr(s.length() - len));
}

Expression::Value Expression::function_upper(const std::vector<Value>& args) {
    std::string s = args[0].string();
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return Value(s);
}

Expression::Value Expression::function_lower(const std::vector<Value>& args) {
    std::string s = args[0].string();
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return Value(s);
}

Expression::Value Expression::function_instr(const std::vector<Value>& args) {
    std::string haystack = args[0].string();
    std::string needle = args[1].string();
    size_t pos = haystack.find(needle);
    return Value(pos == std::string::npos ? -1.0 : (double)pos);
}

Expression::Value Expression::function_match(const std::vector<Value>& args) {
    uint16_t addr = (uint16_t)args[0].get_scalar(m_core);
    std::string pattern = args[1].string();
    for (size_t i = 0; i < pattern.length(); ++i) {
        if (m_core.get_memory().peek(addr + i) != (uint8_t)pattern[i]) {
            return Value(0.0);
        }
    }
    return Value(1.0);
}

Expression::Value Expression::function_from_bcd(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    return Value((double)(((val >> 4) & 0xF) * 10 + (val & 0xF)));
}

Expression::Value Expression::function_to_bcd(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    return Value((double)((((val / 10) % 10) << 4) | (val % 10)));
}

Expression::Value Expression::function_s8(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    return Value((double)(int8_t)(val & 0xFF));
}

Expression::Value Expression::function_abs(const std::vector<Value>& args) {
    return Value(std::abs(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_sign(const std::vector<Value>& args) {
    double v = args[0].get_scalar(m_core);
    return Value((v > 0.0) ? 1.0 : ((v < 0.0) ? -1.0 : 0.0));
}

Expression::Value Expression::function_sqrt(const std::vector<Value>& args) {
    return Value(std::sqrt(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_min(const std::vector<Value>& args) {
    double min_v = 0.0;
    bool first = true;
    auto process = [&](double val) {
        if (first) { min_v = val; first = false; }
        else if (val < min_v) min_v = val;
    };

    for (const auto& v : args) {
        if (v.is_bytes()) {
            for (auto b : v.bytes()) process((double)b);
        } else if (v.is_words()) {
            for (auto w : v.words()) process((double)w);
        } else if (v.is_address()) {
            for (auto a : v.address()) process((double)a);
        } else {
            process(v.get_scalar(m_core));
        }
    }
    return Value(min_v);
}

Expression::Value Expression::function_max(const std::vector<Value>& args) {
    double max_v = 0.0;
    bool first = true;
    auto process = [&](double val) {
        if (first) { max_v = val; first = false; }
        else if (val > max_v) max_v = val;
    };

    for (const auto& v : args) {
        if (v.is_bytes()) {
            for (auto b : v.bytes()) process((double)b);
        } else if (v.is_words()) {
            for (auto w : v.words()) process((double)w);
        } else if (v.is_address()) {
            for (auto a : v.address()) process((double)a);
        } else {
            process(v.get_scalar(m_core));
        }
    }
    return Value(max_v);
}

Expression::Value Expression::function_clamp(const std::vector<Value>& args) {
    double v = args[0].get_scalar(m_core);
    double lo = args[1].get_scalar(m_core);
    double hi = args[2].get_scalar(m_core);
    return Value(std::max(lo, std::min(v, hi)));
}

Expression::Value Expression::function_sin(const std::vector<Value>& args) {
    return Value(std::sin(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_cos(const std::vector<Value>& args) {
    return Value(std::cos(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_deg(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) * 180.0 / M_PI);
}

Expression::Value Expression::function_rad(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) * M_PI / 180.0);
}

Expression::Value Expression::function_int(const std::vector<Value>& args) {
    return Value(std::floor(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_round(const std::vector<Value>& args) {
    return Value(std::round(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_ceil(const std::vector<Value>& args) {
    return Value(std::ceil(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_pow2(const std::vector<Value>& args) {
    return Value(std::pow(2.0, args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_align(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    int base = (int)args[1].get_scalar(m_core);
    if (base == 0) return Value((double)val);
    return Value((double)(((val + base - 1) / base) * base));
}

Expression::Value Expression::function_is_bit_set(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    int n = (int)args[1].get_scalar(m_core);
    return Value((double)((val >> n) & 1));
}

Expression::Value Expression::function_wrap(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    int limit = (int)args[1].get_scalar(m_core);
    if (limit == 0) return Value(0.0);
    return Value((double)(val % limit));
}

Expression::Value Expression::function_sum(const std::vector<Value>& args) {
    const auto& v = args[0];
    double sum = 0.0;
    if (v.is_bytes()) {
        for (auto b : v.bytes()) sum += b;
    } else if (v.is_words()) {
        for (auto w : v.words()) sum += w;
    } else if (v.is_address()) {
        for (auto a : v.address()) sum += a;
    } else {
        sum = v.get_scalar(m_core);
    }
    return Value(sum);
}

Expression::Value Expression::function_avg(const std::vector<Value>& args) {
    const auto& v = args[0];
    double sum = 0.0;
    size_t count = 0;
    if (v.is_bytes()) {
        for (auto b : v.bytes()) sum += b;
        count = v.bytes().size();
    } else if (v.is_words()) {
        for (auto w : v.words()) sum += w;
        count = v.words().size();
    } else if (v.is_address()) {
        for (auto a : v.address()) sum += a;
        count = v.address().size();
    } else {
        return v;
    }
    if (count == 0) return Value(0.0);
    return Value(sum / count);
}

Expression::Value Expression::function_argmax(const std::vector<Value>& args) {
    double max_v = 0.0;
    int max_idx = -1;
    int current_idx = 0;
    bool first = true;

    auto process = [&](double val) {
        if (first) {
            max_v = val;
            max_idx = current_idx;
            first = false;
        } else if (val > max_v) {
            max_v = val;
            max_idx = current_idx;
        }
        current_idx++;
    };

    for (const auto& v : args) {
        if (v.is_bytes()) {
            for (auto b : v.bytes()) process((double)b);
        } else if (v.is_words()) {
            for (auto w : v.words()) process((double)w);
        } else if (v.is_address()) {
            for (auto a : v.address()) process((double)a);
        } else {
            process(v.get_scalar(m_core));
        }
    }
    return Value((double)max_idx);
}

Expression::Value Expression::function_argmin(const std::vector<Value>& args) {
    double min_v = 0.0;
    int min_idx = -1;
    int current_idx = 0;
    bool first = true;

    auto process = [&](double val) {
        if (first) {
            min_v = val;
            min_idx = current_idx;
            first = false;
        } else if (val < min_v) {
            min_v = val;
            min_idx = current_idx;
        }
        current_idx++;
    };

    for (const auto& v : args) {
        if (v.is_bytes()) {
            for (auto b : v.bytes()) process((double)b);
        } else if (v.is_words()) {
            for (auto w : v.words()) process((double)w);
        } else if (v.is_address()) {
            for (auto a : v.address()) process((double)a);
        } else {
            process(v.get_scalar(m_core));
        }
    }
    return Value((double)min_idx);
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
        {"LO",   {1, &Expression::function_low, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"HIGH", {1, &Expression::function_high, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"HI",   {1, &Expression::function_high, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"BYTE", {1, &Expression::function_byte, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"WORD", {-1, &Expression::function_word, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol},
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"MEM", {2, &Expression::function_mem, {
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"FILL", {2, &Expression::function_fill, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"CHECKSUM", {2, &Expression::function_checksum, {
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"CHAR", {1, &Expression::function_char, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"CHR", {1, &Expression::function_char, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"STR", {1, &Expression::function_str, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"LEN", {1, &Expression::function_len, {
            {T::String}, {T::Bytes}, {T::Words}, {T::Address}
        }}},
        {"SUBSTR", {-1, &Expression::function_substr, {
            {T::String, T::Number},
            {T::String, T::Number, T::Number}
        }}},
        {"MID", {-1, &Expression::function_substr, {
            {T::String, T::Number},
            {T::String, T::Number, T::Number}
        }}},
        {"HEX", {-1, &Expression::function_hex, {
            {T::Number}, {T::Register}, {T::Symbol},
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"BIN", {1, &Expression::function_bin, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"VAL", {1, &Expression::function_val, {
            {T::String}
        }}},
        {"READ_STR", {-1, &Expression::function_read_str, {
            {T::Number}, {T::Register}, {T::Symbol},
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"ASC", {1, &Expression::function_asc, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"STR_P", {1, &Expression::function_str_p, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"LEFT", {2, &Expression::function_left, {
            {T::String, T::Number}
        }}},
        {"RIGHT", {2, &Expression::function_right, {
            {T::String, T::Number}
        }}},
        {"UPPER", {1, &Expression::function_upper, {
            {T::String}
        }}},
        {"LOWER", {1, &Expression::function_lower, {
            {T::String}
        }}},
        {"INSTR", {2, &Expression::function_instr, {
            {T::String, T::String}
        }}},
        {"MATCH", {2, &Expression::function_match, {
            {T::Number, T::String}, {T::Register, T::String}, {T::Symbol, T::String}
        }}},
        {"FROM_BCD", {1, &Expression::function_from_bcd, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"TO_BCD", {1, &Expression::function_to_bcd, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"S8", {1, &Expression::function_s8, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"BIT", {2, &Expression::function_bit, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"SETBIT", {2, &Expression::function_setbit, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"RESBIT", {2, &Expression::function_resbit, {
            {T::Number, T::Number}, {T::Number, T::Register}, {T::Number, T::Symbol},
            {T::Register, T::Number}, {T::Register, T::Register}, {T::Register, T::Symbol},
            {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
        }}},
        {"ABS", {1, &Expression::function_abs, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"SIGN", {1, &Expression::function_sign, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"SQRT", {1, &Expression::function_sqrt, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"MIN", {-1, &Expression::function_min, {
        }}},
        {"MAX", {-1, &Expression::function_max, {
        }}},
        {"CLAMP", {3, &Expression::function_clamp, {
            {T::Number, T::Number, T::Number}
        }}},
        {"SIN", {1, &Expression::function_sin, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"COS", {1, &Expression::function_cos, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"DEG", {1, &Expression::function_deg, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"RAD", {1, &Expression::function_rad, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"INT", {1, &Expression::function_int, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"FLOOR", {1, &Expression::function_int, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"ROUND", {1, &Expression::function_round, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"CEIL", {1, &Expression::function_ceil, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"POW2", {1, &Expression::function_pow2, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"ALIGN", {2, &Expression::function_align, {
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"IS_BIT_SET", {2, &Expression::function_is_bit_set, {
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"WRAP", {2, &Expression::function_wrap, {
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"SUM", {1, &Expression::function_sum, {
            {T::Bytes}, {T::Words}, {T::Address}
        }}},
        {"AVG", {1, &Expression::function_avg, {
            {T::Bytes}, {T::Words}, {T::Address}
        }}},
        {"ARGMAX", {-1, &Expression::function_argmax, {
        }}},
        {"ARGMIN", {-1, &Expression::function_argmin, {
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