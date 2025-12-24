#include "Expression.h"
#include "Core.h"
#include "Variables.h"
#include "../Utils/Strings.h"
#include "../Utils/Checksum.h"
#include "Assembler.h"
#include <cctype>
#include <algorithm>
#include <cmath>
#include <type_traits>
#include <cstring>

static constexpr double PI = 3.14159265358979323846;

template <typename T> void Expression::copy_at(std::vector<T>& dest, const std::vector<T>& src, int index) {
    for (size_t k = 0; k < src.size(); ++k) {
        long long pos = (long long)index + k;
        if (pos >= 0 && pos < (long long)dest.size())
            dest[(size_t)pos] = src[k];
    }
}

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
            m_message = "Incorrect number of arguments";
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
        for (size_t i=0; i<len; ++i)
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
        for (size_t i=0; i<len; ++i)
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
        for (int i=0; i<count; ++i)
            res += s;
        return Value(res);
    }
    return Value(args[0].get_scalar(m_core) * args[1].get_scalar(m_core));
}

Expression::Value Expression::operator_div(const std::vector<Value>& args) {
    double div = args[1].get_scalar(m_core);
    if (div == 0.0)
        syntax_error(ErrorCode::GENERIC, "Division by zero");
    return Value(args[0].get_scalar(m_core) / div);
}

Expression::Value Expression::operator_mod(const std::vector<Value>& args) {
    int div = (int)args[1].get_scalar(m_core);
    if (div == 0)
        syntax_error(ErrorCode::GENERIC, "Division by zero");
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
    return Value((double)(uint16_t)(~((uint16_t)args[0].get_scalar(m_core))));
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

Expression::Value Expression::operator_range(const std::vector<Value>& args) {
    int start = (int)args[0].get_scalar(m_core);
    int end = (int)args[1].get_scalar(m_core);
    if (start >= -128 && start <= 255 && end >= -128 && end <= 255) {
        std::vector<uint8_t> vals;
        if (start <= end) {
            for (int i = start; i <= end; ++i)
                vals.push_back((uint8_t)i);
        } else {
            for (int i = start; i >= end; --i)
                vals.push_back((uint8_t)i);
        }
        return Value(vals);
    }
    std::vector<uint16_t> vals;
    if (start <= end) {
        for (int i = start; i <= end; ++i)
            vals.push_back((uint16_t)i);
    } else {
        for (int i = start; i >= end; --i)
            vals.push_back((uint16_t)i);
    }
    return Value(vals, true);
}

Expression::Value Expression::operator_step(const std::vector<Value>& args) {
    int step = (int)args[1].get_scalar(m_core);
    if (step == 0)
        syntax_error(ErrorCode::EVAL_INVALID_INDEXING, "Step cannot be zero");
    auto process = [&](const auto& vec) {
        using T = typename std::decay<decltype(vec)>::type::value_type;
        std::vector<T> res;
        if (step > 0) {
            for (size_t i = 0; i < vec.size(); i += step)
                res.push_back(vec[i]);
        } else {
            for (int i = (int)vec.size() - 1; i >= 0; i += step)
                res.push_back(vec[i]);
        }
        return res;
    };
    const auto& v = args[0];
    if (v.is_address())
        return Value(process(v.address()));
    if (v.is_words())
        return Value(process(v.words()), true);
    if (v.is_bytes())
        return Value(process(v.bytes()));
    return v;
}

Expression::Value Expression::operator_repeat(const std::vector<Value>& args) {
    int count = (int)args[1].get_scalar(m_core);
    if (count < 0)
        syntax_error(ErrorCode::EVAL_INVALID_INDEXING, "Repeat count cannot be negative");
    const auto& v = args[0];
    if (v.is_bytes()) {
        std::vector<uint8_t> res;
        const auto& src = v.bytes();
        for (int k=0; k<count; ++k)
            res.insert(res.end(), src.begin(), src.end());
        return Value(res);
    }
    if (v.is_words()) {
        std::vector<uint16_t> res;
        const auto& src = v.words();
        for (int k=0; k<count; ++k)
            res.insert(res.end(), src.begin(), src.end());
        return Value(res, true);
    }
    if (v.is_address()) {
        std::vector<uint16_t> res;
        const auto& src = v.address();
        for (int k=0; k<count; ++k)
            res.insert(res.end(), src.begin(), src.end());
        return Value(res);
    }
    syntax_error(ErrorCode::EVAL_TYPE_MISMATCH, "Left operand must be a collection");
    return Value(0.0);
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
        {"x",   {15, true, false, &Expression::operator_repeat, {
            {T::Bytes, T::Number}, {T::Words, T::Number}, {T::Address, T::Number},
            {T::Bytes, T::Register}, {T::Words, T::Register}, {T::Address, T::Register},
            {T::Bytes, T::Symbol}, {T::Words, T::Symbol}, {T::Address, T::Symbol},
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number},
            {T::Number, T::Register}, {T::Register, T::Register}, {T::Symbol, T::Register},
            {T::Number, T::Symbol}, {T::Register, T::Symbol}, {T::Symbol, T::Symbol}
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

Expression::Value Expression::function_checksum(const std::vector<Value>& args) {
    uint32_t sum = 0;
    for (const auto& arg : args) {
        auto bytes = arg.to_bytes(m_core);
        for (uint8_t b : bytes)
            sum += b;
    }
    return Value((double)sum);
}

Expression::Value Expression::function_crc(const std::vector<Value>& args) {
    uint32_t crc = Checksum::CRC32_START;
    for (const auto& arg : args) {
        auto bytes = arg.to_bytes(m_core);
        for (uint8_t b : bytes)
            crc = Checksum::crc32_update(crc, b);
    }
    return Value((double)Checksum::crc32_finalize(crc));
}

Expression::Value Expression::function_len(const std::vector<Value>& args) {
    if (args.size() > 1)
        return Value((double)args.size());
    const auto& v = args[0];
    if (v.is_string())
        return Value((double)v.string().length());
    if (v.is_bytes())
        return Value((double)v.bytes().size());
    if (v.is_words())
        return Value((double)v.words().size());
    if (v.is_address())
        return Value((double)v.address().size());
    return Value(1.0);
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
    double lo = args[1].get_scalar(m_core);
    double hi = args[2].get_scalar(m_core);
    const auto& v = args[0];
    if (v.is_bytes()) {
        std::vector<uint8_t> res;
        for (auto b : v.bytes())
            res.push_back((uint8_t)std::max(lo, std::min((double)b, hi)));
        return Value(res);
    } else if (v.is_words()) {
        std::vector<uint16_t> res;
        for (auto w : v.words())
            res.push_back((uint16_t)std::max(lo, std::min((double)w, hi)));
        return Value(res, true);
    } else if (v.is_address()) {
        std::vector<uint16_t> res;
        for (auto a : v.address())
            res.push_back((uint16_t)std::max(lo, std::min((double)a, hi)));
        return Value(res);
    } else {
        double val = v.get_scalar(m_core);
        return Value(std::max(lo, std::min(val, hi)));
    }
}

Expression::Value Expression::function_sin(const std::vector<Value>& args) {
    return Value(std::sin(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_cos(const std::vector<Value>& args) {
    return Value(std::cos(args[0].get_scalar(m_core)));
}

Expression::Value Expression::function_deg(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) * 180.0 / PI);
}

Expression::Value Expression::function_rad(const std::vector<Value>& args) {
    return Value(args[0].get_scalar(m_core) * PI / 180.0);
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
    if (base == 0)
        return Value((double)val);
    return Value((double)(((val + base - 1) / base) * base));
}

Expression::Value Expression::function_wrap(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    int limit = (int)args[1].get_scalar(m_core);
    if (limit == 0)
        return Value(0.0);
    return Value((double)(val % limit));
}

Expression::Value Expression::function_sum(const std::vector<Value>& args) {
    double sum = 0.0;
    for (const auto& v : args) {
        if (v.is_bytes()) {
            for (auto b : v.bytes())
                sum += b;
        } else if (v.is_words()) {
            for (auto w : v.words())
                sum += w;
        } else if (v.is_address()) {
            for (auto a : v.address())
                sum += a;
        } else
            sum += v.get_scalar(m_core);
    }
    return Value(sum);
}

Expression::Value Expression::function_avg(const std::vector<Value>& args) {
    double sum = 0.0;
    size_t count = 0;
    for (const auto& v : args) {
        if (v.is_bytes()) {
            for (auto b : v.bytes())
                sum += b;
            count += v.bytes().size();
        } else if (v.is_words()) {
            for (auto w : v.words())
                sum += w;
            count += v.words().size();
        } else if (v.is_address()) {
            for (auto a : v.address())
                sum += a;
            count += v.address().size();
        } else {
            sum += v.get_scalar(m_core);
            count++;
        }
    }
    if (count == 0)
        return Value(0.0);
    return Value(sum / count);
}

Expression::Value Expression::function_all(const std::vector<Value>& args) {
    if (args.empty())
        return Value(0.0);
    double target = args.back().get_scalar(m_core);
    bool result = true;
    auto process = [&](double val) { if (val != target) result = false; };
    for (size_t i = 0; i < args.size() - 1; ++i) {
        const auto& v = args[i];
        if (v.is_bytes()) {
            for (auto b : v.bytes())
                process((double)b);
        } else if (v.is_words()) {
            for (auto w : v.words())
                process((double)w);
        } else if (v.is_address()) {
            for (auto a : v.address())
                process((double)a);
        } else
            process(v.get_scalar(m_core));
        if (!result)
            break;
    }
    return Value(result ? 1.0 : 0.0);
}

Expression::Value Expression::function_any(const std::vector<Value>& args) {
    if (args.empty())
        return Value(0.0);
    double target = args.back().get_scalar(m_core);
    bool result = false;
    auto process = [&](double val) { if (val == target) result = true; };
    for (size_t i = 0; i < args.size() - 1; ++i) {
        const auto& v = args[i];
        if (v.is_bytes()) {
            for (auto b : v.bytes())
                process((double)b);
        } else if (v.is_words()) {
            for (auto w : v.words())
                process((double)w);
        } else if (v.is_address()) {
            for (auto a : v.address())
                process((double)a);
        } else
            process(v.get_scalar(m_core));
        if (result)
            break;
    }
    return Value(result ? 1.0 : 0.0);
}

Expression::Value Expression::function_asm(const std::vector<Value>& args) {
    uint16_t pc = m_core.get_cpu().get_PC();
    std::string code;

    if (args.size() == 1)
        code = args[0].string();
    else if (args.size() == 2) {
        pc = (uint16_t)args[0].get_scalar(m_core);
        code = args[1].string();
    } else
        syntax_error(ErrorCode::EVAL_NOT_ENOUGH_ARGUMENTS, "ASM requires 1 or 2 arguments");
    std::replace(code.begin(), code.end(), ';', '\n');
    std::map<std::string, uint16_t> symbols;
    for (const auto& pair : m_core.get_context().getSymbols().by_name())
        symbols[pair.first] = pair.second.read();
    for (const auto& pair : m_core.get_context().getVariables().by_name()) {
        const auto& val = pair.second.getValue();
        if (val.is_scalar())
            symbols["@" + pair.first] = (uint16_t)val.get_scalar(m_core);
    }
    std::vector<uint8_t> bytes;
    LineAssembler assembler;
    assembler.assemble(code, symbols, pc, bytes);
    return Value(bytes);
}

Expression::Value Expression::function_copy(const std::vector<Value>& args) {
    const auto& v = args[0];
    if (v.is_bytes())
        return Value(v.bytes());
    if (v.is_words())
        return Value(v.words(), true);
    if (v.is_address())
        return Value(v.address());
    if (v.is_string())
        return Value(v.string());
    return v;
}

std::vector<uint8_t> Expression::Value::to_bytes(Core& core) const {
    std::vector<uint8_t> res;
    if (is_register()) {
        uint16_t val = reg().read(core.get_cpu());
        if (reg().is_16bit()) {
            res.push_back(static_cast<uint8_t>(val & 0xFF));
            res.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        } else
            res.push_back(static_cast<uint8_t>(val & 0xFF));
    } else if (is_scalar()) {
        double d = get_scalar(core);
        int64_t val = static_cast<int64_t>(d);
        bool is_int = (d == (double)val);
        if (is_int && val >= -128 && val <= 255)
            res.push_back(static_cast<uint8_t>(val & 0xFF));
        else if (is_int && val >= -32768 && val <= 65535) {
            res.push_back(static_cast<uint8_t>(val & 0xFF));
            res.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        } else if (is_int && val >= -2147483648LL && val <= 4294967295LL) {
            uint32_t v32 = static_cast<uint32_t>(val);
            for (int i = 0; i < 4; ++i)
                res.push_back(static_cast<uint8_t>((v32 >> (i * 8)) & 0xFF));
        } else if (is_int) {
            uint64_t v64 = static_cast<uint64_t>(val);
            for (int i = 0; i < 8; ++i)
                res.push_back(static_cast<uint8_t>((v64 >> (i * 8)) & 0xFF));
        } else {
            uint64_t v64;
            std::memcpy(&v64, &d, sizeof(d));
            for (int i = 0; i < 8; ++i)
                res.push_back(static_cast<uint8_t>((v64 >> (i * 8)) & 0xFF));
        }
    } else if (is_string()) {
        for (char c : string())
            res.push_back(static_cast<uint8_t>(c));
    } else if (is_bytes()) {
        return bytes();
    } else if (is_words()) {
        for (uint16_t w : words()) {
            res.push_back(w & 0xFF);
            res.push_back(w >> 8);
        }
    } else if (is_address()) {
        for (uint16_t addr : address())
            res.push_back(core.get_memory().peek(addr));
    }
    return res;
}

std::vector<uint16_t> Expression::Value::to_words(Core& core) const {
    std::vector<uint16_t> res;
    if (is_scalar()) {
        double d = get_scalar(core);
        int64_t val = static_cast<int64_t>(d);
        bool is_int = (d == (double)val);
        if (is_int && val >= -32768 && val <= 65535)
            res.push_back(static_cast<uint16_t>(val & 0xFFFF));
        else if (is_int && val >= -2147483648LL && val <= 4294967295LL) {
            uint32_t v32 = static_cast<uint32_t>(val);
            res.push_back(static_cast<uint16_t>(v32 & 0xFFFF));
            res.push_back(static_cast<uint16_t>((v32 >> 16) & 0xFFFF));
        } else if (is_int) {
            uint64_t v64 = static_cast<uint64_t>(val);
            for (int i = 0; i < 4; ++i)
                res.push_back(static_cast<uint16_t>((v64 >> (i * 16)) & 0xFFFF));
        } else {
            uint64_t v64;
            std::memcpy(&v64, &d, sizeof(d));
            for (int i = 0; i < 4; ++i)
                res.push_back(static_cast<uint16_t>((v64 >> (i * 16)) & 0xFFFF));
        }
    } else if (is_string())
        for (char c : string())
            res.push_back(static_cast<uint16_t>(static_cast<unsigned char>(c)));
    else if (is_words())
        return words();
    else if (is_bytes()) {
        const auto& b = bytes();
        for (size_t i = 0; i < b.size(); i += 2) {
            uint16_t w = b[i];
            if (i + 1 < b.size())
                w |= (static_cast<uint16_t>(b[i + 1]) << 8);
            res.push_back(w);
        }
    } else if (is_address()) {
        for (uint16_t addr : address()) {
            uint16_t val = core.get_memory().peek(addr);
            val |= (static_cast<uint16_t>(core.get_memory().peek((addr + 1) & 0xFFFF)) << 8);
            res.push_back(val);
        }
    }
    return res;
}

Expression::Value Expression::function_bytes(const std::vector<Value>& args) {
    std::vector<uint8_t> result;
    for (const auto& arg : args) {
        auto flattened = arg.to_bytes(m_core);
        result.insert(result.end(), flattened.begin(), flattened.end());
    }
    return Value(result);
}

Expression::Value Expression::function_words(const std::vector<Value>& args) {
    std::vector<uint16_t> result;
    for (const auto& arg : args) {
        auto flattened = arg.to_words(m_core);
        result.insert(result.end(), flattened.begin(), flattened.end());
    }
    return Value(result, true);
}

Expression::Value Expression::function_str(const std::vector<Value>& args) {
    const auto& v = args[0];
    if (v.is_string()) return v;
    double d = v.get_scalar(m_core);
    if (d == (long long)d) return Value(std::to_string((long long)d));
    std::stringstream ss;
    ss << d;
    return Value(ss.str());
}

Expression::Value Expression::function_val(const std::vector<Value>& args) {
    double d = 0.0;
    Strings::parse_double(args[0].string(), d);
    return Value(d);
}

Expression::Value Expression::function_hex(const std::vector<Value>& args) {
    int64_t v = (int64_t)args[0].get_scalar(m_core);
    std::stringstream ss;
    ss << std::hex << std::uppercase << v;
    return Value(ss.str());
}

Expression::Value Expression::function_bin(const std::vector<Value>& args) {
    int64_t v = (int64_t)args[0].get_scalar(m_core);
    if (v == 0) return Value(std::string("0"));
    std::string res;
    uint64_t uv = (uint64_t)v;
    while (uv > 0) {
        res = ((uv & 1) ? "1" : "0") + res;
        uv >>= 1;
    }
    return Value(res);
}

Expression::Value Expression::function_bcd(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    int bcd = 0;
    int shift = 0;
    while (val > 0) {
        bcd |= (val % 10) << shift;
        val /= 10;
        shift += 4;
    }
    return Value((double)bcd);
}

Expression::Value Expression::function_dec(const std::vector<Value>& args) {
    int val = (int)args[0].get_scalar(m_core);
    int dec = 0;
    int mul = 1;
    while (val > 0) {
        dec += (val & 0xF) * mul;
        val >>= 4;
        mul *= 10;
    }
    return Value((double)dec);
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
        {"CHECKSUM", {-1, &Expression::function_checksum, {
        }}},
        {"CRC", {-1, &Expression::function_crc, {
        }}},
        {"LEN", {-1, &Expression::function_len, {
        }}},
        {"UPPER", {1, &Expression::function_upper, {
            {T::String}
        }}},
        {"LOWER", {1, &Expression::function_lower, {
            {T::String}
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
            {T::Number, T::Number, T::Number},
            {T::Bytes, T::Number, T::Number},
            {T::Words, T::Number, T::Number},
            {T::Address, T::Number, T::Number}
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
        {"WRAP", {2, &Expression::function_wrap, {
            {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number}
        }}},
        {"SUM", {-1, &Expression::function_sum, {
        }}},
        {"AVG", {-1, &Expression::function_avg, {
        }}},
        {"ALL", {-1, &Expression::function_all, {
        }}},
        {"ANY", {-1, &Expression::function_any, {
        }}},
        {"ASM", {-1, &Expression::function_asm, {
            {T::String},
            {T::Number, T::String}, {T::Register, T::String}, {T::Symbol, T::String}
        }}},
        {"COPY", {1, &Expression::function_copy, {
            {T::Number}, {T::Register}, {T::Symbol},
            {T::String}, {T::Bytes}, {T::Words}, {T::Address}
        }}},
        {"BYTES", {-1, &Expression::function_bytes, {
        }}},
        {"WORDS", {-1, &Expression::function_words, {
        }}}
        ,{"STR", {1, &Expression::function_str, {
            {T::Number}, {T::Register}, {T::Symbol}, {T::String}
        }}},
        {"VAL", {1, &Expression::function_val, {
            {T::String}
        }}},
        {"HEX", {1, &Expression::function_hex, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"BIN", {1, &Expression::function_bin, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"BCD", {1, &Expression::function_bcd, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}},
        {"DEC", {1, &Expression::function_dec, {
            {T::Number}, {T::Register}, {T::Symbol}
        }}}
    };
    return funcs;
}

Expression::Value Expression::evaluate(const std::string& expression) {
    return execute_rpn(shunting_yard(tokenize(expression)));
}

bool Expression::parse_operator(const std::string& expr, size_t& i, std::vector<Token>& tokens) {
    const auto& ops_map = get_operators();
    std::string matched_op;
    const OperatorInfo* op_info = nullptr;
    for (const auto& pair : ops_map) {
        const std::string& op_sym = pair.first;
        if (op_sym == "_" || op_sym == "#")
            continue;
        if (expr.substr(i, op_sym.length()) == op_sym) {
            bool is_valid_candidate = true;
            if (op_sym == "x") {
                if (tokens.empty() || !(tokens.back().type == TokenType::BYTES || tokens.back().type == TokenType::WORDS || tokens.back().type == TokenType::ADDRESS || tokens.back().type == TokenType::RPAREN || tokens.back().type == TokenType::RBRACKET || tokens.back().type == TokenType::RBRACE || tokens.back().type == TokenType::NUMBER || tokens.back().type == TokenType::REGISTER || tokens.back().type == TokenType::SYMBOL))
                    is_valid_candidate = false;
            } else if (std::isalnum(op_sym[0])) {
                size_t next_idx = i + op_sym.length();
                if (next_idx < expr.length() && (std::isalnum(expr[next_idx]) || expr[next_idx] == '_'))
                    is_valid_candidate = false;
            }
            if (is_valid_candidate && op_sym.length() > matched_op.length()) {
                matched_op = op_sym;
                op_info = &pair.second;
            }
        }
    }
    size_t consume_len = matched_op.length();
    if (!matched_op.empty() && (matched_op == "-" || matched_op == "+")) {
        bool is_unary_context = tokens.empty();
        if (!is_unary_context) {
            TokenType t = tokens.back().type;
            is_unary_context = (t == TokenType::OPERATOR || t == TokenType::LPAREN || t == TokenType::COMMA ||
                                t == TokenType::LBRACKET || t == TokenType::LBRACE || t == TokenType::LBRACE_W);
        }
        if (is_unary_context) {
            if (matched_op == "-") {
                matched_op = "_";
                op_info = &ops_map.at("_");
            } else {
                matched_op = "#";
                op_info = &ops_map.at("#");
            }
        }
    }
    if (!matched_op.empty()) {
        tokens.push_back({TokenType::OPERATOR, Value(0.0), matched_op, op_info});
        i += consume_len;
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
    bool starts_digit = false;
    if (index < expr.length() && std::isdigit(expr[index]))
        starts_digit = true;
    while (index < expr.length()) {
        char c = expr[index];
        if (c == '.' && index + 1 < expr.length() && expr[index+1] == '.')
            break;
        if (starts_digit && c == 'x' && word != "0")
            break;
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
    int collection_depth = 0;
    while (i < expr.length()) {
        if (std::isspace(expr[i])) {
            i++;
            continue;
        }
        if (expr[i] == 'W' && i + 1 < expr.length() && expr[i+1] == '{') {
            tokens.push_back({TokenType::LBRACE_W});
            i += 2;
            collection_depth++;
            continue;
        }
        if (i + 1 < expr.length() && expr[i] == '.' && expr[i+1] == '.') {
            if (collection_depth <= 0)
                syntax_error(ErrorCode::SYNTAX_UNEXPECTED_CHARACTER, "Range operator '..' is only allowed inside [] or {}");
            using T = Expression::Value::Type;
            static const OperatorInfo range_op = {20, true, false, &Expression::operator_range, {
                {T::Number, T::Number}, {T::Register, T::Number}, {T::Symbol, T::Number},
                {T::Number, T::Register}, {T::Register, T::Register}, {T::Register, T::Symbol},
                {T::Symbol, T::Number}, {T::Symbol, T::Register}, {T::Symbol, T::Symbol}
            }};
            tokens.push_back({TokenType::OPERATOR, Value(0.0), "..", &range_op});
            i += 2;
            continue;
        }
        if (expr[i] == ':') {
            using T = Expression::Value::Type;
            static const OperatorInfo step_op = {20, true, false, &Expression::operator_step, {
                {T::Address, T::Number}, {T::Words, T::Number}, {T::Bytes, T::Number}
            }};
            tokens.push_back({TokenType::OPERATOR, Value(0.0), ":", &step_op});
            i++;
            continue;
        }
        if (parse_variable(expr, i, tokens))
            continue;
        if (parse_string(expr, i, tokens))
            continue;
        if (parse_operator(expr, i, tokens))
            continue;
        if (parse_punctuation(expr, i, tokens)) {
            TokenType t = tokens.back().type;
            if (t == TokenType::LBRACKET || t == TokenType::LBRACE)
                collection_depth++;
            else if (t == TokenType::RBRACKET || t == TokenType::RBRACE)
                collection_depth--;
            continue;
        }
        size_t j = i;
        std::string word = parse_word(expr, j);
        if (!word.empty()) {
            std::string upper = Strings::upper(word);
            if (upper == "TRUE") {
                tokens.push_back({TokenType::NUMBER, Value(1.0)});
                i = j;
                continue;
            }
            if (upper == "FALSE") {
                tokens.push_back({TokenType::NUMBER, Value(0.0)});
                i = j;
                continue;
            }
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
                if (last_type == TokenType::LPAREN)
                    count = 0;
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
                else if (last_type == TokenType::COMMA)
                    count--;
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
                else if (last_type == TokenType::COMMA)
                    count--;
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
                if (stack.size() < (size_t)count)
                    syntax_error(ErrorCode::EVAL_NOT_ENOUGH_OPERANDS);
                std::vector<uint16_t> addrs;
                std::vector<Value> args;
                for(int k = 0; k < count; ++k) {
                    args.push_back(stack.back());
                    stack.pop_back();
                }
                std::reverse(args.begin(), args.end());
                bool address_mode = false;
                bool dereference_mode = false;
                for (const auto& v : args) {
                    if (v.is_scalar()) {
                        address_mode = true;
                        addrs.push_back((uint16_t)v.get_scalar(m_core));
                    } else if (v.is_address()) {
                        dereference_mode = true;
                        for (auto addr : v.address())
                            addrs.push_back(m_core.get_memory().peek(addr));
                    } else if (v.is_words()) {
                        address_mode = true;
                        const auto& vec = v.words();
                        addrs.insert(addrs.end(), vec.begin(), vec.end());
                    } else if (v.is_bytes()) {
                        address_mode = true;
                        const auto& vec = v.bytes();
                        for (auto b : vec)
                            addrs.push_back((uint16_t)b);
                    } else
                        syntax_error(ErrorCode::EVAL_TYPE_MISMATCH, "Invalid type in []: expected scalar, address, or words");
                }
                if (address_mode)
                    stack.push_back(Value(addrs));
                else if (dereference_mode) {
                    if (addrs.size() == 1)
                        stack.push_back(Value((double)addrs[0]));
                    else {
                        std::vector<uint8_t> bytes;
                        bytes.reserve(addrs.size());
                        for (auto w : addrs)
                            bytes.push_back((uint8_t)w);
                        stack.push_back(Value(bytes));
                    }
                } else
                    stack.push_back(Value(addrs));
            }
        }
        else if (token.type == TokenType::BYTES) {
            if (token.value.is_bytes()) {
                stack.push_back(token.value);
            } else {
                int count = (int)token.value.number();
                if (stack.size() < (size_t)count)
                    syntax_error(ErrorCode::EVAL_NOT_ENOUGH_OPERANDS);
                std::vector<uint8_t> bytes;
                std::vector<Value> args;
                for(int k = 0; k < count; ++k) {
                    args.push_back(stack.back());
                    stack.pop_back();
                }
                std::reverse(args.begin(), args.end());
                for (const auto& v : args) {
                    auto flattened = v.to_bytes(m_core);
                    bytes.insert(bytes.end(), flattened.begin(), flattened.end());
                }
                stack.push_back(Value(bytes));
            }
        }
        else if (token.type == TokenType::WORDS) {
            if (token.value.is_words())
                stack.push_back(token.value);
            else {
                int count = (int)token.value.number();
                if (stack.size() < (size_t)count)
                    syntax_error(ErrorCode::EVAL_NOT_ENOUGH_OPERANDS);
                std::vector<uint16_t> words;
                std::vector<Value> args;
                for (int k = 0; k < count; ++k) {
                    args.push_back(stack.back());
                    stack.pop_back();
                }
                std::reverse(args.begin(), args.end());
                for (const auto& v : args) {
                    auto flattened = v.to_words(m_core);
                    words.insert(words.end(), flattened.begin(), flattened.end());
                }
                stack.push_back(Value(words, true));
            }
        }
    }
    return stack.empty() ? Value(0.0) : stack.back();
}

void Expression::assign(const std::string& lhs, const Value& rhs) {
    size_t i = 0;
    while (i < lhs.length() && std::isspace(lhs[i]))
        i++;
    if (i >= lhs.length())
        return;
    if (lhs[i] == '@') {
        i++;
        std::string name = parse_word(lhs, i);
        Variable* var = m_core.get_context().getVariables().find(name);
        while (i < lhs.length() && std::isspace(lhs[i]))
            i++;
        if (i < lhs.length() && lhs[i] == '[') {
            if (!var) syntax_error(ErrorCode::LOOKUP_UNKNOWN_VARIABLE, name);
            i++;
            size_t start = i;
            int depth = 1;
            while (i < lhs.length() && depth > 0) {
                if (lhs[i] == '[')
                    depth++;
                if (lhs[i] == ']')
                    depth--;
                if (depth > 0)
                    i++;
            }
            if (depth != 0)
                syntax_error(ErrorCode::SYNTAX_MISMATCHED_PARENTHESES, "]");
            std::string idx_str = lhs.substr(start, i - start - 1);
            Value idx_val = evaluate(idx_str);
            int idx = (int)idx_val.get_scalar(m_core);
            Value current = var->getValue();
            if (current.is_bytes()) {
                auto data = current.bytes();
                copy_at(data, rhs.to_bytes(m_core), idx);
                var->setValue(Value(data));
            } else if (current.is_words()) {
                auto data = current.words();
                copy_at(data, rhs.to_words(m_core), idx);
                var->setValue(Value(data, true));
            } else if (current.is_address()) {
                auto data = current.address();
                copy_at(data, rhs.to_words(m_core), idx);
                var->setValue(Value(data));
            } else if (current.is_string()) {
                std::string s = current.string();
                if (idx >= 0 && idx < (int)s.size()) {
                    s[idx] = (char)rhs.get_scalar(m_core);
                    var->setValue(Value(s));
                }
            }
        } else {
            if (var)
                var->setValue(rhs);
            else {
                Variable v(name, rhs, "");
                m_core.get_context().getVariables().add(v);
            }
        }
        return;
    }
    Value target;
    try {
        target = evaluate(lhs);
    } catch (const Error& e) {
        if (e.code() == ErrorCode::LOOKUP_UNKNOWN_SYMBOL) {
            std::string name = e.detail();
            double val = rhs.get_scalar(m_core);
            Symbol s(name, (uint16_t)val, Symbol::Type::Label);
            m_core.get_context().getSymbols().add(s);
            return;
        }
        throw;
    }
    if (target.is_register()) {
        uint16_t num = (uint16_t)rhs.get_scalar(m_core);
        target.reg().write(m_core.get_cpu(), num);
    } else if (target.is_symbol()) {
        uint16_t num = (uint16_t)rhs.get_scalar(m_core);
        std::string name = target.symbol().getName();
        auto& ctx = m_core.get_context();
        Symbol::Type type = target.symbol().getType();
        ctx.getSymbols().remove(name);
        ctx.getSymbols().add(Symbol(name, num, type));
    } else if (target.is_address()) {
        auto& mem = m_core.get_memory();
        const auto& addrs = target.address();
        if (addrs.empty())
            syntax_error(ErrorCode::EVAL_INVALID_INDEXING, "Target address list is empty");
        std::vector<uint8_t> data = rhs.to_bytes(m_core);
        for (size_t k = 0; k < data.size(); ++k) {
            uint16_t addr;
            if (k < addrs.size())
                addr = addrs[k];
            else
                addr = addrs.back() + (uint16_t)(k - (addrs.size() - 1));
            mem.write(addr, data[k]);
        }
    } else
        syntax_error(ErrorCode::EVAL_TYPE_MISMATCH, "Left side must be a register, symbol, variable or address list");
}