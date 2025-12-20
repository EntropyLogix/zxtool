#include "Formatter.h"
#include "Strings.h"
#include <iomanip>
#include <cctype>

std::string Formatter::format_value(const Expression::Value& val) {
    std::stringstream ss;
    if (val.is_number()) {
        ss << Strings::hex((uint16_t)val.number());
    } else if (val.is_string()) {
        ss << "\"" << val.string() << "\"";
    } else if (val.is_bytes()) {
        ss << "{ ";
        const auto& bytes = val.bytes();
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "$" << Strings::hex(bytes[i]);
        }
        ss << " }";
    } else if (val.is_words()) {
        ss << "W{ ";
        const auto& words = val.words();
        for (size_t i = 0; i < words.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "$" << Strings::hex(words[i]);
        }
        ss << " }";
    } else if (val.is_address()) {
        ss << "[ ";
        const auto& addrs = val.address();
        for (size_t i = 0; i < addrs.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "$" << Strings::hex(addrs[i]);
        }
        ss << " ]";
    } else if (val.is_register()) {
        ss << val.reg().getName();
    } else if (val.is_symbol()) {
        ss << val.symbol().getName();
    } else {
        ss << "?";
    }
    return ss.str();
}

std::string Formatter::format_bin_dotted(uint16_t val, int bits) {
    std::string s;
    for (int i = bits - 1; i >= 0; --i) {
        s += ((val >> i) & 1) ? '1' : '0';
        if (i > 0 && i % 4 == 0) s += ".";
    }
    return "%" + s;
}

std::string Formatter::format_flags_detailed(uint8_t f) {
    std::stringstream ss;
    ss << "[";
    ss << "S:" << ((f >> 7) & 1) << " ";
    ss << "Z:" << ((f >> 6) & 1) << " ";
    ss << "H:" << ((f >> 4) & 1) << " ";
    ss << "P:" << ((f >> 2) & 1) << " ";
    ss << "N:" << ((f >> 1) & 1) << " ";
    ss << "C:" << ((f >> 0) & 1);
    ss << "]";
    return ss.str();
}

void Formatter::format_ops(const Z80Analyzer<Memory>::CodeLine& line, std::ostream& os) {
    if (line.operands.empty()) return;
    using Operand = Z80Analyzer<Memory>::CodeLine::Operand;
    for (size_t i = 0; i < line.operands.size(); ++i) {
        if (i > 0) os << ", ";
        const auto& op = line.operands[i];
        switch (op.type) {
            case Operand::REG8: case Operand::REG16: case Operand::CONDITION: os << op.s_val; break;
            case Operand::IMM8: os << "$" << Strings::hex((uint8_t)op.num_val); break;
            case Operand::IMM16: os << "$" << Strings::hex((uint16_t)op.num_val); break;
            case Operand::MEM_IMM16: os << "($" << Strings::hex((uint16_t)op.num_val) << ")"; break;
            case Operand::PORT_IMM8: os << "($" << Strings::hex((uint8_t)op.num_val) << ")"; break;
            case Operand::MEM_REG16: os << "(" << op.s_val << ")"; break;
            case Operand::MEM_INDEXED: os << "(" << op.base_reg << (op.offset >= 0 ? "+" : "") << (int)op.offset << ")"; break;
            case Operand::STRING: os << "\"" << op.s_val << "\""; break;
            case Operand::CHAR_LITERAL: os << "'" << (char)op.num_val << "'"; break;
            default: break;
        }
    }
}