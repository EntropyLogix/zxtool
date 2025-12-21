#include "Formatter.h"
#include "Strings.h"
#include <iomanip>
#include <cctype>
#include <cmath>
#include <vector>
#include <sstream>

// Helper to format sequences with collapsing logic
template <typename T>
static std::string format_sequence(const std::vector<T>& data, 
                                   const std::string& prefix, 
                                   const std::string& suffix, 
                                   const std::string& separator,
                                   bool use_hex_prefix,
                                   bool allow_step_gt_1) {
    std::stringstream ss;
    ss << prefix;
    for (size_t i = 0; i < data.size(); ) {
        if (i > 0) ss << separator;
        
        size_t best_len = 1;
        int64_t best_step = 0;

        if (i + 1 < data.size()) {
            int64_t diff = (int64_t)data[i+1] - (int64_t)data[i];
            bool valid_step = (std::abs(diff) == 1) || (allow_step_gt_1 && diff != 0);
            
            if (valid_step) {
                size_t j = i + 1;
                while (j + 1 < data.size()) {
                    if ((int64_t)data[j+1] - (int64_t)data[j] != diff) break;
                    j++;
                }
                size_t len = j - i + 1;
                // Collapse rule: Step 1 -> >= 2 elements, Step != 1 -> >= 3 elements
                if (std::abs(diff) == 1) {
                    if (len >= 2) { best_len = len; best_step = diff; }
                } else {
                    if (len >= 3) { best_len = len; best_step = diff; }
                }
            }
        }

        auto fmt_item = [&](T v) {
            if (use_hex_prefix) ss << "$";
            ss << Strings::hex(v);
        };

        if (best_len > 1) {
            fmt_item(data[i]);
            ss << "..";
            fmt_item(data[i + best_len - 1]);
            if (std::abs(best_step) != 1) {
                ss << ":";
                ss << std::dec << std::abs(best_step);
            }
            i += best_len;
        } else {
            fmt_item(data[i]);
            i++;
        }
    }
    ss << suffix;
    return ss.str();
}

std::string Formatter::format_value(const Expression::Value& val) {
    std::stringstream ss;
    if (val.is_number()) {
        double d = val.number();
        if (d == (int64_t)d) {
            int64_t i = (int64_t)d;
            if (i >= 0 && i <= 255) {
                ss << "$" << Strings::hex((uint8_t)i) << " (" << i << ")";
            } else {
                ss << "$" << Strings::hex((uint16_t)i) << " (" << i << ")";
            }
        } else {
            ss << d;
        }
    } else if (val.is_string()) {
        ss << "\"" << val.string() << "\"";
    } else if (val.is_bytes()) {
        return format_sequence(val.bytes(), "{", "}", " ", true, true);
    } else if (val.is_words()) {
        return format_sequence(val.words(), "W{", "}", " ", true, true);
    } else if (val.is_address()) {
        return format_sequence(val.address(), "[", "]", ", ", true, true);
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