#ifndef __FORMATTER_H__
#define __FORMATTER_H__

#include <string>
#include <vector>
#include <sstream>
#include "../Core/Expression.h"
#include "../Core/Analyzer.h"

class Formatter {
public:
    static std::string format_value(const Expression::Value& val);
    static std::string format_bin_dotted(uint16_t val, int bits);
    static std::string format_flags_detailed(uint8_t f);
    static void format_ops(const Z80Analyzer<Memory>::CodeLine& line, std::ostream& os);
};

#endif // __FORMATTER_H__