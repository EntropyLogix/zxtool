#include "Evaluator.h"
#include "../Utils/Strings.h"
#include <iostream>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <cmath> // Dla fmod jeśli będziesz chciał modulo
#include <random>
#include <stack>
#include <variant>
#include <iomanip>

Evaluator::Evaluator(Core& core) : m_core(core) {}

const std::map<std::string, Evaluator::OperatorInfo>& Evaluator::get_operators() {
    static const std::map<std::string, OperatorInfo> ops = {
        {"_",   {100, false, true,  [](Core&, const std::vector<Value>& args) { return -args[0].as_number(); }}},
        {"!",   {100, false, true,  [](Core&, const std::vector<Value>& args) { return (double)(!args[0].as_number()); }}},
        {"~",   {100, false, true,  [](Core&, const std::vector<Value>& args) { return (double)(~(uint32_t)args[0].as_number()); }}},
        {"@",   {100, false, true,  [](Core& core, const std::vector<Value>& args) { 
                    return (double)core.get_memory().read((uint16_t)args[0].as_number()); 
                }}},
        {"++",  {100, false, true,  [](Core&, const std::vector<Value>& args) { return args[0].as_number() + 1; }}},
        {"--",  {100, false, true,  [](Core&, const std::vector<Value>& args) { return args[0].as_number() - 1; }}},
        {"*",   {90, true,  false, [](Core&, const std::vector<Value>& args) { return args[0].as_number() * args[1].as_number(); }}},
        {"/",   {90, true,  false, [](Core&, const std::vector<Value>& args) { 
                    double div = args[1].as_number();
                    return (div != 0) ? args[0].as_number() / div : 0; 
                }}},
        {"%",   {90, true,  false, [](Core&, const std::vector<Value>& args) { return std::fmod(args[0].as_number(), args[1].as_number()); }}},
        {"+",   {80, true,  false, [](Core&, const std::vector<Value>& args) { 
                    if (args[0].is_string() || args[1].is_string()) {
                        return Value(args[0].as_string() + args[1].as_string());
                    }
                    return Value(args[0].as_number() + args[1].as_number()); 
                }}},
        {"-",   {80, true,  false, [](Core&, const std::vector<Value>& args) { return args[0].as_number() - args[1].as_number(); }}},
        {"<<",  {70, true,  false, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].as_number() << (int)args[1].as_number()); }}},
        {">>",  {70, true,  false, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].as_number() >> (int)args[1].as_number()); }}},
        {"&",   {60, true,  false, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].as_number() & (int)args[1].as_number()); }}},
        {"^",   {50, true,  false, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].as_number() ^ (int)args[1].as_number()); }}},
        {"|",   {40, true,  false, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].as_number() | (int)args[1].as_number()); }}},
    };
    return ops;
}

const std::map<std::string, Evaluator::FunctionInfo>& Evaluator::get_functions() {
    static const std::map<std::string, FunctionInfo> funcs = {
        {"SIN",  {1, [](Core&, const std::vector<Value>& args) { return std::sin(args[0].as_number()); }}},
        {"COS",  {1, [](Core&, const std::vector<Value>& args) { return std::cos(args[0].as_number()); }}},
        {"SQRT", {1, [](Core&, const std::vector<Value>& args) { return std::sqrt(args[0].as_number()); }}},
        {"MIN",  {2, [](Core&, const std::vector<Value>& args) { return std::min(args[0].as_number(), args[1].as_number()); }}},
        {"MAX",  {2, [](Core&, const std::vector<Value>& args) { return std::max(args[0].as_number(), args[1].as_number()); }}},
        {"RND",  {0, [](Core&, const std::vector<Value>&) { return (double)rand() / RAND_MAX; }}},
        {"ABS",  {1, [](Core&, const std::vector<Value>& args) { return std::abs(args[0].as_number()); }}},
        {"LOW",  {1, [](Core&, const std::vector<Value>& args) { return (double)((int)args[0].as_number() & 0xFF); }}},
        {"HIGH", {1, [](Core&, const std::vector<Value>& args) { return (double)(((int)args[0].as_number() >> 8) & 0xFF); }}},
        {"WORD", {2, [](Core&, const std::vector<Value>& args) { return (double)((((int)args[0].as_number() & 0xFF) << 8) | ((int)args[1].as_number() & 0xFF)); }}},
        {"BIT",  {2, [](Core&, const std::vector<Value>& args) { return (double)(((int)args[1].as_number() >> (int)args[0].as_number()) & 1); }}},
        // New functions for strings and arrays
        {"STR",  {1, [](Core&, const std::vector<Value>& args) { return args[0].as_string(); }}},
        {"VAL",  {1, [](Core&, const std::vector<Value>& args) { 
                    try { return std::stod(args[0].as_string()); } catch(...) { return 0.0; } 
                }}},
        {"LEN",  {1, [](Core&, const std::vector<Value>& args) { 
                    if (args[0].is_string()) return (double)args[0].as_string().length();
                    if (args[0].is_array()) return (double)args[0].as_array().size();
                    return 0.0;
                }}},
        {"ARRAY",{ -1, [](Core&, const std::vector<Value>& args) { return args; } }}, // Variable args
        {"GET",  {2, [](Core&, const std::vector<Value>& args) { 
                    if (args[0].is_array()) {
                        size_t idx = (size_t)args[1].as_number();
                        const auto& arr = args[0].as_array();
                        if (idx < arr.size()) return arr[idx];
                    }
                    return Value(0.0);
                }}}
        ,{"ASM",  {1, [](Core& core, const std::vector<Value>& args) {
            std::string code = args[0].as_string();
            std::map<std::string, uint16_t> symbols;
            for (const auto& [addr, name] : core.get_context().labels) {
                symbols[name] = addr;
            }
            LineAssembler assembler;
            std::vector<uint8_t> bytes;
            uint16_t pc = core.get_cpu().get_PC();
            assembler.assemble(code, symbols, pc, bytes);
            return Value(bytes);
        }}}
    };
    return funcs;
}

// NOTE: Return type changed from double to Value
Value Evaluator::evaluate(const std::string& expression) {
    if (expression.empty()) return Value(0.0);
    auto tokens = tokenize(expression);
    auto rpn = shunting_yard(tokens);
    return execute_rpn(rpn);
}

// NOTE: value type changed from double to Value
void Evaluator::assign(const std::string& target_in, Value value) {
    std::string target = target_in;
    
    // 1. Czyszczenie: usuń spacje i zamień na wielkie litery
    target.erase(std::remove_if(target.begin(), target.end(), ::isspace), target.end());
    std::transform(target.begin(), target.end(), target.begin(), ::toupper);

    if (target.empty()) 
        throw std::runtime_error("Assignment target cannot be empty.");

    // 2. Przypadek Pamięci: [WYRAŻENIE] = WARTOŚĆ
    if (target.front() == '[' && target.back() == ']') {
        Value dest_val = evaluate(target);
        if (!dest_val.is_array()) 
             throw std::runtime_error("Invalid assignment target.");
        
        const auto& dest_addrs = dest_val.as_array();
        auto src_bytes = value.as_byte_block();

        if (dest_addrs.empty()) return;

        if (dest_addrs.size() == 1) {
            // Block write to single address
            uint16_t start_addr = (uint16_t)dest_addrs[0].as_number();
            for (size_t i = 0; i < src_bytes.size(); ++i) {
                m_core.get_memory().poke(start_addr + i, src_bytes[i]);
            }
        } else {
            // Multi-target write
            if (src_bytes.size() != dest_addrs.size())
                throw std::runtime_error("Source and destination size mismatch in assignment.");
            
            for (size_t i = 0; i < dest_addrs.size(); ++i) {
                uint16_t addr = (uint16_t)dest_addrs[i].as_number();
                m_core.get_memory().poke(addr, src_bytes[i]);
            }
        }
        return;
    }

    set_register_value(target, value);
}

// --- Tokenizer ---
std::vector<Evaluator::Token> Evaluator::tokenize(const std::string& expr) {
    std::vector<Token> tokens;
    size_t i = 0;
    auto& ops_map = get_operators();
    
    while (i < expr.length()) {
        if (std::isspace(expr[i])) { i++; continue; }

        // String literals
        if (expr[i] == '"') {
            i++;
            std::string str_val;
            while (i < expr.length() && expr[i] != '"') {
                str_val += expr[i];
                i++;
            }
            if (i < expr.length()) i++;
            tokens.push_back({TokenType::NUMBER, Value(str_val)}); // Reusing NUMBER as LITERAL
            continue;
        }

        // Obsługa literałów binarnych (np. %10101010)
        if (expr[i] == '%' && i + 1 < expr.length() && (expr[i+1] == '0' || expr[i+1] == '1')) {
            bool expect_value = false;
            if (tokens.empty()) {
                expect_value = true;
            } else {
                TokenType t = tokens.back().type;
                if (t == TokenType::OPERATOR || t == TokenType::LPAREN || t == TokenType::LBRACKET || t == TokenType::COMMA || t == TokenType::FUNCTION) {
                    expect_value = true;
                }
            }

            if (expect_value) {
                std::string bin_str;
                i++; // Pomiń '%'
                while (i < expr.length() && (expr[i] == '0' || expr[i] == '1')) {
                    bin_str += expr[i];
                    i++;
                }
                try {
                    unsigned long val = std::stoul(bin_str, nullptr, 2);
                    tokens.push_back({TokenType::NUMBER, Value(static_cast<double>(val))});
                    continue;
                } catch (...) {}
            }
        }

        std::string matched_op;
        for (const auto& pair : ops_map) {
            const std::string& op_sym = pair.first;
            if (expr.substr(i, op_sym.length()) == op_sym) {
                if (op_sym == "-" && (tokens.empty() || tokens.back().type == TokenType::OPERATOR || tokens.back().type == TokenType::LPAREN || tokens.back().type == TokenType::LBRACKET || tokens.back().type == TokenType::COMMA)) {
                    auto it = ops_map.find("_");
                    tokens.push_back({TokenType::OPERATOR, 0, "_", &it->second});
                    i += 1;
                    matched_op = "_";
                    break;
                }
                if (matched_op.length() < op_sym.length()) {
                    matched_op = op_sym;
                }
            }
        }

        if (!matched_op.empty()) {
            if (matched_op != "_" && matched_op != "@") {
                 tokens.push_back({TokenType::OPERATOR, 0, matched_op, &ops_map.at(matched_op)});
                 i += matched_op.length();
            }
            continue;
        }

        if (expr[i] == '(') { tokens.push_back({TokenType::LPAREN}); i++; continue; }
        if (expr[i] == ')') { tokens.push_back({TokenType::RPAREN}); i++; continue; }
        if (expr[i] == '[') { tokens.push_back({TokenType::LBRACKET}); i++; continue; }
        if (expr[i] == ']') { tokens.push_back({TokenType::RBRACKET}); i++; continue; }
        if (expr[i] == ',') { tokens.push_back({TokenType::COMMA}); i++; continue; }
        if (expr[i] == '{') { tokens.push_back({TokenType::LBRACE}); i++; continue; }
        if (expr[i] == '}') { tokens.push_back({TokenType::RBRACE}); i++; continue; }

        {
            std::string word;
            char c = expr[i];
            // Dodajemy kropkę '.' do dozwolonych znaków dla liczb zmiennoprzecinkowych
            while (i < expr.length() && (std::isalnum(c) || c == '$' || c == '#' || c == '_' || c == '.')) {
                word += c;
                i++;
                if (i < expr.length()) c = expr[i];
            }

            if (!word.empty()) {
                std::string upper_word = word;
                std::transform(upper_word.begin(), upper_word.end(), upper_word.begin(), ::toupper);

                auto func_it = get_functions().find(upper_word);
                if (func_it != get_functions().end()) {
                    tokens.push_back({TokenType::FUNCTION, 0, upper_word, nullptr, &func_it->second});
                }
                else {
                    // Try to resolve as symbol or register
                    try {
                        double val = resolve_symbol(word); // Use original case for labels
                        tokens.push_back({TokenType::NUMBER, Value(val)});
                        continue;
                    } catch (...) { /* Not a symbol/register, try as number below */ }

                    double d_val;
                    if (Strings::parse_double(word, d_val)) {
                        tokens.push_back({TokenType::NUMBER, Value(d_val)});
                    } else {
                        throw std::runtime_error("Unknown token: " + word);
                    }
                }
            } else {
                throw std::runtime_error(std::string("Unexpected character: ") + c);
            }
        }
    }
    return tokens;
}

// --- Shunting-yard (Bez zmian logicznych, tylko typ Token::value jest double) ---
std::vector<Evaluator::Token> Evaluator::shunting_yard(const std::vector<Token>& tokens) {
    std::vector<Token> output_queue;
    std::stack<Token> operator_stack;
    std::stack<int> arg_counts; // Stos liczników elementów dla zagnieżdżonych tablic
    TokenType last_type = TokenType::OPERATOR; // Do wykrywania pustych tablic {}

    for (const auto& token : tokens) {
        switch (token.type) {
            case TokenType::NUMBER:
                output_queue.push_back(token);
                break;
            case TokenType::FUNCTION:
                operator_stack.push(token);
                break;
            case TokenType::COMMA:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LPAREN && operator_stack.top().type != TokenType::LBRACE && operator_stack.top().type != TokenType::LBRACKET) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                // Jeśli jesteśmy wewnątrz tablicy lub listy adresów, inkrementujemy licznik elementów
                if (!operator_stack.empty() && (operator_stack.top().type == TokenType::LBRACE || operator_stack.top().type == TokenType::LBRACKET)) {
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
                operator_stack.push(token);
                arg_counts.push(1);
                break;
            case TokenType::LBRACE:
                operator_stack.push(token);
                arg_counts.push(1); // Zakładamy 1 element, chyba że zaraz będzie }
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
                if (!operator_stack.empty()) operator_stack.pop();
                
                {
                    int count = 1;
                    if (!arg_counts.empty()) { count = arg_counts.top(); arg_counts.pop(); }
                    output_queue.push_back({TokenType::ARRAY_BUILD, Value((double)count)});
                }
                break;
            case TokenType::RBRACE:
                // Obsługa pustej tablicy {}
                if (last_type == TokenType::LBRACE) {
                    if (!arg_counts.empty()) arg_counts.top() = 0;
                }

                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LBRACE) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (!operator_stack.empty()) operator_stack.pop(); // Zdejmij LBRACE
                
                int count = 0;
                if (!arg_counts.empty()) {
                    count = arg_counts.top();
                    arg_counts.pop();
                }
                output_queue.push_back({TokenType::ARRAY_BUILD, Value((double)count)});
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

// --- RPN Execution (Double Logic) ---
Value Evaluator::execute_rpn(const std::vector<Token>& rpn) {
    std::vector<Value> stack; // Stos Value!

    for (const auto& token : rpn) {
        if (token.type == TokenType::NUMBER) {
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
            if (info->num_args == -1) args_needed = stack.size(); // Variable args support (simple)
            if (stack.size() < args_needed) throw std::runtime_error("Stack underflow func");

            std::vector<Value> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            
            stack.push_back(info->apply(m_core, args));
        }
        else if (token.type == TokenType::ARRAY_BUILD) {
            int count = static_cast<int>(token.value.as_number());
            if (stack.size() < (size_t)count) throw std::runtime_error("Stack underflow array build");
            
            std::vector<Value> elements;
            for(int k=0; k<count; ++k) {
                elements.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(elements.begin(), elements.end());
            stack.push_back(Value(elements));
        }
    }
    return stack.empty() ? Value(0.0) : stack.back();
}

bool Evaluator::is_register(const std::string& name) {
    static const std::vector<std::string> regs = {
        "AF", "BC", "DE", "HL", "IX", "IY", "SP", "PC", 
        "A", "B", "C", "D", "E", "H", "L", "I", "R",
        "IXH", "IXL", "IYH", "IYL"
    };
    return std::find(regs.begin(), regs.end(), name) != regs.end();
}

// Zwracamy double
double Evaluator::resolve_symbol(const std::string& name) {
    // 1. Check context labels (case-sensitive)
    for (const auto& [addr, label] : m_core.get_context().labels) {
        if (label == name) return static_cast<double>(addr);
    }

    // 2. Check registers (case-insensitive)
    std::string upper_name = name;
    std::transform(upper_name.begin(), upper_name.end(), upper_name.begin(), ::toupper);

    auto& cpu = m_core.get_cpu();
    uint16_t val = 0;
    if (upper_name == "PC") val = cpu.get_PC();
    else if (upper_name == "SP") val = cpu.get_SP();
    else if (upper_name == "HL") val = cpu.get_HL();
    else if (upper_name == "DE") val = cpu.get_DE();
    else if (upper_name == "BC") val = cpu.get_BC();
    else if (upper_name == "AF") val = cpu.get_AF();
    else if (upper_name == "IX") val = cpu.get_IX();
    else if (upper_name == "IY") val = cpu.get_IY();
    else if (upper_name == "A") val = cpu.get_AF() >> 8;
    else if (upper_name == "B") val = cpu.get_BC() >> 8;
    else if (upper_name == "C") val = cpu.get_BC() & 0xFF;
    else if (upper_name == "D") val = cpu.get_DE() >> 8;
    else if (upper_name == "E") val = cpu.get_DE() & 0xFF;
    else if (upper_name == "H") val = cpu.get_HL() >> 8;
    else if (upper_name == "L") val = cpu.get_HL() & 0xFF;
    else if (upper_name == "I") val = cpu.get_I();
    else if (upper_name == "R") val = cpu.get_R();
    else if (upper_name == "IXH") val = cpu.get_IX() >> 8;
    else if (upper_name == "IXL") val = cpu.get_IX() & 0xFF;
    else if (upper_name == "IYH") val = cpu.get_IY() >> 8;
    else if (upper_name == "IYL") val = cpu.get_IY() & 0xFF;
    else throw std::runtime_error("Unknown symbol: " + name);
    
    return static_cast<double>(val);
}

// Przyjmujemy double, rzutujemy na uint16_t
void Evaluator::set_register_value(const std::string& name, Value val_in) {
    auto& cpu = m_core.get_cpu();
    
    // Rzutujemy double na uint16_t (ucinamy część ułamkową)
    uint16_t val = static_cast<uint16_t>(val_in.as_number());

    // --- Rejestry 16-bitowe (Proste przypisanie) ---
    if (name == "PC") cpu.set_PC(val);
    else if (name == "SP") cpu.set_SP(val);
    else if (name == "HL") cpu.set_HL(val);
    else if (name == "DE") cpu.set_DE(val);
    else if (name == "BC") cpu.set_BC(val);
    else if (name == "AF") cpu.set_AF(val);
    else if (name == "IX") cpu.set_IX(val);
    else if (name == "IY") cpu.set_IY(val);
    
    // --- Rejestry 8-bitowe (Modyfikacja par) ---
    // Musimy odczytać całą parę, zmodyfikować połówkę i zapisać z powrotem.
    
    // Para AF (A = High, F = Low)
    else if (name == "A") {
        uint16_t current = cpu.get_AF();
        cpu.set_AF((current & 0x00FF) | ((val & 0xFF) << 8));
    }
    
    // Para BC (B = High, C = Low)
    else if (name == "B") {
        uint16_t current = cpu.get_BC();
        cpu.set_BC((current & 0x00FF) | ((val & 0xFF) << 8));
    }
    else if (name == "C") {
        uint16_t current = cpu.get_BC();
        cpu.set_BC((current & 0xFF00) | (val & 0xFF));
    }
    
    // Para DE (D = High, E = Low)
    else if (name == "D") {
        uint16_t current = cpu.get_DE();
        cpu.set_DE((current & 0x00FF) | ((val & 0xFF) << 8));
    }
    else if (name == "E") {
        uint16_t current = cpu.get_DE();
        cpu.set_DE((current & 0xFF00) | (val & 0xFF));
    }
    
    // Para HL (H = High, L = Low)
    else if (name == "H") {
        uint16_t current = cpu.get_HL();
        cpu.set_HL((current & 0x00FF) | ((val & 0xFF) << 8));
    }
    else if (name == "L") {
        uint16_t current = cpu.get_HL();
        cpu.set_HL((current & 0xFF00) | (val & 0xFF));
    }
    
    else if (name == "I") cpu.set_I(val & 0xFF);
    else if (name == "R") cpu.set_R(val & 0xFF);

    // Para IX
    else if (name == "IXH") {
        uint16_t current = cpu.get_IX();
        cpu.set_IX((current & 0x00FF) | ((val & 0xFF) << 8));
    }
    else if (name == "IXL") {
        uint16_t current = cpu.get_IX();
        cpu.set_IX((current & 0xFF00) | (val & 0xFF));
    }

    // Para IY
    else if (name == "IYH") {
        uint16_t current = cpu.get_IY();
        cpu.set_IY((current & 0x00FF) | ((val & 0xFF) << 8));
    }
    else if (name == "IYL") {
        uint16_t current = cpu.get_IY();
        cpu.set_IY((current & 0xFF00) | (val & 0xFF));
    }

    else {
        throw std::runtime_error("Unknown or read-only register: " + name);
    }
}