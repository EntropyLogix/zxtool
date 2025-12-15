#include "Evaluator.h"
#include "../Utils/Strings.h"
#include <iostream>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <cmath> // Dla fmod jeśli będziesz chciał modulo
#include <random>
#include <stack>

Evaluator::Evaluator(Core& core) : m_core(core) {}

const std::map<std::string, Evaluator::OperatorInfo>& Evaluator::get_operators() {
    static const std::map<std::string, OperatorInfo> ops = {
        {"_",   {100, false, true,  [](Core&, const std::vector<double>& args) { return -args[0]; }}},
        {"!",   {100, false, true,  [](Core&, const std::vector<double>& args) { return (double)(!args[0]); }}},
        {"~",   {100, false, true,  [](Core&, const std::vector<double>& args) { return (double)(~(uint32_t)args[0]); }}},
        {"@",   {100, false, true,  [](Core& core, const std::vector<double>& args) { 
                    return (double)core.get_memory().read((uint16_t)args[0]); 
                }}},
        {"++",  {100, false, true,  [](Core&, const std::vector<double>& args) { return args[0] + 1; }}},
        {"--",  {100, false, true,  [](Core&, const std::vector<double>& args) { return args[0] - 1; }}},
        {"*",   {90, true,  false, [](Core&, const std::vector<double>& args) { return args[0] * args[1]; }}},
        {"/",   {90, true,  false, [](Core&, const std::vector<double>& args) { return (args[1] != 0) ? args[0] / args[1] : 0; }}},
        {"%",   {90, true,  false, [](Core&, const std::vector<double>& args) { return std::fmod(args[0], args[1]); }}},
        {"+",   {80, true,  false, [](Core&, const std::vector<double>& args) { return args[0] + args[1]; }}},
        {"-",   {80, true,  false, [](Core&, const std::vector<double>& args) { return args[0] - args[1]; }}},
        {"<<",  {70, true,  false, [](Core&, const std::vector<double>& args) { return (double)((int)args[0] << (int)args[1]); }}},
        {">>",  {70, true,  false, [](Core&, const std::vector<double>& args) { return (double)((int)args[0] >> (int)args[1]); }}},
        {"&",   {60, true,  false, [](Core&, const std::vector<double>& args) { return (double)((int)args[0] & (int)args[1]); }}},
        {"^",   {50, true,  false, [](Core&, const std::vector<double>& args) { return (double)((int)args[0] ^ (int)args[1]); }}},
        {"|",   {40, true,  false, [](Core&, const std::vector<double>& args) { return (double)((int)args[0] | (int)args[1]); }}},
    };
    return ops;
}

const std::map<std::string, Evaluator::FunctionInfo>& Evaluator::get_functions() {
    static const std::map<std::string, FunctionInfo> funcs = {
        {"SIN",  {1, [](Core&, const std::vector<double>& args) { return std::sin(args[0]); }}},
        {"COS",  {1, [](Core&, const std::vector<double>& args) { return std::cos(args[0]); }}},
        {"SQRT", {1, [](Core&, const std::vector<double>& args) { return std::sqrt(args[0]); }}},
        {"MIN",  {2, [](Core&, const std::vector<double>& args) { return std::min(args[0], args[1]); }}},
        {"MAX",  {2, [](Core&, const std::vector<double>& args) { return std::max(args[0], args[1]); }}},
        {"RND",  {0, [](Core&, const std::vector<double>&) { return (double)rand() / RAND_MAX; }}},
        {"ABS",  {1, [](Core&, const std::vector<double>& args) { return std::abs(args[0]); }}},
        {"LOW",  {1, [](Core&, const std::vector<double>& args) { return (double)((int)args[0] & 0xFF); }}},
        {"HIGH", {1, [](Core&, const std::vector<double>& args) { return (double)(((int)args[0] >> 8) & 0xFF); }}},
        {"WORD", {2, [](Core&, const std::vector<double>& args) { return (double)((((int)args[0] & 0xFF) << 8) | ((int)args[1] & 0xFF)); }}},
        {"BIT",  {2, [](Core&, const std::vector<double>& args) { return (double)(((int)args[1] >> (int)args[0]) & 1); }}}
    };
    return funcs;
}

double Evaluator::evaluate(const std::string& expression) {
    if (expression.empty()) return 0.0;
    auto tokens = tokenize(expression);
    auto rpn = shunting_yard(tokens);
    return execute_rpn(rpn);
}

void Evaluator::assign(const std::string& target_in, double value) {
    std::string target = target_in;
    
    // 1. Czyszczenie: usuń spacje i zamień na wielkie litery
    target.erase(std::remove_if(target.begin(), target.end(), ::isspace), target.end());
    std::transform(target.begin(), target.end(), target.begin(), ::toupper);

    if (target.empty()) 
        throw std::runtime_error("Assignment target cannot be empty.");

    // 2. Przypadek Pamięci: [WYRAŻENIE] = WARTOŚĆ
    if (target.front() == '[' && target.back() == ']') {
        // Wyciągnij to co jest w środku nawiasów, np. z "[HL+1]" wyciągnij "HL+1"
        std::string inner_expr = target.substr(1, target.size() - 2);
        
        // REKURENCJA: Oblicz adres docelowy używając tego samego ewaluatora!
        double address_dbl = evaluate(inner_expr);
        uint16_t address = static_cast<uint16_t>(address_dbl);
        
        // Zapisz do pamięci (Z80 jest 8-bitowe, więc bierzemy modulo 256)
        uint8_t byte_val = static_cast<uint8_t>(static_cast<int>(value) & 0xFF);
        m_core.get_memory().poke(address, byte_val);
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
                    tokens.push_back({TokenType::NUMBER, static_cast<double>(val)});
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
                        tokens.push_back({TokenType::NUMBER, val});
                        continue;
                    } catch (...) { /* Not a symbol/register, try as number below */ }

                    // Sprawdzamy czy to hex/prefixy (te zwracają uint16_t, rzutujemy na double)
                    // Jeśli to czysty decimal z kropką (np. "2.5"), parse_address tego nie obsłuży standardowo,
                    // ale zakładamy, że na razie wprowadzamy adresy/inty.
                    // Dla pełnego wsparcia float w input (np. "2.5") można tu dodać std::stod.
                    try {
                        tokens.push_back({TokenType::NUMBER, static_cast<double>(m_core.parse_address(word))}); 
                    } catch(...) {
                        // Fallback dla prostych floatów w stringu, jeśli parse_address rzuci wyjątek
                        try { tokens.push_back({TokenType::NUMBER, std::stod(word)}); } catch(...) { throw std::runtime_error("Unknown token: " + word); }
                    }
                }
            }
        }
    }
    return tokens;
}

// --- Shunting-yard (Bez zmian logicznych, tylko typ Token::value jest double) ---
std::vector<Evaluator::Token> Evaluator::shunting_yard(const std::vector<Token>& tokens) {
    std::vector<Token> output_queue;
    std::stack<Token> operator_stack;

    for (const auto& token : tokens) {
        switch (token.type) {
            case TokenType::NUMBER:
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
            case TokenType::LBRACKET:
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
            case TokenType::RBRACKET:
                while (!operator_stack.empty() && operator_stack.top().type != TokenType::LBRACKET) {
                    output_queue.push_back(operator_stack.top());
                    operator_stack.pop();
                }
                if (!operator_stack.empty()) operator_stack.pop();
                static const Token peek_token = {TokenType::OPERATOR, 0, "@", &get_operators().at("@")};
                output_queue.push_back(peek_token); 
                break;
        }
    }
    while (!operator_stack.empty()) {
        output_queue.push_back(operator_stack.top());
        operator_stack.pop();
    }
    return output_queue;
}

// --- RPN Execution (Double Logic) ---
double Evaluator::execute_rpn(const std::vector<Token>& rpn) {
    std::vector<double> stack; // Stos double!

    for (const auto& token : rpn) {
        if (token.type == TokenType::NUMBER) {
            stack.push_back(token.value);
        } 
        else if (token.type == TokenType::OPERATOR) {
            const auto* info = token.op_info;
            int args_needed = info->is_unary ? 1 : 2;
            
            if (stack.size() < args_needed) throw std::runtime_error("Stack underflow op");
            
            std::vector<double> args;
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
            if (stack.size() < args_needed) throw std::runtime_error("Stack underflow func");

            std::vector<double> args;
            for(int k=0; k<args_needed; ++k) {
                args.push_back(stack.back());
                stack.pop_back();
            }
            std::reverse(args.begin(), args.end());
            
            stack.push_back(info->apply(m_core, args));
        }
    }
    return stack.empty() ? 0.0 : stack.back();
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
void Evaluator::set_register_value(const std::string& name, double val_dbl) {
    auto& cpu = m_core.get_cpu();
    
    // Rzutujemy double na uint16_t (ucinamy część ułamkową)
    uint16_t val = static_cast<uint16_t>(val_dbl);

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