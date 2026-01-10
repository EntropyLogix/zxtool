#ifndef __VARIABLES_H__
#define __VARIABLES_H__

#include "Expression.h"
#include <string>
#include <map>
#include <functional>
#include <stdexcept>

// Definicja typu dla funkcji pobierającej wartość (Getter)
using VarGetter = std::function<Expression::Value()>;

class Variable {
public:
    Variable() : m_is_system(false) {}

    // Konstruktor dla zwykłej zmiennej użytkownika (@zmienna)
    Variable(const std::string& name, const Expression::Value& val, const std::string& comment = "")
        : m_name(name), m_static_val(val), m_comment(comment), m_is_system(false) {}

    // Konstruktor dla zmiennej systemowej (@@zmienna)
    Variable(const std::string& name, VarGetter getter, const std::string& comment = "")
        : m_name(name), m_getter(getter), m_comment(comment), m_is_system(true) 
    {
        m_static_val = Expression::Value(0.0);
    }

    // Pobieranie wartości (automatycznie wywołuje logikę UI dla systemowych)
    Expression::Value getValue() const {
        if (m_is_system && m_getter) {
            return m_getter(); 
        }
        return m_static_val;
    }

    // Ustawianie wartości (blokada dla systemowych)
    void setValue(const Expression::Value& val) {
        if (m_is_system) {
            throw std::runtime_error("System variable @@" + m_name + " is read-only.");
        }
        m_static_val = val;
    }

    bool isSystem() const { return m_is_system; }
    const std::string& getName() const { return m_name; }

private:
    std::string m_name;
    Expression::Value m_static_val;
    std::string m_comment;
    
    bool m_is_system;
    VarGetter m_getter;
};

class Variables {
public:
    Variables();
    void add(const Variable& var) { m_vars[var.getName()] = var; }
    
    Variable* find(const std::string& name) {
        auto it = m_vars.find(name);
        if (it != m_vars.end()) return &it->second;
        return nullptr;
    }
    const Variable* find(const std::string& name) const {
        auto it = m_vars.find(name);
        if (it != m_vars.end()) return &it->second;
        return nullptr;
    }

    const std::map<std::string, Variable>& by_name() const { return m_vars; }

    bool remove(const std::string& name) {
        auto it = m_vars.find(name);
        if (it == m_vars.end()) return false;
        if (it->second.isSystem()) return false; // Nie można usunąć @@zmiennej
        m_vars.erase(it);
        return true;
    }

    // Metoda do usuwania zmiennych systemowych (dla modułów jak DebugEngine)
    void removeSystem(const std::string& name) {
        auto it = m_vars.find(name);
        if (it != m_vars.end() && it->second.isSystem())
            m_vars.erase(it);
    }

    void clear() { m_vars.clear(); }

private:
    std::map<std::string, Variable> m_vars;
};

#endif // __VARIABLES_H__