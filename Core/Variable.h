#ifndef __VARIABLE_H__
#define __VARIABLE_H__

#include <string>
#include "Expression.h"

class Variable {
public:
    Variable() : m_value(0.0) {}
    Variable(const std::string& name, const Expression::Value& value)
        : m_name(name), m_value(value) {}

    const std::string& getName() const { return m_name; }
    const Expression::Value& getValue() const { return m_value; }
    void setValue(const Expression::Value& value) { m_value = value; }

private:
    std::string m_name;
    Expression::Value m_value;
};

#endif // __VARIABLE_H__