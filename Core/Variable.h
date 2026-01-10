#ifndef __VARIABLE_H__
#define __VARIABLE_H__

#include <string>
#include "Expression.h"

class Variable {
public:
    Variable() : m_value(0.0) {}
    Variable(const std::string& name, const Expression::Value& value, const std::string& expression = "")
        : m_name(name), m_value(value), m_expression(expression) {}

    const std::string& getName() const { return m_name; }
    const Expression::Value& getValue() const { return m_value; }
    const std::string& getExpression() const { return m_expression; }
    void setValue(const Expression::Value& value) { m_value = value; }
    void setExpression(const std::string& expression) { m_expression = expression; }

private:
    std::string m_name;
    Expression::Value m_value;
    std::string m_expression;
};

#endif // __VARIABLE_H__