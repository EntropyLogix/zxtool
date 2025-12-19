#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "CoreIncludes.h"
#include "Symbols.h"
#include "Comments.h"
#include "Variables.h"

#include <map>
#include <string>
#include <cstdint>
#include <utility>

class Context {
public:
    Symbols& getSymbols() { return m_symbols; }
    const Symbols& getSymbols() const { return m_symbols; }

    Comments& getComments() { return m_comments; }
    const Comments& getComments() const { return m_comments; }

    Variables& getVariables() { return m_variables; }
    const Variables& getVariables() const { return m_variables; }

private:
    Symbols m_symbols;
    Comments m_comments;
    Variables m_variables;
};

#endif // __CONTEXT_H__