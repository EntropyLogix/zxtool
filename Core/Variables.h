#ifndef __VARIABLES_H__
#define __VARIABLES_H__

#include "Variable.h"
#include <map>
#include <string>

class Variables {
public:
    void add(const Variable& v);
    bool remove(const std::string& name);
    void clear();
    
    const Variable* find(const std::string& name) const;
    Variable* find(const std::string& name);

private:
    std::map<std::string, Variable> m_by_name;
};

#endif // __VARIABLES_H__