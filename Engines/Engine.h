#ifndef __ENGINE_H__
#define __ENGINE_H__

#include "../Core/Core.h"
#include "../Cmd/Options.h"

class Engine {
public:
    virtual ~Engine() = default;
    virtual int run() = 0;
};

#endif // __ENGINE_H__