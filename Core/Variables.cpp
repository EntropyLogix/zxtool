#include "Variables.h"

Variables::Variables() {
    // Dodanie przykładowych zmiennych
    add(Variable("SCREEN_WIDTH", 256, "32 * 8"));
    add(Variable("SCREEN_HEIGHT", 192, "24 * 8"));
    add(Variable("ATTR_START", 22528, "16384 + 6144"));
}