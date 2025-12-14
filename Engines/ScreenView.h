#pragma once
#include "../Core/Core.h"
#include <vector>
#include <string>
#include <cstdint>

class ScreenView {
public:
    ScreenView(Core& core) : m_core(core) {}

    // Generuje wektor linii gotowych do wypisania w terminalu
    std::vector<std::string> render();

private:
    Core& m_core;

    int get_pixel(int x, int y);
    uint8_t get_attr(int x, int y);
    
    // Konwersja indeksu Spectrum (0-7) na ANSI 256
    int spec_to_ansi(int color, bool bright);
};