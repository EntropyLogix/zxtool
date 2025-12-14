#include "ScreenView.h"
#include "../Utils/Terminal.h"
#include <sstream>

// Mapa kolorów Spectrum -> ANSI 256 (xterm-256-color)
// Standard: Black, Blue, Red, Magenta, Green, Cyan, Yellow, White
static const int ANSIColorsNormal[] = { 0, 4, 1, 5, 2, 6, 3, 7 };
static const int ANSIColorsBright[] = { 8, 12, 9, 13, 10, 14, 11, 15 };

int ScreenView::spec_to_ansi(int color, bool bright) {
    color &= 7; // Safety mask
    return bright ? ANSIColorsBright[color] : ANSIColorsNormal[color];
}

int ScreenView::get_pixel(int x, int y) {
    if (x < 0 || x >= 256 || y < 0 || y >= 192) return 0;

    // Magia adresowania VRAM ZX Spectrum
    int vram_addr = 0x4000 | 
                    ((y & 0xC0) << 5) | // Block (Y7, Y6) -> bit 11, 12
                    ((y & 0x07) << 8) | // Pixel row (Y2, Y1, Y0) -> bit 8, 9, 10
                    ((y & 0x38) << 2) | // Char row (Y5, Y4, Y3) -> bit 5, 6, 7
                    (x >> 3);           // Char col (X7..X3) -> bit 0..4

    uint8_t byte = m_core.get_memory().read(vram_addr);
    int bit = 7 - (x & 7);
    return (byte >> bit) & 1;
}

uint8_t ScreenView::get_attr(int x, int y) {
    // Adres atrybutów zaczyna się od 0x5800 (22528)
    int char_x = x >> 3;
    int char_y = y >> 3;
    int attr_addr = 0x5800 + (char_y * 32) + char_x;
    return m_core.get_memory().read(attr_addr);
}

std::vector<std::string> ScreenView::render() {
    std::vector<std::string> lines;
    
    lines.push_back("+" + std::string(128, '-') + "+");

    for (int y = 0; y < 192; y += 2) {
        std::stringstream ss;
        ss << "|"; // Lewa krawędź

        int last_fg = -1;
        int last_bg = -1;

        for (int x = 0; x < 256; x += 2) {
            uint8_t attr = get_attr(x, y);
            int ink = (attr & 0x07);
            int paper = (attr >> 3) & 0x07;
            bool bright = (attr >> 6) & 1;

            int ansi_ink = spec_to_ansi(ink, bright);
            int ansi_paper = spec_to_ansi(paper, bright);

            bool top_pixel = get_pixel(x, y) || get_pixel(x + 1, y);
            bool bot_pixel = get_pixel(x, y + 1) || get_pixel(x + 1, y + 1);

            int fg_color, bg_color;

            if (top_pixel) fg_color = ansi_ink; else fg_color = ansi_paper;
            if (bot_pixel) bg_color = ansi_ink; else bg_color = ansi_paper;

            if (fg_color != last_fg) {
                ss << "\033[38;5;" << fg_color << "m";
                last_fg = fg_color;
            }
            if (bg_color != last_bg) {
                ss << "\033[48;5;" << bg_color << "m";
                last_bg = bg_color;
            }

            ss << "\u2580"; // Upper Half Block
        }
        ss << Terminal::RESET << "|"; // Reset i prawa krawędź
        lines.push_back(ss.str());
    }
    lines.push_back("+" + std::string(128, '-') + "+");
    return lines;
}