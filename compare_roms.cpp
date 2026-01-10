#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>
#include <cstdint>

int main(int argc, char* argv[]) {
    // Domyślne nazwy plików, jeśli nie podano argumentów
    std::string file1_name = (argc > 1) ? argv[1] : "out.bin";
    std::string file2_name = (argc > 2) ? argv[2] : "48.rom";

    std::ifstream f1(file1_name, std::ios::binary | std::ios::ate);
    std::ifstream f2(file2_name, std::ios::binary | std::ios::ate);

    if (!f1.is_open()) {
        std::cerr << "Error: Cannot open file " << file1_name << std::endl;
        return 1;
    }
    if (!f2.is_open()) {
        std::cerr << "Error: Cannot open file " << file2_name << std::endl;
        return 1;
    }

    std::streamsize s1 = f1.tellg();
    std::streamsize s2 = f2.tellg();

    f1.seekg(0, std::ios::beg);
    f2.seekg(0, std::ios::beg);

    if (s1 != s2) {
        std::cout << "Size mismatch: " << file1_name << " (" << s1 << " bytes) vs " << file2_name << " (" << s2 << " bytes)" << std::endl;
    } else {
        std::cout << "Sizes match: " << s1 << " bytes" << std::endl;
    }

    std::vector<uint8_t> d1(s1);
    std::vector<uint8_t> d2(s2);

    f1.read(reinterpret_cast<char*>(d1.data()), s1);
    f2.read(reinterpret_cast<char*>(d2.data()), s2);

    size_t min_size = (s1 < s2) ? s1 : s2;
    bool diff = false;
    int err_count = 0;

    for (size_t i = 0; i < min_size; ++i) {
        if (d1[i] != d2[i]) {
            std::cout << "Difference at address $" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << i 
                      << ": " << file1_name << "=$" << std::setw(2) << (int)d1[i] 
                      << ", " << file2_name << "=$" << std::setw(2) << (int)d2[i] << std::endl;
            diff = true;
            if (++err_count >= 10) {
                std::cout << "Stopped after 10 errors." << std::endl;
                break;
            }
        }
    }

    if (!diff && s1 == s2) {
        std::cout << "Files are identical!" << std::endl;
    } else if (!diff) {
        std::cout << "Content matches for the first " << std::dec << min_size << " bytes." << std::endl;
    }

    return diff ? 1 : 0;
}
