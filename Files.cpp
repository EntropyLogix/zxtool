#include "Files.h"
#include <fstream>

bool Files::read_file(const std::string& identifier, std::vector<uint8_t>& data) {
    std::filesystem::path file_path;
    if (m_current_path_stack.empty())
        file_path = std::filesystem::canonical(identifier);
    else
        file_path = std::filesystem::canonical(m_current_path_stack.back().parent_path() / identifier);
    m_current_path_stack.push_back(file_path);
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        m_current_path_stack.pop_back();
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    m_current_path_stack.pop_back();
    return true;
}

size_t Files::file_size(const std::string& identifier) {
    try {
        return std::filesystem::file_size(identifier);
    } catch (const std::filesystem::filesystem_error&) {
    }
    return 0;
}

bool Files::exists(const std::string& identifier) {
    return std::filesystem::exists(identifier);
}