#ifndef __SOURCEFILES_H__
#define __SOURCEFILES_H__

#include <vector>
#include <filesystem>

#include "../Z80Assemble.h"

class FileProvider : public IFileProvider {
public:
    bool read_file(const std::string& identifier, std::vector<uint8_t>& data) override;
    size_t file_size(const std::string& identifier) override;
    bool exists(const std::string& identifier) override;
private:
    std::vector<std::filesystem::path> m_current_path_stack;
};

#endif//__SOURCEFILES_H__
