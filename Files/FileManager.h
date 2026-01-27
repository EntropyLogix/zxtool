#ifndef __FILEMANAGER_H__
#define __FILEMANAGER_H__

#include "File.h"
#include <vector>
#include <string>

class FileManager {
public:
    ~FileManager();
    void register_loader(FileFormat* loader);
    std::pair<bool, std::optional<uint16_t>> load_binary(const std::string& path, std::vector<FileFormat::Block>& blocks, uint16_t address);
    bool load_metadata(const std::string& path);

private:
    std::vector<FileFormat*> m_loaders;
};

#endif // __FILEMANAGER_H__