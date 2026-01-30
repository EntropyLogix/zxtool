#ifndef __FILEMANAGER_H__
#define __FILEMANAGER_H__

#include "FileFormat.h"
#include <vector>
#include <string>

class FileManager {
public:
    ~FileManager();
    void register_loader(FileFormat* loader);
    std::pair<bool, std::optional<uint16_t>> load_binary(const std::string& path, std::vector<FileFormat::Block>& blocks, uint16_t address);
    bool load_metadata(const std::string& path);

    const std::vector<FileFormat::Message>& get_last_messages() const { return m_last_messages; }

private:
    std::vector<FileFormat*> m_loaders;
    std::vector<FileFormat::Message> m_last_messages;
};

#endif // __FILEMANAGER_H__