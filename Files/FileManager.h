#ifndef __FILEMANAGER_H__
#define __FILEMANAGER_H__

#include "File.h"
#include <vector>
#include <string>

class FileManager {
public:
    ~FileManager();
    void register_loader(IFile* loader);
    LoadResult load_binary(const std::string& path, std::vector<LoadedBlock>& blocks, uint16_t address);
    bool load_aux(const std::string& path);

private:
    std::vector<IFile*> m_loaders;
};

#endif // __FILEMANAGER_H__