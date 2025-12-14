#include "FileManager.h"
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

FileManager::~FileManager() {
    for (auto loader : m_loaders) {
        delete loader;
    }
}

void FileManager::register_loader(IFile* loader) {
    m_loaders.push_back(loader);
}

LoadResult FileManager::load_binary(const std::string& path, std::vector<LoadedBlock>& blocks, uint16_t address) {
    std::string ext = fs::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    // 1. Try exact extension match
    for (const auto& loader : m_loaders) {
        auto binLoader = dynamic_cast<IBinaryFile*>(loader);
        if (!binLoader) continue;

        const auto& extensions = loader->get_extensions();
        for (const auto& supported_ext : extensions) {
            if (supported_ext == ext) {
                return binLoader->load(path, blocks, address);
            }
        }
    }

    // 2. Try wildcard match (fallback)
    for (const auto& loader : m_loaders) {
        auto binLoader = dynamic_cast<IBinaryFile*>(loader);
        if (!binLoader) continue;

        const auto& extensions = loader->get_extensions();
        for (const auto& supported_ext : extensions) {
            if (supported_ext == "*") {
                return binLoader->load(path, blocks, address);
            }
        }
    }

    return {false, std::nullopt};
}

bool FileManager::load_aux(const std::string& path) {
    std::string ext = fs::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    for (const auto& loader : m_loaders) {
        auto auxLoader = dynamic_cast<IAuxiliaryFile*>(loader);
        if (!auxLoader) continue;

        const auto& extensions = loader->get_extensions();
        for (const auto& supported_ext : extensions) {
            if (supported_ext == ext) {
                return auxLoader->load(path);
            }
        }
    }
    return false;
}