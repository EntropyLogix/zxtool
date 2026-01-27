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

void FileManager::register_loader(FileFormat* loader) {
    m_loaders.push_back(loader);
}

std::pair<bool, std::optional<uint16_t>> FileManager::load_binary(const std::string& path, std::vector<FileFormat::Block>& blocks, uint16_t address) {
    std::string ext = fs::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    // 1. Try exact extension match
    for (const auto& loader : m_loaders) {
        if (!(loader->get_capabilities() & FileFormat::LoadBinary)) continue;
        const auto& extensions = loader->get_extensions();
        for (const auto& supported_ext : extensions) {
            if (supported_ext == ext) {
                size_t initial_size = blocks.size();
                if (loader->load_binary(path, blocks, address)) {
                    if (blocks.size() > initial_size) {
                        return {true, blocks[initial_size].start};
                    }
                    return {true, std::nullopt};
                }
            }
        }
    }

    // 2. Try wildcard match (fallback)
    for (const auto& loader : m_loaders) {
        if (!(loader->get_capabilities() & FileFormat::LoadBinary)) continue;
        const auto& extensions = loader->get_extensions();
        for (const auto& supported_ext : extensions) {
            if (supported_ext == "*") {
                size_t initial_size = blocks.size();
                if (loader->load_binary(path, blocks, address)) {
                    if (blocks.size() > initial_size) {
                        return {true, blocks[initial_size].start};
                    }
                    return {true, std::nullopt};
                }
            }
        }
    }

    return {false, std::nullopt};
}

bool FileManager::load_metadata(const std::string& path) {
    std::string ext = fs::path(path).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    for (const auto& loader : m_loaders) {
        if (!(loader->get_capabilities() & FileFormat::LoadMetadata)) continue;
        const auto& extensions = loader->get_extensions();
        for (const auto& supported_ext : extensions) {
            if (supported_ext == ext) {
                if (loader->load_metadata(path)) return true;
            }
        }
    }
    return false;
}