#ifndef __IFILE_H__
#define __IFILE_H__

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

struct LoadedBlock {
    uint16_t start_address;
    uint16_t size;
    std::string description;
};

struct LoadResult {
    bool success;
    std::optional<uint16_t> start_address;
};

class IFile {
public:
    virtual ~IFile() = default;
    virtual std::vector<std::string> get_extensions() const = 0;
};

class IBinaryFile : virtual public IFile {
public:
    virtual LoadResult load(const std::string& filename, std::vector<LoadedBlock>& blocks, uint16_t address) = 0;
};

class IAuxiliaryFile : virtual public IFile {
public:
    virtual bool load(const std::string& filename) = 0;
};

#endif // __IFILE_H__