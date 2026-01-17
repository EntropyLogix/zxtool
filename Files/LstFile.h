#ifndef __LSTFILE_H__
#define __LSTFILE_H__

#include "File.h"
#include "../Core/Core.h"

class LstFile : public IBinaryFile, public IAuxiliaryFile {
public:
    LstFile(Core& core);
    virtual ~LstFile() = default;

    // IBinaryFile
    LoadResult load(const std::string& path, std::vector<LoadedBlock>& blocks, uint16_t load_address) override;
    
    // IAuxiliaryFile
    bool load(const std::string& path) override;
    void parse_data(const std::string& data);

    std::vector<std::string> get_extensions() const override;

private:
    Core& m_core;
    void parse_line(const std::string& line);
};

#endif // __LSTFILE_H__