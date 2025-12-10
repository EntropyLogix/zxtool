#ifndef __FILESAVER_H__
#define __FILESAVER_H__

#include <string>
#include <vector>
#include "../Core/Tool.h"

class FileSaver {
public:
    explicit FileSaver(Tool& tool);

    void save(const std::string& outputFile, const std::string& format, const std::vector<MemoryBlock>& blocks);

private:
    void save_bin(const std::string& outputFile, const std::vector<MemoryBlock>& blocks);

    Tool& m_tool;
};

#endif//__FILESAVER_H__