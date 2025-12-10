#ifndef __FILEPROCESSOR_H__
#define __FILEPROCESSOR_H__

#include <string>
#include <vector>
#include <cstdint>

#include "../Core/Tool.h"
#include "BinFiles.h"
#include "AsmFiles.h"

struct File {
    std::string path;
    uint16_t address;
};

class FileProcessor {
public:
    explicit FileProcessor(Tool& tool);
    std::vector<MemoryBlock> process(const std::vector<File>& files, bool verbose);
private:
    Tool& m_tool;
    BinFiles m_bin_files;
    AsmFiles m_asm_files;
    std::string get_file_extension(const std::string& filename);
};

#endif//__FILEPROCESSOR_H__