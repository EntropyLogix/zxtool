cmake_minimum_required(VERSION 3.15)
project(zxtool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  replxx
  GIT_REPOSITORY https://github.com/AmokHuginnsson/replxx.git
  GIT_TAG        release-0.0.4 
)

FetchContent_Declare(
  Z80
  GIT_REPOSITORY https://github.com/EntropyLogix/Z80.git
  GIT_TAG        v1.1.2
)

FetchContent_MakeAvailable(replxx)
FetchContent_MakeAvailable(Z80)

add_executable(zxtool 
                main.cpp
                Cmd/CommandLine.cpp
                Core/Tool.cpp
                Files/FileProvider.cpp
                Files/AsmFiles.cpp
                Files/FileProcessor.cpp
                Files/BinFiles.cpp
                Files/FileSaver.cpp
                Utils/Strings.cpp
  )

  target_include_directories(zxtool PRIVATE 
    ${replxx_SOURCE_DIR}/include
    ${z80_SOURCE_DIR}
  )

  target_link_libraries(zxtool PRIVATE replxx)