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
  GIT_TAG        main
)

FetchContent_MakeAvailable(replxx)
FetchContent_MakeAvailable(Z80)

add_executable(zxtool 
                main.cpp
                Cmd/CommandLine.cpp
                Core/Context.cpp
                Core/Analyzer.cpp
                Core/Core.cpp
                Core/Expression.cpp
                Core/Symbols.cpp
                Core/Comments.cpp
                Core/Application.cpp
                Engines/AssembleEngine.cpp
                Engines/RunEngine.cpp
                Engines/DisassembleEngine.cpp
                Engines/DebugEngine.cpp
                Files/AsmFiles.cpp
                Files/BinFiles.cpp
                Files/Z80File.cpp
                Files/SymbolFile.cpp
                Files/ControlFile.cpp
                Files/FileManager.cpp
                Utils/Strings.cpp
                Utils/Terminal.cpp
  )

  target_include_directories(zxtool PRIVATE 
    ${replxx_SOURCE_DIR}/include
    ${z80_SOURCE_DIR}
  )

  target_link_libraries(zxtool PRIVATE replxx)