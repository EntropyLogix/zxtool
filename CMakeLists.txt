cmake_minimum_required(VERSION 3.15)
project(zxtool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  Z80
  GIT_REPOSITORY https://github.com/EntropyLogix/Z80.git
  GIT_TAG        main
)

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
                Core/Variables.cpp
                Core/Application.cpp
                Engines/AssembleEngine.cpp
                Engines/RunEngine.cpp
                Engines/DisassembleEngine.cpp
                Engines/DebugEngine.cpp
                Core/Debugger.cpp
                Engines/ProfileEngine.cpp
                Engines/Autocompletion.cpp
                Engines/Hint.cpp
                Files/AssemblyFormat.cpp
                Files/BinaryFormat.cpp
                Files/Z80Format.cpp
                Files/SymbolFormat.cpp
                Files/ListingFormat.cpp
                Files/SkoolFormat.cpp
                Files/FileManager.cpp
                Utils/Checksum.cpp
                Utils/Strings.cpp
                Utils/Commands.cpp
                Utils/Terminal.cpp
  )

  target_include_directories(zxtool PRIVATE 
    ${z80_SOURCE_DIR}
  )

add_subdirectory(Tests)