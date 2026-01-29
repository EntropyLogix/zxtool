#include "SymbolFormatTests.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>
#include "../Core/Core.h"
#include "../Files/SymbolFormat.h"

void test_sym_load_simple() {
    Core core;
    SymbolFormat format(core.get_analyzer());
    
    std::string content = 
        "Label1 EQU $8000\n"
        "Label2 = $8001\n";
    
    std::ofstream out("test.sym");
    out << content;
    out.close();
    
    bool result = format.load("test.sym");
    std::filesystem::remove("test.sym");
    
    assert(result == true);
    
    auto sym1 = core.get_context().getSymbols().find("Label1");
    assert(sym1 != nullptr);
    assert(sym1->read() == 0x8000);
    
    auto sym2 = core.get_context().getSymbols().find("Label2");
    assert(sym2 != nullptr);
    assert(sym2->read() == 0x8001);
}

void test_sym_load_comments() {
    Core core;
    SymbolFormat format(core.get_analyzer());
    
    std::string content = 
        "Label1 EQU $8000 ; This is a comment\n"
        "; Full line comment\n"
        "Label2 EQU $8001\n";
    
    std::ofstream out("comments.sym");
    out << content;
    out.close();
    
    bool result = format.load("comments.sym");
    std::filesystem::remove("comments.sym");
    
    assert(result == true);
    
    auto sym1 = core.get_context().getSymbols().find("Label1");
    assert(sym1 != nullptr);
    
    const Comment* c = core.get_context().getComments().find(0x8000, Comment::Type::Inline);
    assert(c != nullptr);
    assert(c->getText() == "This is a comment");
}

void test_map_load_simple() {
    Core core;
    SymbolFormat format(core.get_analyzer());
    
    std::string content = 
        "8000 Label1\n"
        "8001 Label2\n";
    
    std::ofstream out("test.map");
    out << content;
    out.close();
    
    bool result = format.load("test.map");
    std::filesystem::remove("test.map");
    
    assert(result == true);
    
    auto sym1 = core.get_context().getSymbols().find("Label1");
    assert(sym1 != nullptr);
    assert(sym1->read() == 0x8000);
    
    auto sym2 = core.get_context().getSymbols().find("Label2");
    assert(sym2 != nullptr);
    assert(sym2->read() == 0x8001);
}

void test_sym_load_formats() {
    Core core;
    SymbolFormat format(core.get_analyzer());
    
    std::string content = 
        "Hex1 EQU $1000\n"
        "Hex2 EQU 2000H\n"
        "Hex3 EQU 3000\n"; // SymbolFormat treats numbers as hex by default
    
    std::ofstream out("formats.sym");
    out << content;
    out.close();
    
    bool result = format.load("formats.sym");
    std::filesystem::remove("formats.sym");
    
    assert(result == true);
    
    auto sym1 = core.get_context().getSymbols().find("Hex1");
    assert(sym1 != nullptr);
    assert(sym1->read() == 0x1000);
    
    auto sym2 = core.get_context().getSymbols().find("Hex2");
    assert(sym2 != nullptr);
    assert(sym2->read() == 0x2000);
    
    auto sym3 = core.get_context().getSymbols().find("Hex3");
    assert(sym3 != nullptr);
    assert(sym3->read() == 0x3000);
}