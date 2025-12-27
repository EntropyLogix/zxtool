#ifndef __REGISTER_H__
#define __REGISTER_H__

#include "CoreIncludes.h"

#include <string>
#include <cstdint>
#include <vector>
#include <algorithm>


class Register {
public:
    Register() = default;
    Register(const std::string& name) : m_name(name) {}

    const std::string& getName() const { return m_name; }

    bool is_16bit() const {
        static const std::vector<std::string> regs16 = {
            "AF", "BC", "DE", "HL", "IX", "IY", "SP", "PC", "WZ",
            "AF'", "BC'", "DE'", "HL'"
        };
        return std::find(regs16.begin(), regs16.end(), m_name) != regs16.end();
    }
    
    template <typename TBus, typename TEvents, typename TDebugger>
    uint16_t read(Z80<TBus, TEvents, TDebugger>& cpu) const {
        if (m_name == "AF") return cpu.get_AF();
        if (m_name == "BC") return cpu.get_BC();
        if (m_name == "DE") return cpu.get_DE();
        if (m_name == "HL") return cpu.get_HL();
        if (m_name == "PC") return cpu.get_PC();
        if (m_name == "SP") return cpu.get_SP();
        if (m_name == "IX") return cpu.get_IX();
        if (m_name == "IY") return cpu.get_IY();
        if (m_name == "AF'") return cpu.get_AFp();
        if (m_name == "BC'") return cpu.get_BCp();
        if (m_name == "DE'") return cpu.get_DEp();
        if (m_name == "HL'") return cpu.get_HLp();
        if (m_name == "WZ") return cpu.get_WZ();
        if (m_name == "IFF1") return cpu.get_IFF1();
        if (m_name == "IFF2") return cpu.get_IFF2();
        
        // 8-bit registers
        if (m_name == "A") return (cpu.get_AF() >> 8) & 0xFF;
        if (m_name == "F") return cpu.get_AF() & 0xFF;
        if (m_name == "B") return (cpu.get_BC() >> 8) & 0xFF;
        if (m_name == "C") return cpu.get_BC() & 0xFF;
        if (m_name == "D") return (cpu.get_DE() >> 8) & 0xFF;
        if (m_name == "E") return cpu.get_DE() & 0xFF;
        if (m_name == "H") return (cpu.get_HL() >> 8) & 0xFF;
        if (m_name == "L") return cpu.get_HL() & 0xFF;
        if (m_name == "I") return cpu.get_I();
        if (m_name == "R") return cpu.get_R();
        
        if (m_name == "IXH") return (cpu.get_IX() >> 8) & 0xFF;
        if (m_name == "IXL") return cpu.get_IX() & 0xFF;
        if (m_name == "IYH") return (cpu.get_IY() >> 8) & 0xFF;
        if (m_name == "IYL") return cpu.get_IY() & 0xFF;

        return 0;
    }

    template <typename TBus, typename TEvents, typename TDebugger>
    void write(Z80<TBus, TEvents, TDebugger>& cpu, uint16_t value) const {
        if (m_name == "AF") cpu.set_AF(value);
        else if (m_name == "BC") cpu.set_BC(value);
        else if (m_name == "DE") cpu.set_DE(value);
        else if (m_name == "HL") cpu.set_HL(value);
        else if (m_name == "PC") cpu.set_PC(value);
        else if (m_name == "SP") cpu.set_SP(value);
        else if (m_name == "IX") cpu.set_IX(value);
        else if (m_name == "IY") cpu.set_IY(value);
        else if (m_name == "AF'") cpu.set_AFp(value);
        else if (m_name == "BC'") cpu.set_BCp(value);
        else if (m_name == "DE'") cpu.set_DEp(value);
        else if (m_name == "HL'") cpu.set_HLp(value);
        else if (m_name == "WZ") cpu.set_WZ(value);
        else if (m_name == "IFF1") cpu.set_IFF1(value != 0);
        else if (m_name == "IFF2") cpu.set_IFF2(value != 0);
        
        // 8-bit writes (read-modify-write)
        else if (m_name == "A") cpu.set_AF((cpu.get_AF() & 0x00FF) | ((value & 0xFF) << 8));
        else if (m_name == "F") cpu.set_AF((cpu.get_AF() & 0xFF00) | (value & 0xFF));
        else if (m_name == "B") cpu.set_BC((cpu.get_BC() & 0x00FF) | ((value & 0xFF) << 8));
        else if (m_name == "C") cpu.set_BC((cpu.get_BC() & 0xFF00) | (value & 0xFF));
        else if (m_name == "D") cpu.set_DE((cpu.get_DE() & 0x00FF) | ((value & 0xFF) << 8));
        else if (m_name == "E") cpu.set_DE((cpu.get_DE() & 0xFF00) | (value & 0xFF));
        else if (m_name == "H") cpu.set_HL((cpu.get_HL() & 0x00FF) | ((value & 0xFF) << 8));
        else if (m_name == "L") cpu.set_HL((cpu.get_HL() & 0xFF00) | (value & 0xFF));
        else if (m_name == "I") cpu.set_I(value & 0xFF);
        else if (m_name == "R") cpu.set_R(value & 0xFF);
        
        else if (m_name == "IXH") cpu.set_IX((cpu.get_IX() & 0x00FF) | ((value & 0xFF) << 8));
        else if (m_name == "IXL") cpu.set_IX((cpu.get_IX() & 0xFF00) | (value & 0xFF));
        else if (m_name == "IYH") cpu.set_IY((cpu.get_IY() & 0x00FF) | ((value & 0xFF) << 8));
        else if (m_name == "IYL") cpu.set_IY((cpu.get_IY() & 0xFF00) | (value & 0xFF));
    }
    
    static const std::vector<std::string>& get_names() {
        static const std::vector<std::string> regs = {
            "AF", "BC", "DE", "HL", "IX", "IY", "SP", "PC", "WZ",
            "AF'", "BC'", "DE'", "HL'",
            "A", "B", "C", "D", "E", "H", "L", "I", "R", "F", "IFF1", "IFF2",
            "IXH", "IXL", "IYH", "IYL"
        };
        return regs;
    }

    static bool is_valid(const std::string& name) {
        const auto& regs = get_names();
        return std::find(regs.begin(), regs.end(), name) != regs.end();
    }

private:
    std::string m_name;
};

#endif//__REGISTER_H__