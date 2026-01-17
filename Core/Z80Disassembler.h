#ifndef __CORE_Z80DISASSEMBLER_H__
#define __CORE_Z80DISASSEMBLER_H__

#include "Z80Decoder.h"
#include "Z80.h"
#include <vector>
#include <map>
#include <set>
#include <bitset>
#include <functional>
#include <iomanip>
#include <sstream>

template <typename TMemory> class Z80Disassembler {
public:
    using CodeLine = typename Z80Decoder<TMemory>::CodeLine;

    struct CodeMap : public std::vector<uint8_t> {
        using std::vector<uint8_t>::vector;
        enum MapFlags : uint8_t {
            FLAG_NONE = 0,
            FLAG_CODE_START = 1 << 0,    // Start of instruction
            FLAG_CODE_INTERIOR = 1 << 1, // Arguments/interior of instruction
            FLAG_DATA_READ = 1 << 2,     // Data read
            FLAG_DATA_WRITE = 1 << 3,    // Data write
            FLAG_EXECUTED = 1 << 4       // Code executed
        };
        size_t mark_code(uint16_t address, size_t length, bool set) {
            if (this->empty())
                return 0;
            size_t sz = this->size();
            if (length == 0) 
                return 0;
            size_t changed = 0;
            for (size_t i = 0; i < length; ++i) {
                size_t idx = (address + i) % sz;
                uint8_t old_val = (*this)[idx];
                uint8_t val = old_val & ~(FLAG_CODE_START | FLAG_CODE_INTERIOR);
                if (set) {
                    if (i == 0)
                        val |= FLAG_CODE_START;
                    else
                        val |= FLAG_CODE_INTERIOR;
                }
                if (val != old_val) {
                    (*this)[idx] = val;
                    changed++;
                }
            }
            changed += cleanup_orphans(address + length);
            return changed;
        }
        size_t mark_data(uint16_t address, size_t length, bool write, bool set) {
            if (this->empty())
                return 0;
            size_t sz = this->size();
            uint8_t flag = write ? FLAG_DATA_WRITE : FLAG_DATA_READ;
            size_t changed = 0;
            for (size_t i = 0; i < length; ++i) {
                size_t idx = (address + i) % sz;
                uint8_t old_val = (*this)[idx];
                uint8_t val = old_val;
                if (set)
                    val |= flag;
                else
                    val &= ~flag;
                if (val != old_val) {
                    (*this)[idx] = val;
                    changed++;
                }
            }
            return changed;
        }
        size_t mark_executed(uint16_t address, bool set) {
            if (this->empty())
                return 0;
            size_t sz = this->size();
            size_t idx = address % sz;
            uint8_t old_val = (*this)[idx];
            uint8_t val = old_val;
            if (set)
                val |= FLAG_EXECUTED;
            else
                val &= ~FLAG_EXECUTED;
            if (val != old_val) {
                (*this)[idx] = val;
                return 1;
            }
            return 0;
        }
    private:
        size_t cleanup_orphans(uint32_t start_index) {
            if (this->empty()) return 0;
            size_t sz = this->size();
            size_t count = 0;
            size_t changed = 0;
            while (count < sz) {
                size_t idx = start_index % sz;
                uint8_t old_val = (*this)[idx];
                if ((old_val & FLAG_CODE_INTERIOR) && !(old_val & FLAG_CODE_START)) {
                    uint8_t val = old_val & ~FLAG_CODE_INTERIOR;
                    if (val != old_val) {
                        (*this)[idx] = val;
                        changed++;
                    }
                    start_index++;
                    count++;
                } else {
                    break;
                }
            }
            return changed;
        }
    };

    Z80Disassembler(TMemory* memory, ILabels* labels = nullptr) : m_decoder(memory, labels), m_memory(memory), m_labels(labels) {}
    virtual ~Z80Disassembler() = default;

    Z80Decoder<TMemory>& get_decoder() { return m_decoder; }

    void set_z80n_mode(bool enable) { m_decoder.set_z80n_mode(enable); }
    bool is_z80n_mode() const { return m_decoder.is_z80n_mode(); }

    void set_validation_mask(std::bitset<65536>* mask) {
        m_valid_mask = mask;
    }
    void set_validation_range(uint16_t start, uint16_t end, bool valid) {
        if (!m_valid_mask) return;
        for (size_t i = start; i <= end && i < 65536; ++i)
            (*m_valid_mask)[i] = valid;
    }

    enum class AnalysisMode { RAW, HEURISTIC, EXEC };
    class CodeMapProfiler {
    public:
        enum Opcode : uint8_t {
            OP_RET      = 0xC9,
            OP_RET_CC   = 0xC0, // Mask 0xC7
            OP_CALL     = 0xCD,
            OP_CALL_CC  = 0xC4, // Mask 0xC7
            OP_RST      = 0xC7, // Mask 0xC7
            OP_PREFIX   = 0xED,
            OP_RETN_I   = 0x45  // Mask 0xC7 inside ED
        };
        CodeMapProfiler(CodeMap& map, TMemory* mem, std::bitset<65536>* valid_mask = nullptr) 
            : m_code_map(map), m_memory(mem), m_valid_mask(valid_mask), m_cpu(nullptr), m_labels(nullptr) {}
        void connect(Z80<CodeMapProfiler, Z80StandardEvents, CodeMapProfiler>* cpu) {
            m_cpu = cpu;
        }
        void set_labels(ILabels* labels) {
            m_labels = labels;
        }
        void set_generate_labels(bool generate) {
            m_generate_labels = generate;
        }
        uint8_t read(uint16_t address) {
            if (m_inside_instruction && m_cpu->get_PC() == address) {
                if (m_valid_mask && !(*m_valid_mask)[address])
                    return m_memory->peek(address);
                m_instruction_byte_count++;
                uint8_t flags = (m_instruction_byte_count == 1) ? CodeMap::FLAG_CODE_START : CodeMap::FLAG_CODE_INTERIOR;
                flags |= CodeMap::FLAG_EXECUTED;
                m_code_map[address] |= flags;
                return m_memory->peek(address);
            }
            m_code_map[address] |= CodeMap::FLAG_DATA_READ;
            return m_memory->peek(address);
        }
        void write(uint16_t address, uint8_t value) {
            m_code_map[address] |= CodeMap::FLAG_DATA_WRITE;
            m_memory->poke(address, value);
        }
        void reset() {
            m_pc_before_step = 0;
            m_inside_instruction = false;
            m_instruction_byte_count = 0;
        }
        void before_step() {
            if (m_cpu) {
                m_inside_instruction = true;
                m_pc_before_step = m_cpu->get_PC();
                m_instruction_byte_count = 0;
            }
        }
        void after_step() {
            m_inside_instruction = false;
            if (!m_cpu || !m_labels || !m_generate_labels)
                return;
            uint16_t pc_after = m_cpu->get_PC();
            if (pc_after == m_pc_before_step)
                return;
            if ((uint16_t)(m_pc_before_step + m_instruction_byte_count) != pc_after) {
                uint8_t opcode = m_memory->peek(m_pc_before_step);
                if (opcode == OP_RET || (opcode & 0xC7) == OP_RET_CC)
                    return;
                if (opcode == OP_PREFIX) {
                    uint8_t opcode2 = m_memory->peek(m_pc_before_step + 1);
                    if ((opcode2 & 0xC7) == OP_RETN_I)
                        return;
                }
                if (m_labels->get_label(pc_after).empty()) {
                    bool is_call = (opcode == OP_CALL) || ((opcode & 0xC7) == OP_CALL_CC) || ((opcode & 0xC7) == OP_RST);
                    char buffer[10];
                    char* p = buffer;
                    if (is_call) {
                        *p++ = 'S';
                        *p++ = 'U';
                        *p++ = 'B';
                        *p++ = '_'; }
                    else {
                        *p++ = 'L';
                        *p++ = '_';
                    }
                    const char* hex = "0123456789ABCDEF";
                    *p++ = hex[(pc_after >> 12) & 0xF];
                    *p++ = hex[(pc_after >> 8) & 0xF];
                    *p++ = hex[(pc_after >> 4) & 0xF];
                    *p++ = hex[pc_after & 0xF];
                    *p = '\0';
                    //m_labels->add_label(pc_after, std::string(buffer, p - buffer));
                }
            }
        }
        uint8_t in(uint16_t port) { return 0xFF; }
        void out(uint16_t port, uint8_t value) {}        
        void before_IRQ() {} void after_IRQ() {} void before_NMI() {} void after_NMI() {}
    private:
        CodeMap& m_code_map;
        TMemory* m_memory;
        std::bitset<65536>* m_valid_mask;
        Z80<CodeMapProfiler, Z80StandardEvents, CodeMapProfiler>* m_cpu;
        ILabels* m_labels;
        bool m_generate_labels = true;
        uint16_t m_pc_before_step = 0;
        bool m_inside_instruction = false;
        uint8_t m_instruction_byte_count = 0;
    };

    virtual std::vector<CodeLine> parse_code(uint16_t& start_address, size_t instruction_limit, CodeMap* external_code_map = nullptr, bool use_execution = false, bool use_heuristic = false, size_t max_data_group = 16) {
        CodeMap local_map;
        CodeMap* pMap = external_code_map; 
        if (!pMap) {
            pMap = &local_map;
        }
        if (pMap->size() < 0x10000)
            pMap->resize(0x10000, CodeMap::FLAG_NONE);
        bool has_map_info = (external_code_map != nullptr);
        if (use_execution) {
            run_execution_phase(*pMap, start_address);
            has_map_info = true; 
        }
        if (use_heuristic) {
            run_heuristic_phase(*pMap, start_address);
            has_map_info = true;
        }
        return generate_listing(*pMap, start_address, instruction_limit, has_map_info, max_data_group);
    }

    virtual uint16_t parse_instruction_backwards(uint16_t target_addr, CodeMap* map = nullptr) {
        if (map) {
            uint16_t ptr = target_addr - 1;
            int safety = 0;
            const int MAX_SAFETY = 32;
            while (safety < MAX_SAFETY) {
                uint8_t flags = (*map)[ptr];
                if (flags & CodeMap::FLAG_CODE_START) {
                    CodeLine line = m_decoder.parse_instruction(ptr);
                    if ((uint16_t)(ptr + (uint16_t)line.bytes.size()) == target_addr)
                        return ptr;
                    break;
                }
                if (flags & CodeMap::FLAG_CODE_INTERIOR) {
                    ptr--;
                    safety++;
                    continue;
                }
                break;
            }
        }
        const int HEURISTIC_SEARCH_DEPTH = 24;
        const int HEURISTIC_STEP_LIMIT = 32;
        uint16_t start_scan = target_addr - HEURISTIC_SEARCH_DEPTH;
        std::map<uint16_t, int> votes;
        for (int i = 0; i <= (HEURISTIC_SEARCH_DEPTH - 4); ++i) {
            uint16_t pc = start_scan + i;
            uint16_t prev = pc;
            int steps = 0;
            while (pc != target_addr && steps < HEURISTIC_STEP_LIMIT) {
                int16_t dist = (int16_t)((uint16_t)(target_addr - pc));
                if (dist < 0)
                    break;
                prev = pc;
                CodeLine line = m_decoder.parse_instruction(pc);
                pc = (uint16_t)(pc + line.bytes.size());
                steps++;
            }
            if (pc == target_addr)
                votes[prev]++;
        }
        uint16_t winner = target_addr - 1;
        int max_votes = -1;
        for (auto const& [addr, count] : votes) {
            if (count > max_votes) {
                max_votes = count;
                winner = addr;
            }
        }
        return winner;
    }

    std::vector<uint16_t> analyze_code_map(const CodeMapProfiler& profiler) {
        std::vector<uint16_t> smc_locations;
        for (uint32_t i = 0; i < 0x10000; ++i) {
            uint8_t flags = profiler.m_code_map[i];
            bool is_code = (flags & CodeMap::FLAG_CODE_START) || (flags & CodeMap::FLAG_CODE_INTERIOR);
            bool is_written = (flags & CodeMap::FLAG_DATA_WRITE);
            if (is_code && is_written)
                smc_locations.push_back((uint16_t)i);
        }
        return smc_locations;
    }

protected:
    virtual bool is_valid_address(uint16_t address) {
        if (m_valid_mask)
            return (*m_valid_mask)[address];
        return true;
    }

    static constexpr size_t EXECUTION_TRACE_LIMIT = 1000000;

    void group_data_blocks(uint32_t& pc, std::vector<CodeLine>& result, size_t instruction_limit, std::function<bool(uint32_t)> is_data, size_t max_data_group = 16) {
        while (pc < 0x10000 && is_data(pc)) {
            if (result.size() >= instruction_limit)
                break;
            uint16_t scan_pc = (uint16_t)pc;
            uint8_t fill_byte = m_memory->peek(scan_pc);
            size_t repeat_count = 0;
            while (scan_pc + repeat_count < 0x10000 && is_data(scan_pc + repeat_count) && m_memory->peek(scan_pc + repeat_count) == fill_byte)
                repeat_count++;
            const size_t DS_THRESHOLD = 4;
            if (repeat_count >= DS_THRESHOLD) {
                result.push_back(m_decoder.parse_ds(scan_pc, repeat_count, fill_byte));
                pc += repeat_count;
            } else {
                uint16_t db_start_pc = (uint16_t)pc;
                size_t db_count = 0;
                while (pc < 0x10000 && is_data(pc)) {
                    if (max_data_group > 0 && db_count >= max_data_group)
                        break;
                    uint8_t next_fill = m_memory->peek(pc);
                    size_t next_repeat = 0;
                    while (pc + next_repeat < 0x10000 && is_data(pc + next_repeat) && m_memory->peek(pc + next_repeat) == next_fill)
                        next_repeat++;
                    if (next_repeat >= DS_THRESHOLD)
                        break;
                    db_count++;
                    pc++;
                }
                if (db_count > 0)
                    result.push_back(m_decoder.parse_db(db_start_pc, db_count));
            }
        }
    }

    void run_execution_phase(CodeMap& map, uint16_t start_addr) {
        CodeMapProfiler profiler(map, m_memory, m_valid_mask);
        profiler.set_labels(m_labels);
        Z80<CodeMapProfiler, Z80StandardEvents, CodeMapProfiler> cpu(&profiler, nullptr, &profiler);
        profiler.connect(&cpu);
        cpu.set_PC(start_addr);
        std::set<uint16_t> executed_pcs;
        for (size_t i = 0; i < EXECUTION_TRACE_LIMIT; ++i) {
            uint16_t pc = cpu.get_PC();
            if (!is_valid_address(pc))
                break;
            executed_pcs.insert(pc);
            cpu.step();
            if (cpu.is_halted())
                break;
        }
    }
    void run_heuristic_phase(CodeMap& map, uint16_t start_addr) {
        std::vector<bool> visited(0x10000, false);
        std::vector<uint16_t> work_list;
        bool found_existing_code = false;
        for(size_t i=0; i<map.size(); ++i) {
            if (map[i] & CodeMap::FLAG_CODE_START) {
                work_list.push_back((uint16_t)i);
                found_existing_code = true;
            }
        }
        if (!found_existing_code || work_list.empty())
            work_list.push_back(start_addr);
        while (!work_list.empty()) {
            uint16_t current_addr = work_list.back();
            work_list.pop_back();
            if (visited[current_addr])
                continue;
            while (true) {
                if (!is_valid_address(current_addr))
                    break;
                if (visited[current_addr])
                    break;
                CodeLine line = m_decoder.parse_instruction(current_addr);
                uint16_t len = line.bytes.size();
                visited[current_addr] = true;
                map[current_addr] |= CodeMap::FLAG_CODE_START;
                for(size_t k=1; k<len; ++k)
                {
                    uint16_t addr = (uint16_t)(current_addr + k);
                    visited[addr] = true;
                    map[addr] |= CodeMap::FLAG_CODE_INTERIOR;
                }
                if (line.has_flag(CodeLine::Type::JUMP) || line.has_flag(CodeLine::Type::CALL)) {
                    if (!line.operands.empty()) {
                        const auto& last_op = line.operands.back();
                        if (last_op.type == CodeLine::Operand::Type::IMM16) {
                            uint16_t target = (uint16_t)last_op.num_val;
                            if (is_valid_address(target)) {
                                work_list.push_back(target);
                                if (m_labels && m_labels->get_label(target).empty()) {
                                    std::stringstream ss;
                                    ss << (line.type == CodeLine::Type::CALL ? "SUB_" : "L_");
                                    ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << target;
                                    //m_labels->add_label(target, ss.str());
                                }
                            }
                        }
                    }
                }
                bool stop = false;
                if (line.mnemonic == "RET" || line.mnemonic == "RETI" || line.mnemonic == "RETN" || line.mnemonic == "HALT") 
                    stop = true;
                else if (line.mnemonic == "JP" || line.mnemonic == "JR") {
                     bool is_conditional = !line.operands.empty() && line.operands[0].type == CodeLine::Operand::Type::CONDITION;
                     if (!is_conditional)
                        stop = true;
                }
                current_addr += len;
                if (stop)
                    break;
            }
        }
    }
    virtual std::vector<CodeLine> generate_listing(CodeMap& map, uint16_t& start_address, size_t instruction_limit, bool use_map, size_t max_data_group = 16) {
        if (instruction_limit == 0)
            instruction_limit = (size_t)-1; // Treat 0 as unlimited (SIZE_MAX)
        std::vector<CodeLine> result;
        uint32_t pc = start_address;
        while (pc < 0x10000 && result.size() < instruction_limit) {
            uint16_t current_pc = (uint16_t)pc;
            if (!is_valid_address(current_pc)) {
                pc++;
                continue;
            }
            bool is_code = false;
            if (use_map) {
                if (map[current_pc] & CodeMap::FLAG_CODE_START)
                    is_code = true;
                else if (map[current_pc] & CodeMap::FLAG_CODE_INTERIOR) {
                    pc++;
                    continue;
                }
            } else
                is_code = true;
            if (is_code) {
                CodeLine line = m_decoder.parse_instruction(current_pc);
                if (line.bytes.empty()) {
                    result.push_back(m_decoder.parse_db(current_pc, 1));
                    pc++;
                } else {
                    result.push_back(line);
                    pc += line.bytes.size();
                }
            } else {
                group_data_blocks(pc, result, instruction_limit, [&](uint32_t addr) { 
                     if (addr >= 0x10000)
                        return false;
                     return !(map[addr] & (CodeMap::FLAG_CODE_START | CodeMap::FLAG_CODE_INTERIOR));
                }, max_data_group);
            }
        }
        start_address = (uint16_t)pc;
        return result;
    }

    Z80Decoder<TMemory> m_decoder;
    TMemory* m_memory;
    ILabels* m_labels = nullptr;
    std::bitset<65536>* m_valid_mask = nullptr;
};

template <typename TMemory> class Z80Analyzer : public Z80Disassembler<TMemory> {
public:
    using Z80Disassembler<TMemory>::Z80Disassembler;
};

#endif // __CORE_Z80DISASSEMBLER_H__