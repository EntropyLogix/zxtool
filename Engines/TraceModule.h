#pragma once
#include <vector>
#include <cstdint>
#include <algorithm>
#include <cstring>

struct TraceEntry {
    uint16_t pc;
    uint8_t  opcodes[4];
    uint8_t  len;
};

class TraceModule {
public:
    TraceModule(size_t size = 1024) {
        buffer.resize(size);
    }

    void push(uint16_t pc, const std::vector<uint8_t>& bytes) {
        if (!recording) return;
        
        TraceEntry& entry = buffer[head];
        entry.pc = pc;
        entry.len = (uint8_t)std::min((size_t)4, bytes.size());
        for (size_t i = 0; i < entry.len; ++i) {
            entry.opcodes[i] = bytes[i];
        }
        
        head = (head + 1) % buffer.size();
        if (head == 0) wrapped = true;
    }

    void clear() {
        head = 0;
        wrapped = false;
    }

    void set_recording(bool on) {
        recording = on;
    }

    bool is_recording() const {
        return recording;
    }

    std::vector<TraceEntry> get_history(size_t count) const {
        std::vector<TraceEntry> result;
        size_t available = wrapped ? buffer.size() : head;
        if (count > available) count = available;

        for (size_t i = 0; i < count; ++i) {
            size_t idx = (head >= i + 1) ? (head - (i + 1)) : (buffer.size() - ((i + 1) - head));
            result.push_back(buffer[idx]);
        }
        std::reverse(result.begin(), result.end());
        return result;
    }

    size_t get_count() const { return wrapped ? buffer.size() : head; }
    size_t get_capacity() const { return buffer.size(); }

private:
    std::vector<TraceEntry> buffer;
    size_t head = 0;
    bool wrapped = false;
    bool recording = false;
};