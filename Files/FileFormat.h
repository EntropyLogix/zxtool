#ifndef __FILEFORMAT_H__
#define __FILEFORMAT_H__

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

class FileFormat {
public:
    enum Capability {
        None = 0,
        LoadBinary   = 1 << 0,
        SaveBinary   = 1 << 1,
        LoadMetadata = 1 << 2,
        SaveMetadata = 1 << 3
    };

    struct Message {
        enum class Type {
            Info,
            Warning,
            Error
        };
        Type type;
        std::string text;
    };

    struct Block {
        uint16_t start;
        uint16_t size;
        std::string description;
    };

    virtual ~FileFormat() = default;
    virtual std::vector<std::string> get_extensions() const = 0;

    virtual uint32_t get_capabilities() const { return None; }

    virtual bool load_binary(const std::string& filename, std::vector<Block>& blocks, uint16_t address) { return false; }
    virtual bool save_binary(const std::string& filename, const std::vector<Block>& blocks) { return false; }
    
    virtual bool load_metadata(const std::string& filename) { return false; }
    virtual bool save_metadata(const std::string& filename) { return false; }

    const std::vector<Message>& get_messages() const { return m_messages; }
    void clear_messages() { m_messages.clear(); }

protected:
    void log_info(const std::string& text) { m_messages.push_back({Message::Type::Info, text}); }
    void log_warning(const std::string& text) { m_messages.push_back({Message::Type::Warning, text}); }
    void log_error(const std::string& text) { m_messages.push_back({Message::Type::Error, text}); }

private:
    std::vector<Message> m_messages;
};

#endif // __FILEFORMAT_H__