// feito por: maquinzz
#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace peana {
struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};
struct SectionInfo {
    std::string name;
    std::uint32_t virtualSize = 0;
    std::uint32_t virtualAddress = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t rawPtr = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;
};
struct ImportEntry {
    std::string dll;
    std::vector<std::string> functions;
};
struct ExportEntry {
    std::string name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
};
struct PeInfo {
    bool is64 = false;
    std::uint16_t machine = 0;
    std::uint16_t numSections = 0;
    std::uint32_t timestamp = 0;
    std::uint16_t characteristics = 0;
    std::uint16_t optionalMagic = 0;
    std::uint32_t entryPoint = 0;
    std::uint64_t imageBase = 0;
    std::uint32_t sectionAlign = 0;
    std::uint32_t fileAlign = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dllChars = 0;
    std::uint32_t numRva = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::vector<DataDirectory> dirs;
    std::vector<SectionInfo> sections;
    std::vector<ImportEntry> imports;
    std::vector<ExportEntry> exports;
    std::string fileName;
    std::uint64_t fileSize = 0;
};
class Reader {
public:
    explicit Reader(const std::vector<std::uint8_t> &d) : data(d) {}
    bool can(std::size_t off, std::size_t n) const {
        if (n > data.size()) return false;
        if (off > data.size()) return false;
        return off + n <= data.size();
    }
    bool u16(std::size_t off, std::uint16_t &v) const {
        if (!can(off, 2)) return false;
        v = static_cast<std::uint16_t>(data[off])
          | static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[off + 1]) << 8);
        return true;
    }
    bool u32(std::size_t off, std::uint32_t &v) const {
        if (!can(off, 4)) return false;
        v = static_cast<std::uint32_t>(data[off])
          | (static_cast<std::uint32_t>(data[off + 1]) << 8)
          | (static_cast<std::uint32_t>(data[off + 2]) << 16)
          | (static_cast<std::uint32_t>(data[off + 3]) << 24);
        return true;
    }
    bool u64(std::size_t off, std::uint64_t &v) const {
        if (!can(off, 8)) return false;
        v = static_cast<std::uint64_t>(data[off])
          | (static_cast<std::uint64_t>(data[off + 1]) << 8)
          | (static_cast<std::uint64_t>(data[off + 2]) << 16)
          | (static_cast<std::uint64_t>(data[off + 3]) << 24)
          | (static_cast<std::uint64_t>(data[off + 4]) << 32)
          | (static_cast<std::uint64_t>(data[off + 5]) << 40)
          | (static_cast<std::uint64_t>(data[off + 6]) << 48)
          | (static_cast<std::uint64_t>(data[off + 7]) << 56);
        return true;
    }
    bool bytes(std::size_t off, std::uint8_t *out, std::size_t n) const {
        if (!can(off, n)) return false;
        for (std::size_t i = 0; i < n; ++i) out[i] = data[off + i];
        return true;
    }
    bool cstr(std::size_t off, std::size_t maxlen, std::string &out) const {
        out.clear();
        if (maxlen == 0 || maxlen > 512) return false;
        if (off >= data.size()) return false;
        std::size_t limit = data.size() - off;
        if (limit > maxlen) limit = maxlen;
        for (std::size_t i = 0; i < limit; ++i) {
            std::uint8_t c = data[off + i];
            if (c == 0) return true;
            if (c < 32 || c > 126) return false;
            out.push_back(static_cast<char>(c));
        }
        return !out.empty();
    }
private:
    const std::vector<std::uint8_t> &data;
};
class PeParser {
public:
    static bool parse(const std::string &path, PeInfo &out, std::string &err);
    static double calcEntropy(const std::vector<std::uint8_t> &data, std::size_t off, std::size_t n);
    static std::string machineName(std::uint16_t m);
    static std::string subsystemName(std::uint16_t s);
    static bool rvaToOffset(const PeInfo &info, std::uint32_t rva, std::uint32_t &fileOff);
};
}
