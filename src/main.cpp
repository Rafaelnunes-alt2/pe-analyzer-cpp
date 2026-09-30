// feito por: maquinzz
#include "pe_parser.hpp"
#include <cstdio>
#include <iostream>
#include <string>
using peana::PeInfo;
namespace {
void printInfo(const PeInfo &p) {
    std::cout << "file: " << p.fileName << "\n";
    std::cout << "size: " << p.fileSize << " bytes\n";
    std::cout << "arch: " << (p.is64 ? "PE32+ x64" : "PE32 x86") << " (" << peana::PeParser::machineName(p.machine) << ")\n";
    std::cout << "sections: " << p.numSections << "\n";
    std::cout << "entry: 0x";
    {
        char b[16] = {};
        std::snprintf(b, sizeof(b), "%08X", p.entryPoint);
        std::cout << b;
    }
    std::cout << "\n";
    std::cout << "imagebase: 0x";
    {
        char b[32] = {};
        if (p.is64) std::snprintf(b, sizeof(b), "%016llX", static_cast<unsigned long long>(p.imageBase));
        else std::snprintf(b, sizeof(b), "%08llX", static_cast<unsigned long long>(p.imageBase));
        std::cout << b;
    }
    std::cout << "\n";
    std::cout << "subsystem: " << peana::PeParser::subsystemName(p.subsystem) << "\n";
    std::cout << "\n[sections]\n";
    for (const auto &s : p.sections) {
        char b[160] = {};
        std::snprintf(b, sizeof(b), "%-8s VA=0x%08X VS=%8u RAW=%8u ENT=%.3f CH=0x%08X",
            s.name.c_str(), s.virtualAddress, s.virtualSize, s.rawSize, s.entropy, s.characteristics);
        std::cout << b << "\n";
    }
    std::cout << "\n[imports] dlls=" << p.imports.size() << "\n";
    std::size_t totalF = 0;
    for (const auto &im : p.imports) totalF += im.functions.size();
    std::cout << "functions=" << totalF << "\n";
    for (const auto &im : p.imports) {
        std::cout << "  " << im.dll << " (" << im.functions.size() << ")\n";
        std::size_t lim = im.functions.size() > 25 ? 25 : im.functions.size();
        for (std::size_t i = 0; i < lim; ++i) std::cout << "    " << im.functions[i] << "\n";
        if (im.functions.size() > lim) std::cout << "    ... +" << (im.functions.size() - lim) << " more\n";
    }
    std::cout << "\n[exports] count=" << p.exports.size() << "\n";
    std::size_t elim = p.exports.size() > 40 ? 40 : p.exports.size();
    for (std::size_t i = 0; i < elim; ++i) {
        char b[64] = {};
        std::snprintf(b, sizeof(b), "ord=%u rva=0x%08X", p.exports[i].ordinal, p.exports[i].rva);
        std::cout << "  " << p.exports[i].name << " " << b << "\n";
    }
    if (p.exports.size() > elim) std::cout << "  ... +" << (p.exports.size() - elim) << " more\n";
}
}
int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "usage: pe-analyzer <file.exe>" << "\n";
        return 1;
    }
    std::string path = argv[1];
    if (path.empty() || path.size() > 4096) {
        std::cerr << "bad_path" << "\n";
        return 1;
    }
    PeInfo info;
    std::string err;
    if (!peana::PeParser::parse(path, info, err)) {
        std::cerr << "parse_failed: " << err << "\n";
        return 2;
    }
    printInfo(info);
    return 0;
}
