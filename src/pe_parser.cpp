// feito por: maquinzz
#include "pe_parser.hpp"
#include <cmath>
#include <cstdio>
#include <fstream>
namespace peana {
namespace {
constexpr std::size_t kMaxFile = 100 * 1024 * 1024;
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxImports = 512;
constexpr std::size_t kMaxThunks = 4096;
constexpr std::size_t kMaxExports = 8192;
bool safeAdd(std::size_t a, std::size_t b, std::size_t &r) {
    r = a + b;
    return r >= a;
}
}
double PeParser::calcEntropy(const std::vector<std::uint8_t> &data, std::size_t off, std::size_t n) {
    if (n == 0) return 0.0;
    if (off >= data.size()) return 0.0;
    if (n > data.size() - off) return 0.0;
    std::uint64_t freq[256] = {};
    for (std::size_t i = 0; i < n; ++i) freq[data[off + i]]++;
    double e = 0.0;
    double len = static_cast<double>(n);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / len;
        e -= p * (std::log(p) / std::log(2.0));
    }
    return e;
}
std::string PeParser::machineName(std::uint16_t m) {
    switch (m) {
        case 0x014c: return "i386";
        case 0x8664: return "x86-64";
        case 0x01c0: return "ARM";
        case 0xaa64: return "ARM64";
        default: break;
    }
    char b[16] = {};
    std::snprintf(b, sizeof(b), "0x%04X", m);
    return std::string(b);
}
std::string PeParser::subsystemName(std::uint16_t s) {
    switch (s) {
        case 1: return "NATIVE";
        case 2: return "GUI";
        case 3: return "CUI";
        case 5: return "OS2_CUI";
        case 7: return "POSIX_CUI";
        case 9: return "WINCE_GUI";
        case 10: return "EFI_APP";
        default: break;
    }
    char b[16] = {};
    std::snprintf(b, sizeof(b), "%u", s);
    return std::string(b);
}
bool PeParser::rvaToOffset(const PeInfo &info, std::uint32_t rva, std::uint32_t &fileOff) {
    for (const auto &s : info.sections) {
        std::uint32_t span = s.virtualSize > s.rawSize ? s.virtualSize : s.rawSize;
        if (span == 0) continue;
        if (rva >= s.virtualAddress) {
            std::uint64_t diff = static_cast<std::uint64_t>(rva) - s.virtualAddress;
            if (diff < span) {
                std::uint64_t o = static_cast<std::uint64_t>(s.rawPtr) + diff;
                if (o > 0xFFFFFFFFULL) return false;
                if (o >= info.fileSize) return false;
                fileOff = static_cast<std::uint32_t>(o);
                return true;
            }
        }
    }
    if (info.sizeOfHeaders > 0 && rva < info.sizeOfHeaders) {
        if (rva >= info.fileSize) return false;
        fileOff = rva;
        return true;
    }
    return false;
}
bool PeParser::parse(const std::string &path, PeInfo &out, std::string &err) {
    out = PeInfo();
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { err = "open_failed"; return false; }
    std::streamsize sz = f.tellg();
    if (sz < 64) { err = "too_small"; return false; }
    if (sz > static_cast<std::streamsize>(kMaxFile)) { err = "too_big"; return false; }
    f.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> d(static_cast<std::size_t>(sz));
    if (!f.read(reinterpret_cast<char*>(d.data()), sz)) { err = "read_failed"; return false; }
    Reader r(d);
    std::uint16_t mz = 0;
    if (!r.u16(0, mz) || mz != 0x5A4D) { err = "bad_mz"; return false; }
    std::uint32_t lfanew = 0;
    if (!r.u32(0x3C, lfanew)) { err = "bad_lfanew"; return false; }
    std::size_t nt = static_cast<std::size_t>(lfanew);
    if (nt + 6 > d.size()) { err = "bad_nt_off"; return false; }
    std::uint32_t sig = 0;
    if (!r.u32(nt, sig) || sig != 0x00004550U) { err = "bad_pe_sig"; return false; }
    std::size_t coff = 0;
    if (!safeAdd(nt, 4, coff)) { err = "overflow"; return false; }
    std::uint16_t machine = 0, nsec = 0, chars = 0;
    std::uint32_t tstamp = 0;
    std::uint16_t optSize = 0;
    if (!r.u16(coff + 0, machine)) { err = "bad_coff"; return false; }
    if (!r.u16(coff + 2, nsec)) { err = "bad_coff"; return false; }
    if (!r.u32(coff + 4, tstamp)) { err = "bad_coff"; return false; }
    if (!r.u16(coff + 16, optSize)) { err = "bad_coff"; return false; }
    if (!r.u16(coff + 18, chars)) { err = "bad_coff"; return false; }
    if (nsec == 0 || nsec > kMaxSections) { err = "bad_sections_count"; return false; }
    if (optSize < 28 || optSize > 1024) { err = "bad_opt_size"; return false; }
    std::size_t opt = 0;
    if (!safeAdd(coff, 20, opt)) { err = "overflow"; return false; }
    if (opt + optSize > d.size()) { err = "bad_opt"; return false; }
    std::uint16_t magic = 0;
    if (!r.u16(opt + 0, magic)) { err = "bad_opt"; return false; }
    bool is64 = false;
    if (magic == 0x10b) is64 = false;
    else if (magic == 0x20b) is64 = true;
    else { err = "bad_opt_magic"; return false; }
    std::uint32_t entry = 0;
    std::uint64_t imgBase = 0;
    std::uint32_t secAlign = 0, fileAlign = 0, sizeImg = 0, sizeHdr = 0;
    std::uint16_t subsys = 0, dllc = 0;
    std::uint32_t nrva = 0;
    if (!r.u32(opt + 16, entry)) { err = "bad_opt"; return false; }
    if (!r.u32(opt + 32, secAlign)) { err = "bad_opt"; return false; }
    if (!r.u32(opt + 36, fileAlign)) { err = "bad_opt"; return false; }
    if (is64) {
        std::uint64_t b = 0;
        if (!r.u64(opt + 24, b)) { err = "bad_opt"; return false; }
        imgBase = b;
        if (!r.u32(opt + 56, sizeImg)) { err = "bad_opt"; return false; }
        if (!r.u32(opt + 60, sizeHdr)) { err = "bad_opt"; return false; }
        if (!r.u16(opt + 68, subsys)) { err = "bad_opt"; return false; }
        if (!r.u16(opt + 70, dllc)) { err = "bad_opt"; return false; }
        if (!r.u32(opt + 108, nrva)) { err = "bad_opt"; return false; }
    } else {
        std::uint32_t b = 0;
        if (!r.u32(opt + 28, b)) { err = "bad_opt"; return false; }
        imgBase = b;
        if (!r.u32(opt + 56, sizeImg)) { err = "bad_opt"; return false; }
        if (!r.u32(opt + 60, sizeHdr)) { err = "bad_opt"; return false; }
        if (!r.u16(opt + 68, subsys)) { err = "bad_opt"; return false; }
        if (!r.u16(opt + 70, dllc)) { err = "bad_opt"; return false; }
        if (!r.u32(opt + 92, nrva)) { err = "bad_opt"; return false; }
    }
    if (nrva > 16) nrva = 16;
    std::size_t dirBase = is64 ? opt + 112 : opt + 96;
    if (dirBase + static_cast<std::size_t>(nrva) * 8 > d.size()) { err = "bad_dirs"; return false; }
    out.dirs.clear();
    for (std::uint32_t i = 0; i < nrva; ++i) {
        DataDirectory dd;
        if (!r.u32(dirBase + i * 8, dd.rva)) { err = "bad_dirs"; return false; }
        if (!r.u32(dirBase + i * 8 + 4, dd.size)) { err = "bad_dirs"; return false; }
        out.dirs.push_back(dd);
    }
    while (out.dirs.size() < 16) out.dirs.push_back(DataDirectory{});
    std::size_t secBase = 0;
    if (!safeAdd(opt, optSize, secBase)) { err = "overflow"; return false; }
    if (secBase + static_cast<std::size_t>(nsec) * 40 > d.size()) { err = "bad_sec_table"; return false; }
    out.sections.clear();
    for (std::uint16_t i = 0; i < nsec; ++i) {
        std::size_t o = secBase + static_cast<std::size_t>(i) * 40;
        std::uint8_t nb[8] = {};
        if (!r.bytes(o, nb, 8)) { err = "bad_section"; return false; }
        std::string nm;
        for (int k = 0; k < 8; ++k) {
            if (nb[k] == 0) break;
            if (nb[k] < 32 || nb[k] > 126) { nm.push_back('.'); continue; }
            nm.push_back(static_cast<char>(nb[k]));
        }
        if (nm.empty()) nm = ".sec";
        SectionInfo s;
        s.name = nm;
        if (!r.u32(o + 8, s.virtualSize)) { err = "bad_section"; return false; }
        if (!r.u32(o + 12, s.virtualAddress)) { err = "bad_section"; return false; }
        if (!r.u32(o + 16, s.rawSize)) { err = "bad_section"; return false; }
        if (!r.u32(o + 20, s.rawPtr)) { err = "bad_section"; return false; }
        if (!r.u32(o + 36, s.characteristics)) { err = "bad_section"; return false; }
        if (s.rawSize > 0 && s.rawPtr != 0) {
            if (s.rawPtr < d.size()) {
                std::size_t avail = d.size() - s.rawPtr;
                std::size_t take = s.rawSize < avail ? s.rawSize : avail;
                s.entropy = calcEntropy(d, s.rawPtr, take);
            }
        }
        out.sections.push_back(s);
    }
    out.is64 = is64;
    out.machine = machine;
    out.numSections = nsec;
    out.timestamp = tstamp;
    out.characteristics = chars;
    out.optionalMagic = magic;
    out.entryPoint = entry;
    out.imageBase = imgBase;
    out.sectionAlign = secAlign;
    out.fileAlign = fileAlign;
    out.sizeOfImage = sizeImg;
    out.sizeOfHeaders = sizeHdr;
    out.subsystem = subsys;
    out.dllChars = dllc;
    out.numRva = nrva;
    out.fileName = path;
    out.fileSize = static_cast<std::uint64_t>(d.size());
    {
        DataDirectory imp = out.dirs.size() > 1 ? out.dirs[1] : DataDirectory{};
        if (imp.rva != 0 && imp.size != 0) {
            std::uint32_t impOff = 0;
            if (rvaToOffset(out, imp.rva, impOff)) {
                for (std::size_t di = 0; di < kMaxImports; ++di) {
                    std::size_t e = static_cast<std::size_t>(impOff) + di * 20;
                    if (e + 20 > d.size()) break;
                    std::uint32_t oft = 0, ft = 0, nmr = 0;
                    if (!r.u32(e + 0, oft)) break;
                    if (!r.u32(e + 12, nmr)) break;
                    if (!r.u32(e + 16, ft)) break;
                    if (oft == 0 && nmr == 0 && ft == 0) break;
                    if (nmr == 0) continue;
                    std::uint32_t nmOff = 0;
                    if (!rvaToOffset(out, nmr, nmOff)) continue;
                    std::string dll;
                    if (!r.cstr(nmOff, 256, dll)) continue;
                    ImportEntry ie;
                    ie.dll = dll;
                    std::uint32_t thunkRva = oft != 0 ? oft : ft;
                    if (thunkRva == 0) { out.imports.push_back(ie); continue; }
                    std::uint32_t thunkOff = 0;
                    if (!rvaToOffset(out, thunkRva, thunkOff)) { out.imports.push_back(ie); continue; }
                    std::size_t step = is64 ? 8 : 4;
                    for (std::size_t ti = 0; ti < kMaxThunks; ++ti) {
                        std::size_t to = static_cast<std::size_t>(thunkOff) + ti * step;
                        if (to + step > d.size()) break;
                        bool isOrd = false;
                        std::uint64_t val = 0;
                        if (is64) {
                            std::uint64_t v = 0;
                            if (!r.u64(to, v)) break;
                            val = v;
                            if ((v & 0x8000000000000000ULL) != 0) isOrd = true;
                        } else {
                            std::uint32_t v = 0;
                            if (!r.u32(to, v)) break;
                            val = v;
                            if ((v & 0x80000000U) != 0) isOrd = true;
                        }
                        if (val == 0) break;
                        if (isOrd) {
                            std::uint32_t ord = static_cast<std::uint32_t>(val & 0xFFFFULL);
                            char b[32] = {};
                            std::snprintf(b, sizeof(b), "Ordinal_%u", ord);
                            ie.functions.push_back(std::string(b));
                        } else {
                            std::uint32_t hnr = is64 ? static_cast<std::uint32_t>(val & 0xFFFFFFFFULL) : static_cast<std::uint32_t>(val);
                            std::uint32_t ho = 0;
                            if (!rvaToOffset(out, hnr, ho)) continue;
                            if (ho + 2 >= d.size()) continue;
                            std::string fn;
                            if (!r.cstr(ho + 2, 256, fn)) continue;
                            ie.functions.push_back(fn);
                        }
                        if (ie.functions.size() > 2048) break;
                    }
                    out.imports.push_back(ie);
                    if (out.imports.size() > 256) break;
                }
            }
        }
    }
    {
        DataDirectory ex = out.dirs.size() > 0 ? out.dirs[0] : DataDirectory{};
        if (ex.rva != 0 && ex.size != 0) {
            std::uint32_t exOff = 0;
            if (rvaToOffset(out, ex.rva, exOff) && exOff + 40 <= d.size()) {
                std::uint32_t nF = 0, nN = 0, aF = 0, aN = 0, aO = 0, base = 1;
                if (r.u32(exOff + 14 + 4 - 4 + 4, nF) && r.u32(exOff + 24, nN)
                    && r.u32(exOff + 28, aF) && r.u32(exOff + 32, aN)
                    && r.u32(exOff + 36, aO) && r.u32(exOff + 16, base)) {
                    if (nF > 0 && nF <= kMaxExports && nN <= nF) {
                        std::uint32_t fO = 0, nO = 0, oO = 0;
                        bool okF = rvaToOffset(out, aF, fO);
                        bool okN = nN == 0 || rvaToOffset(out, aN, nO);
                        bool okO = nN == 0 || rvaToOffset(out, aO, oO);
                        if (okF && okN && okO) {
                            for (std::uint32_t i = 0; i < nN && i < kMaxExports; ++i) {
                                std::size_t ne = static_cast<std::size_t>(nO) + i * 4;
                                std::size_t oe = static_cast<std::size_t>(oO) + i * 2;
                                if (ne + 4 > d.size() || oe + 2 > d.size()) break;
                                std::uint32_t nr = 0;
                                std::uint16_t oi = 0;
                                if (!r.u32(ne, nr)) break;
                                if (!r.u16(oe, oi)) break;
                                std::uint32_t so = 0;
                                if (!rvaToOffset(out, nr, so)) continue;
                                std::string fn;
                                if (!r.cstr(so, 256, fn)) continue;
                                ExportEntry e2;
                                e2.name = fn;
                                e2.ordinal = static_cast<std::uint32_t>(base) + oi;
                                if (oi < nF) {
                                    std::size_t fe = static_cast<std::size_t>(fO) + oi * 4;
                                    std::uint32_t fr = 0;
                                    if (r.u32(fe, fr)) e2.rva = fr;
                                }
                                out.exports.push_back(e2);
                            }
                        }
                    }
                }
            }
        }
    }
    return true;
}
}
