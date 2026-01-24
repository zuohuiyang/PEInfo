#include "stdafx.h"
#include "CliOptions.h"
#include "PEDebugInfo.h"
#include "PEParser.h"
#include "PESignature.h"
#include "HashCalculator.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <wintrust.h>

namespace {

std::wstring ToWStringUtf8BestEffort(const std::string& s) {
    if (s.empty()) {
        return L"";
    }

    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    UINT codePage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (needed == 0) {
        codePage = CP_ACP;
        flags = 0;
        needed = MultiByteToWideChar(codePage, flags, s.data(), static_cast<int>(s.size()), nullptr, 0);
    }
    if (needed <= 0) {
        return L"";
    }

    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(codePage, flags, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

static std::wstring FileTimeToStringUtc(const FILETIME& ft) {
    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&ft, &st)) {
        return L"";
    }
    wchar_t buf[64] = {};
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::wstring FormatCoffTime(DWORD timeDateStamp, CliTimeFormat mode) {
    if (mode == CliTimeFormat::Raw) {
        std::wostringstream oss;
        oss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << timeDateStamp;
        return oss.str();
    }

    ULONGLONG t = static_cast<ULONGLONG>(timeDateStamp);
    ULONGLONG ft64 = (t + 11644473600ULL) * 10000000ULL;
    FILETIME ft = {};
    ft.dwLowDateTime = static_cast<DWORD>(ft64 & 0xFFFFFFFFu);
    ft.dwHighDateTime = static_cast<DWORD>(ft64 >> 32);

    if (mode == CliTimeFormat::Utc) {
        return FileTimeToStringUtc(ft) + L"Z";
    }

    FILETIME localFt = {};
    if (!FileTimeToLocalFileTime(&ft, &localFt)) {
        return L"";
    }
    return FileTimeToStringUtc(localFt);
}

static std::wstring HexU32(DWORD v, int width) {
    std::wostringstream oss;
    oss << L"0x" << std::hex << std::setw(width) << std::setfill(L'0') << v << std::dec;
    return oss.str();
}

static std::wstring HexU64(ULONGLONG v, int width) {
    std::wostringstream oss;
    oss << L"0x" << std::hex << std::setw(width) << std::setfill(L'0') << v << std::dec;
    return oss.str();
}

static std::string WStringToUtf8(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

static bool WriteAllBytes(const std::wstring& path, const std::string& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        return false;
    }
    if (!bytes.empty()) {
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(f);
}

static void PrintHeaderInfo(std::wostream& os, const PEHeaderInfo& h, const CliOptions& opt) {
    os << L"PE Header:\n";
    os << L"  Bitness: " << (h.is64Bit ? L"x64" : (h.is32Bit ? L"x86" : L"Unknown")) << L"\n";
    os << L"  Machine: " << HexU32(h.machine, 4) << L"\n";
    os << L"  Sections: " << h.numberOfSections << L"\n";
    if (opt.timeFormat == CliTimeFormat::Raw) {
        os << L"  TimeDateStamp: " << HexU32(h.timeDateStamp, 8) << L"\n";
    } else {
        os << L"  TimeDateStamp: " << HexU32(h.timeDateStamp, 8) << L" (" << FormatCoffTime(h.timeDateStamp, opt.timeFormat) << L")\n";
    }
    os << L"  SizeOfImage: " << HexU32(h.sizeOfImage, 8) << L"\n";
    os << L"  EntryPointRVA: " << HexU32(h.entryPoint, 8) << L"\n";
    os << L"  ImageBase: " << HexU64(h.imageBase, 16) << L"\n";
    os << L"  Subsystem: " << ToWStringUtf8BestEffort(h.subsystem) << L"\n";
}

static void PrintSectionsSummary(std::wostream& os, const std::vector<PESectionInfo>& sections) {
    if (sections.empty()) {
        os << L"Sections: (none)\n";
        return;
    }
    os << L"Sections:\n";
    os << L"  Name     RVA       VSz       RawOff    RawSz     Flags\n";
    for (const auto& s : sections) {
        std::wstring name = ToWStringUtf8BestEffort(s.name);
        if (name.size() > 8) {
            name.resize(8);
        }
        std::wstring flags;
        flags.push_back((s.characteristics & IMAGE_SCN_MEM_READ) ? L'R' : L'-');
        flags.push_back((s.characteristics & IMAGE_SCN_MEM_WRITE) ? L'W' : L'-');
        flags.push_back((s.characteristics & IMAGE_SCN_MEM_EXECUTE) ? L'X' : L'-');

        os << L"  " << std::left << std::setw(8) << std::setfill(L' ') << name << std::right
           << L" " << HexU32(s.virtualAddress, 8)
           << L" " << HexU32(s.virtualSize, 8)
           << L" " << HexU32(s.rawAddress, 8)
           << L" " << HexU32(s.rawSize, 8)
           << L"  " << flags << L"\n";
    }
}

static void PrintImportsSummary(std::wostream& os, const std::wstring& title, const std::vector<PEImportDLL>& imports, size_t maxFunctionsPerDll) {
    if (imports.empty()) {
        os << title << L": (none)\n";
        return;
    }

    bool unlimited = (maxFunctionsPerDll == 0);

    os << title << L":\n";
    for (const auto& dll : imports) {
        os << L"  " << ToWStringUtf8BestEffort(dll.dllName) << L" (" << dll.functions.size() << L" funcs)\n";
        size_t shown = 0;
        for (const auto& fn : dll.functions) {
            if (!unlimited && shown >= maxFunctionsPerDll) {
                os << L"    ...\n";
                break;
            }
            os << L"    " << ToWStringUtf8BestEffort(fn.name) << L"\n";
            ++shown;
        }
    }
}

static void PrintExportsSummary(std::wostream& os, const std::vector<PEExportFunction>& exports, size_t maxExports) {
    if (exports.empty()) {
        os << L"Exports: (none)\n";
        return;
    }

    os << L"Exports:\n";
    os << L"  Ordinal  RVA       Name\n";
    size_t shown = 0;
    for (const auto& e : exports) {
        if (shown >= maxExports) {
            os << L"  ...\n";
            break;
        }
        os << L"  " << std::setw(7) << e.ordinal << L"  0x" << std::hex << std::setw(8) << std::setfill(L'0') << e.rva
           << std::dec << std::setfill(L' ') << L"  "
           << (e.hasName ? ToWStringUtf8BestEffort(e.name) : L"(no-name)") << L"\n";
        ++shown;
    }
}

static void PrintPdbInfo(std::wostream& os, const std::optional<PEPdbInfo>& pdbOpt) {
    if (!pdbOpt.has_value() || !pdbOpt->hasRsds) {
        os << L"PDB: (none)\n";
        return;
    }

    std::wstring guid = ToWStringUtf8BestEffort(FormatGuidLower(pdbOpt->guid));
    os << L"PDB:\n";
    os << L"  GUID: " << guid << L"\n";
    os << L"  Age: " << pdbOpt->age << L"\n";
    os << L"  Path: " << ToWStringUtf8BestEffort(pdbOpt->pdbPath) << L"\n";
}

static std::wstring VerifyStatusToString(PESignatureVerifyStatus s) {
    switch (s) {
        case PESignatureVerifyStatus::Valid: return L"Valid";
        case PESignatureVerifyStatus::NotSigned: return L"NotSigned";
        case PESignatureVerifyStatus::Invalid: return L"Invalid";
        case PESignatureVerifyStatus::Error: return L"Error";
    }
    return L"Unknown";
}

static void PrintSignerInfo(std::wostream& os, const PESignerInfo& si) {
    if (!si.subject.empty()) {
        os << L"  Subject: " << si.subject << L"\n";
    }
    if (!si.issuer.empty()) {
        os << L"  Issuer: " << si.issuer << L"\n";
    }
    if (!si.sha1Thumbprint.empty()) {
        os << L"  Thumbprint(SHA1): " << si.sha1Thumbprint << L"\n";
    }
    if (!si.notBefore.empty()) {
        os << L"  NotBefore: " << si.notBefore << L"\n";
    }
    if (!si.notAfter.empty()) {
        os << L"  NotAfter: " << si.notAfter << L"\n";
    }
    if (!si.timestamp.empty()) {
        os << L"  Timestamp: " << si.timestamp << L"\n";
    }
}

static void PrintSignatureText(std::wostream& os,
                               const PESignaturePresence& presence,
                               const std::optional<PESignatureVerifyResult>& embedded,
                               const std::optional<PESignatureVerifyResult>& catalog) {
    std::wstring source;
    if (presence.hasEmbedded && presence.hasCatalog) {
        source = L"both";
    } else if (presence.hasEmbedded) {
        source = L"embedded";
    } else if (presence.hasCatalog) {
        source = L"catalog";
    } else {
        source = L"none";
    }

    os << L"Signature:\n";
    os << L"  Presence: " << source << L"\n";

    if (embedded.has_value()) {
        os << L"Embedded:\n";
        os << L"  Status: " << VerifyStatusToString(embedded->status) << L" (0x" << std::hex << embedded->winVerifyTrustStatus << std::dec << L")\n";
        PrintSignerInfo(os, embedded->signer);
    }

    if (catalog.has_value()) {
        os << L"Catalog:\n";
        os << L"  Status: " << VerifyStatusToString(catalog->status) << L" (0x" << std::hex << catalog->winVerifyTrustStatus << std::dec << L")\n";
        if (!catalog->catalogPath.empty()) {
            os << L"  CatalogFile: " << catalog->catalogPath << L"\n";
        }
        PrintSignerInfo(os, catalog->signer);
    }
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char ch : s) {
        switch (ch) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[7] = {};
                    sprintf_s(buf, "\\u%04x", static_cast<unsigned>(ch));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }
    return out;
}

static std::string JsonQuoteUtf8(const std::string& s) {
    return std::string("\"") + JsonEscape(s) + "\"";
}

static std::string JsonQuoteWide(const std::wstring& w) {
    return JsonQuoteUtf8(WStringToUtf8(w));
}

static std::string BuildJsonReport(const CliOptions& opt,
                                   const PEParser& parser,
                                   const std::optional<PEPdbInfo>& pdbOpt,
                                   const PESignaturePresence* sigPresence,
                                   const std::optional<PESignatureVerifyResult>* embedded,
                                   const std::optional<PESignatureVerifyResult>* catalog,
                                   const std::optional<HashResult>* hashResult) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"file\":" << JsonQuoteWide(opt.filePath);

    if (opt.showSummary) {
        const auto& h = parser.GetHeaderInfo();
        oss << ",\"summary\":{";
        oss << "\"bitness\":" << JsonQuoteUtf8(h.is64Bit ? "x64" : (h.is32Bit ? "x86" : "unknown"));
        {
            std::ostringstream t;
            t << "0x" << std::hex << std::setw(4) << std::setfill('0') << h.machine;
            oss << ",\"machine\":" << JsonQuoteUtf8(t.str());
        }
        oss << ",\"sections\":" << h.numberOfSections;
        {
            std::ostringstream raw;
            raw << "0x" << std::hex << std::setw(8) << std::setfill('0') << h.timeDateStamp;
            oss << ",\"timeDateStamp\":{";
            oss << "\"raw\":" << JsonQuoteUtf8(raw.str());
            if (opt.timeFormat != CliTimeFormat::Raw) {
                oss << ",\"human\":" << JsonQuoteWide(FormatCoffTime(h.timeDateStamp, opt.timeFormat));
            }
            oss << "}";
        }
        oss << ",\"sizeOfImage\":" << h.sizeOfImage;
        oss << ",\"entryPointRva\":" << h.entryPoint;
        {
            std::ostringstream base;
            base << "0x" << std::hex << std::setw(16) << std::setfill('0') << h.imageBase;
            oss << ",\"imageBase\":" << JsonQuoteUtf8(base.str());
        }
        oss << ",\"subsystem\":" << JsonQuoteUtf8(h.subsystem);
        oss << "}";
    }

    if (opt.showSections) {
        auto sections = parser.GetSectionsInfo();
        oss << ",\"sections\":[";
        for (size_t i = 0; i < sections.size(); ++i) {
            const auto& s = sections[i];
            if (i) oss << ",";
            oss << "{";
            oss << "\"name\":" << JsonQuoteUtf8(s.name);
            oss << ",\"rva\":" << s.virtualAddress;
            oss << ",\"virtualSize\":" << s.virtualSize;
            oss << ",\"rawOffset\":" << s.rawAddress;
            oss << ",\"rawSize\":" << s.rawSize;
            oss << ",\"characteristics\":" << s.characteristics;
            oss << "}";
        }
        oss << "]";
    }

    if (opt.showImports) {
        auto writeDlls = [&](const char* key, const std::vector<PEImportDLL>& dlls) {
            oss << ",\"" << key << "\":[";
            for (size_t i = 0; i < dlls.size(); ++i) {
                const auto& d = dlls[i];
                if (i) oss << ",";
                oss << "{";
                oss << "\"dll\":" << JsonQuoteUtf8(d.dllName);
                oss << ",\"count\":" << d.functions.size();
                if (opt.importsAll) {
                    oss << ",\"functions\":[";
                    for (size_t j = 0; j < d.functions.size(); ++j) {
                        if (j) oss << ",";
                        oss << JsonQuoteUtf8(d.functions[j].name);
                    }
                    oss << "]";
                }
                oss << "}";
            }
            oss << "]";
        };
        writeDlls("imports", parser.GetImports());
        writeDlls("delayImports", parser.GetDelayImports());
    }

    if (opt.showExports) {
        const auto& exports = parser.GetExports();
        oss << ",\"exports\":[";
        for (size_t i = 0; i < exports.size(); ++i) {
            const auto& e = exports[i];
            if (i) oss << ",";
            oss << "{";
            oss << "\"ordinal\":" << e.ordinal;
            oss << ",\"rva\":" << e.rva;
            oss << ",\"name\":" << JsonQuoteUtf8(e.hasName ? e.name : std::string());
            oss << "}";
        }
        oss << "]";
    }

    if (opt.showPdb) {
        if (pdbOpt.has_value() && pdbOpt->hasRsds) {
            oss << ",\"pdb\":{";
            oss << "\"guid\":" << JsonQuoteUtf8(FormatGuidLower(pdbOpt->guid));
            oss << ",\"age\":" << pdbOpt->age;
            oss << ",\"path\":" << JsonQuoteUtf8(pdbOpt->pdbPath);
            oss << "}";
        } else {
            oss << ",\"pdb\":null";
        }
    }

    if (opt.showSignature && sigPresence != nullptr) {
        oss << ",\"signature\":{";
        std::string presence;
        if (sigPresence->hasEmbedded && sigPresence->hasCatalog) {
            presence = "both";
        } else if (sigPresence->hasEmbedded) {
            presence = "embedded";
        } else if (sigPresence->hasCatalog) {
            presence = "catalog";
        } else {
            presence = "none";
        }
        oss << "\"presence\":" << JsonQuoteUtf8(presence);

        auto writeVerify = [&](const char* key, const std::optional<PESignatureVerifyResult>* vr) {
            if (vr == nullptr || !vr->has_value()) {
                return;
            }
            oss << ",\"" << key << "\":{";
            oss << "\"status\":" << JsonQuoteWide(VerifyStatusToString((*vr)->status));
            {
                std::ostringstream hs;
                hs << "0x" << std::hex << (*vr)->winVerifyTrustStatus;
                oss << ",\"statusCode\":" << JsonQuoteUtf8(hs.str());
            }
            if (!(*vr)->catalogPath.empty()) {
                oss << ",\"catalogFile\":" << JsonQuoteWide((*vr)->catalogPath);
            }
            const PESignerInfo& si = (*vr)->signer;
            if (!si.subject.empty()) oss << ",\"subject\":" << JsonQuoteWide(si.subject);
            if (!si.issuer.empty()) oss << ",\"issuer\":" << JsonQuoteWide(si.issuer);
            if (!si.sha1Thumbprint.empty()) oss << ",\"thumbprintSha1\":" << JsonQuoteWide(si.sha1Thumbprint);
            if (!si.notBefore.empty()) oss << ",\"notBefore\":" << JsonQuoteWide(si.notBefore);
            if (!si.notAfter.empty()) oss << ",\"notAfter\":" << JsonQuoteWide(si.notAfter);
            if (!si.timestamp.empty()) oss << ",\"timestamp\":" << JsonQuoteWide(si.timestamp);
            oss << "}";
        };

        writeVerify("embedded", embedded);
        writeVerify("catalog", catalog);
        oss << "}";
    }

    if (hashResult != nullptr && hashResult->has_value()) {
        oss << ",\"hash\":{";
        oss << "\"algorithm\":" << JsonQuoteWide(hashResult->value().algorithm);
        oss << ",\"value\":" << JsonQuoteWide(hashResult->value().result);
        oss << ",\"ms\":" << hashResult->value().calculationTime;
        oss << "}";
    }

    oss << "}";
    return oss.str();
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    CliParseResult parsed = ParseCliArgs(argc, argv);
    if (!parsed.ok) {
        if (!parsed.error.empty()) {
            std::wcerr << parsed.error << L"\n\n";
        }
        std::wcout << BuildUsageText();
        return parsed.exitCode;
    }
    if (parsed.showHelp) {
        std::wcout << BuildUsageText();
        return parsed.exitCode;
    }

    const CliOptions& opt = parsed.options;
    size_t importMaxPerDll = opt.importsAll ? 0 : 50;

    PEParser parser;
    if (!parser.LoadFile(opt.filePath)) {
        std::wcerr << parser.GetLastError() << L"\n";
        return 1;
    }

    std::optional<PEPdbInfo> pdbOpt;
    if (opt.showPdb) {
        pdbOpt = ExtractPdbInfo(parser);
    }

    std::optional<PESignatureVerifyResult> embeddedVerify;
    std::optional<PESignatureVerifyResult> catalogVerify;
    PESignaturePresence sigPresence = {};
    bool sigPresenceReady = false;

    if (opt.showSignature) {
        sigPresence = DetectSignaturePresence(opt.filePath, parser);
        sigPresenceReady = true;

        bool doEmbedded = (opt.sigSource == CliSigSource::Embedded || opt.sigSource == CliSigSource::Both || opt.sigSource == CliSigSource::Auto);
        bool doCatalog = (opt.sigSource == CliSigSource::Catalog || opt.sigSource == CliSigSource::Both);
        if (opt.sigSource == CliSigSource::Auto) {
            doCatalog = false;
        }

        if (doEmbedded && sigPresence.hasEmbedded) {
            embeddedVerify = VerifyEmbeddedSignature(opt.filePath);
        } else if (doEmbedded && opt.verifySignature) {
            embeddedVerify = PESignatureVerifyResult{PESignatureVerifyStatus::NotSigned, TRUST_E_NOSIGNATURE, {}, {}};
        }

        if (doCatalog && sigPresence.hasCatalog) {
            catalogVerify = VerifyCatalogSignature(opt.filePath);
        } else if (doCatalog && opt.verifySignature) {
            catalogVerify = PESignatureVerifyResult{PESignatureVerifyStatus::NotSigned, TRUST_E_NOSIGNATURE, {}, {}};
        }

        if (opt.sigSource == CliSigSource::Auto && !sigPresence.hasEmbedded && sigPresence.hasCatalog) {
            catalogVerify = VerifyCatalogSignature(opt.filePath);
        }
    }

    std::optional<HashResult> hashResult;
    if (opt.hashAlg.has_value()) {
        HashCalculator calc;
        HashResult r = calc.CalculateFileHash(opt.filePath, *opt.hashAlg);
        if (!r.success) {
            std::wcerr << r.errorMessage << L"\n";
            return 1;
        }
        hashResult = r;
    }

    int exitCode = 0;
    if (opt.verifySignature) {
        bool anyPresent = false;
        bool anyValid = false;
        bool anyInvalid = false;

        auto consider = [&](const std::optional<PESignatureVerifyResult>& vr) {
            if (!vr.has_value()) {
                return;
            }
            if (vr->status == PESignatureVerifyStatus::NotSigned) {
                anyPresent = anyPresent || false;
                return;
            }
            anyPresent = true;
            if (vr->status == PESignatureVerifyStatus::Valid) {
                anyValid = true;
            } else {
                anyInvalid = true;
            }
        };

        if (opt.sigSource == CliSigSource::Embedded) {
            consider(embeddedVerify);
        } else if (opt.sigSource == CliSigSource::Catalog) {
            consider(catalogVerify);
        } else if (opt.sigSource == CliSigSource::Both) {
            consider(embeddedVerify);
            consider(catalogVerify);
        } else {
            if (embeddedVerify.has_value()) {
                consider(embeddedVerify);
            } else {
                consider(catalogVerify);
            }
        }

        if (!sigPresenceReady || (!sigPresence.hasEmbedded && !sigPresence.hasCatalog)) {
            exitCode = 4;
        } else if (anyValid) {
            exitCode = 0;
        } else if (!anyPresent) {
            exitCode = 4;
        } else if (anyInvalid) {
            exitCode = 3;
        } else {
            exitCode = 3;
        }
    }

    if (opt.outputFormat == CliOutputFormat::Json) {
        std::string json = BuildJsonReport(opt, parser, pdbOpt, sigPresenceReady ? &sigPresence : nullptr, &embeddedVerify, &catalogVerify, &hashResult);
        json.push_back('\n');
        if (opt.outPath.has_value()) {
            if (!WriteAllBytes(*opt.outPath, json)) {
                std::wcerr << L"Failed to write output file: " << *opt.outPath << L"\n";
                return 1;
            }
        } else {
            std::cout.write(json.data(), static_cast<std::streamsize>(json.size()));
        }
        return exitCode;
    }

    std::wostringstream out;
    if (!opt.quiet) {
        if (opt.showSummary) {
            PrintHeaderInfo(out, parser.GetHeaderInfo(), opt);
        }
        if (opt.showSections) {
            PrintSectionsSummary(out, parser.GetSectionsInfo());
        }
        if (opt.showImports) {
            PrintImportsSummary(out, L"Imports", parser.GetImports(), importMaxPerDll);
            PrintImportsSummary(out, L"Delay-Imports", parser.GetDelayImports(), importMaxPerDll);
        }
        if (opt.showExports) {
            PrintExportsSummary(out, parser.GetExports(), 500);
        }
        if (opt.showPdb) {
            PrintPdbInfo(out, pdbOpt);
        }
        if (opt.showSignature && sigPresenceReady) {
            PrintSignatureText(out, sigPresence, embeddedVerify, catalogVerify);
        }
        if (hashResult.has_value()) {
            out << hashResult->algorithm << L"  " << hashResult->result << L"  " << std::fixed << std::setprecision(3) << hashResult->calculationTime << L" ms\n";
        }
    } else {
        out << opt.filePath;
        if (opt.showSignature && sigPresenceReady) {
            std::wstring presence;
            if (sigPresence.hasEmbedded && sigPresence.hasCatalog) presence = L"both";
            else if (sigPresence.hasEmbedded) presence = L"embedded";
            else if (sigPresence.hasCatalog) presence = L"catalog";
            else presence = L"none";
            out << L"  sig=" << presence;
        }
        if (opt.verifySignature) {
            out << L"  verify_exit=" << exitCode;
        }
        if (hashResult.has_value()) {
            out << L"  " << hashResult->algorithm << L"=" << hashResult->result;
        }
        out << L"\n";
    }

    std::string utf8 = WStringToUtf8(out.str());
    if (opt.outPath.has_value()) {
        if (!WriteAllBytes(*opt.outPath, utf8)) {
            std::wcerr << L"Failed to write output file: " << *opt.outPath << L"\n";
            return 1;
        }
    } else {
        std::wcout << out.str();
    }

    return exitCode;
}
