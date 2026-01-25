#include "stdafx.h"
#include "ReportTextWriter.h"
#include "ReportUtil.h"

#include <iomanip>
#include <sstream>

namespace {

std::wstring VerifyStatusToString(PESignatureVerifyStatus s) {
    switch (s) {
        case PESignatureVerifyStatus::Valid: return L"Valid";
        case PESignatureVerifyStatus::NotSigned: return L"NotSigned";
        case PESignatureVerifyStatus::Invalid: return L"Invalid";
        case PESignatureVerifyStatus::Error: return L"Error";
    }
    return L"Unknown";
}

static void PrintHeaderInfo(std::wostream& os, const PEHeaderInfo& h, const ReportOptions& opt) {
    os << L"PE Header:\n";
    os << L"  Bitness: " << (h.is64Bit ? L"x64" : (h.is32Bit ? L"x86" : L"Unknown")) << L"\n";
    os << L"  Machine: " << HexU32(h.machine, 4) << L"\n";
    os << L"  Sections: " << h.numberOfSections << L"\n";
    if (opt.timeFormat == ReportTimeFormat::Raw) {
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

} // namespace

std::wstring BuildTextReport(const ReportOptions& opt,
                             const std::wstring& filePath,
                             const PEParser& parser,
                             const std::optional<PEPdbInfo>& pdbOpt,
                             const PESignaturePresence* sigPresence,
                             const std::optional<PESignatureVerifyResult>& embedded,
                             const std::optional<PESignatureVerifyResult>& catalog,
                             const std::optional<HashResult>& hashResult,
                             size_t importMaxPerDll,
                             size_t maxExports) {
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
            PrintExportsSummary(out, parser.GetExports(), maxExports);
        }
        if (opt.showPdb) {
            PrintPdbInfo(out, pdbOpt);
        }
        if (opt.showSignature && sigPresence != nullptr) {
            PrintSignatureText(out, *sigPresence, embedded, catalog);
        }
        if (hashResult.has_value()) {
            out << hashResult->algorithm << L"  " << hashResult->result << L"  " << std::fixed << std::setprecision(3) << hashResult->calculationTime << L" ms\n";
        }
    } else {
        out << filePath;
        if (opt.showSignature && sigPresence != nullptr) {
            std::wstring presence;
            if (sigPresence->hasEmbedded && sigPresence->hasCatalog) presence = L"both";
            else if (sigPresence->hasEmbedded) presence = L"embedded";
            else if (sigPresence->hasCatalog) presence = L"catalog";
            else presence = L"none";
            out << L"  sig=" << presence;
        }
        if (hashResult.has_value()) {
            out << L"  " << hashResult->algorithm << L"=" << hashResult->result;
        }
        out << L"\n";
    }

    return out.str();
}

