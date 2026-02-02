#include "stdafx.h"
#include "ReportTextWriter.h"
#include "PEResource.h"
#include "ReportUtil.h"

#include <iomanip>
#include <algorithm>
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
    const wchar_t* bitness = h.is64Bit ? L"x64" : (h.is32Bit ? L"x86" : L"Unknown");
    os << L"  Architecture: " << bitness << L" (" << CoffMachineToName(h.machine) << L", " << HexU32(h.machine, 4) << L")\n";
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

static void PrintExportDirectory(std::wostream& os, const PEParser& parser, const ReportOptions& opt) {
    const auto& dOpt = parser.GetExportDirectoryInfo();
    if (!dOpt.has_value() || !dOpt->present) {
        os << L"Export Directory: (none)\n";
        return;
    }

    const auto& d = *dOpt;
    os << L"Export Directory:\n";
    os << L"  DirectoryRva: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.directoryRva
       << L"  Size: 0x" << std::setw(8) << d.directorySize << std::dec << std::setfill(L' ') << L"\n";
    os << L"  DirectoryOff: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.directoryFileOffset << std::dec << std::setfill(L' ') << L"\n";
    os << L"  Characteristics: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.characteristics << std::dec << std::setfill(L' ') << L"\n";
    if (opt.timeFormat == ReportTimeFormat::Raw) {
        os << L"  TimeDateStamp: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.timeDateStamp << std::dec << std::setfill(L' ') << L"\n";
    } else {
        os << L"  TimeDateStamp: " << FormatCoffTime(d.timeDateStamp, opt.timeFormat) << L"  (0x"
           << std::hex << std::setw(8) << std::setfill(L'0') << d.timeDateStamp << std::dec << std::setfill(L' ') << L")\n";
    }
    os << L"  MajorVersion: 0x" << std::hex << std::setw(4) << std::setfill(L'0') << d.majorVersion
       << L"  MinorVersion: 0x" << std::setw(4) << d.minorVersion << std::dec << std::setfill(L' ') << L"\n";
    os << L"  NameRva: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.nameRva;
    if (d.nameFileOffset != 0) {
        os << L"  NameOff: 0x" << std::setw(8) << d.nameFileOffset;
    }
    os << std::dec << std::setfill(L' ') << L"\n";
    os << L"  DllName: " << ToWStringUtf8BestEffort(d.dllName) << L"\n";
    os << L"  Base: " << d.base << L"  NumberOfFunctions: " << d.numberOfFunctions << L"  NumberOfNames: " << d.numberOfNames << L"\n";
    os << L"  AddressOfFunctions: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.addressOfFunctionsRva;
    if (d.addressOfFunctionsFileOffset != 0) os << L"  Off: 0x" << std::setw(8) << d.addressOfFunctionsFileOffset;
    os << L"\n";
    os << L"  AddressOfNames:    0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.addressOfNamesRva;
    if (d.addressOfNamesFileOffset != 0) os << L"  Off: 0x" << std::setw(8) << d.addressOfNamesFileOffset;
    os << L"\n";
    os << L"  AddressOfOrdinals: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.addressOfNameOrdinalsRva;
    if (d.addressOfNameOrdinalsFileOffset != 0) os << L"  Off: 0x" << std::setw(8) << d.addressOfNameOrdinalsFileOffset;
    os << std::dec << std::setfill(L' ') << L"\n";
}

static void PrintExportsSummary(std::wostream& os, const std::vector<PEExportFunction>& exports, size_t maxExports) {
    if (exports.empty()) {
        os << L"Exports: (none)\n";
        return;
    }

    os << L"Exports:\n";
    os << L"  Ordinal  RVA       Offset    Name  Forwarder\n";
    size_t shown = 0;
    for (const auto& e : exports) {
        if (shown >= maxExports) {
            os << L"  ...\n";
            break;
        }
        os << L"  " << std::setw(7) << e.ordinal << L"  0x" << std::hex << std::setw(8) << std::setfill(L'0') << e.rva;
        if (e.fileOffset != 0) {
            os << L"  0x" << std::setw(8) << e.fileOffset;
        } else {
            os << L"  " << std::setw(10) << L"";
        }
        os << std::dec << std::setfill(L' ') << L"  " << (e.hasName ? ToWStringUtf8BestEffort(e.name) : L"(no-name)");
        if (e.isForwarded && !e.forwarder.empty()) {
            os << L"  " << ToWStringUtf8BestEffort(e.forwarder);
        }
        os << L"\n";
        ++shown;
    }
}

static std::wstring FormatResourceId(const PEResourceNameOrId& id) {
    if (id.isString) {
        return id.name;
    }
    return std::to_wstring(id.id);
}

static std::wstring FormatResourceType(const PEResourceNameOrId& id) {
    if (id.isString) {
        return id.name;
    }
    if (!id.name.empty()) {
        return id.name;
    }
    return HexU32(id.id, 4);
}

static void PrintResources(std::wostream& os, const PEParser& parser, bool resourcesAll) {
    DWORD rva = 0;
    DWORD size = 0;
    if (!parser.GetResourceDirectory(rva, size)) {
        os << L"Resources: (none)\n";
        return;
    }

    std::vector<PEResourceItem> items;
    std::wstring err;
    if (!EnumerateResources(parser, items, err)) {
        os << L"Resources: (error)\n";
        if (!err.empty()) {
            os << L"  Error: " << err << L"\n";
        }
        return;
    }

    PEResourceSummary s = BuildResourceSummary(items);
    s.present = true;

    os << L"Resources:\n";
    os << L"  Types: " << s.typeCount << L"  Items: " << s.itemCount << L"  TotalBytes: " << s.totalBytes << L"\n";

    if (!s.types.empty()) {
        os << L"  Types:\n";
        for (const auto& t : s.types) {
            std::wstring name;
            if (t.isString) {
                name = t.typeName;
            } else if (t.typeName.empty()) {
                name = HexU32(t.typeId, 4);
            } else {
                name = t.typeName + L"(" + std::to_wstring(t.typeId) + L")";
            }
            os << L"    " << name << L": items=" << t.items << L" bytes=" << t.totalBytes << L"\n";
        }
    }

    auto vi = TryParseVersionInfo(items, parser);
    if (vi.has_value()) {
        os << L"  Version:\n";
        if (!vi->fileVersion.empty()) os << L"    FileVersion: " << vi->fileVersion << L"\n";
        if (!vi->productVersion.empty()) os << L"    ProductVersion: " << vi->productVersion << L"\n";
        static const wchar_t* keys[] = {L"CompanyName",
                                        L"FileDescription",
                                        L"FileVersion",
                                        L"InternalName",
                                        L"OriginalFilename",
                                        L"ProductName",
                                        L"ProductVersion",
                                        L"LegalCopyright"};
        for (const auto* k : keys) {
            auto it = vi->strings.find(k);
            if (it != vi->strings.end() && !it->second.empty()) {
                os << L"    " << k << L": " << it->second << L"\n";
            }
        }
    }

    auto mi = TryParseManifest(items, parser, resourcesAll);
    if (mi.has_value() && mi->present) {
        os << L"  Manifest:\n";
        os << L"    Encoding: " << (mi->encoding.empty() ? L"unknown" : mi->encoding) << L"  Size: " << mi->size << L"\n";
        if (!mi->requestedExecutionLevel.empty()) {
            os << L"    requestedExecutionLevel: " << mi->requestedExecutionLevel << L"\n";
        }
        if (mi->uiAccess.has_value()) {
            os << L"    uiAccess: " << (*mi->uiAccess ? L"true" : L"false") << L"\n";
        }
        if (resourcesAll && !mi->text.empty()) {
            std::wistringstream iss(mi->text);
            os << L"    ManifestText:\n";
            std::wstring line;
            size_t shown = 0;
            while (std::getline(iss, line)) {
                os << L"      " << line << L"\n";
                if (++shown >= 20) {
                    if (!iss.eof()) {
                        os << L"      ...\n";
                    }
                    break;
                }
            }
        }
    }

    auto groups = TryParseIconGroups(items, parser);
    if (!groups.empty()) {
        os << L"  Icons:\n";
        os << L"    Groups: " << groups.size() << L"\n";
        for (const auto& g : groups) {
            os << L"    Group " << FormatResourceId(g.name) << L" (lang " << HexU32(g.language, 4) << L"): images=" << g.images.size() << L"\n";
            for (const auto& img : g.images) {
                os << L"      " << img.width << L"x" << img.height << L" @" << img.bitCount << L"bpp  bytes=" << img.bytesInRes << L"  iconId=" << img.iconId << L"\n";
            }
        }
    }

    if (resourcesAll && !items.empty()) {
        std::sort(items.begin(), items.end(), [](const PEResourceItem& a, const PEResourceItem& b) {
            WORD at = a.type.isString ? 0 : a.type.id;
            WORD bt = b.type.isString ? 0 : b.type.id;
            if (at != bt) return at < bt;
            if (a.name.isString != b.name.isString) return a.name.isString < b.name.isString;
            if (!a.name.isString && a.name.id != b.name.id) return a.name.id < b.name.id;
            if (a.language != b.language) return a.language < b.language;
            return a.size < b.size;
        });

        os << L"  Items:\n";
        os << L"    Type           Name        Lang      Size     DataRVA   RawOff\n";
        size_t shown = 0;
        for (const auto& it : items) {
            if (shown >= 500) {
                os << L"    ...\n";
                break;
            }
            std::wstring type = FormatResourceType(it.type);
            if (type.size() > 13) type.resize(13);
            std::wstring name = FormatResourceId(it.name);
            if (name.size() > 10) name.resize(10);
            os << L"    " << std::left << std::setw(13) << std::setfill(L' ') << type << std::right
               << L" " << std::left << std::setw(10) << name << std::right
               << L" " << HexU32(it.language, 4)
               << L"  " << std::setw(7) << it.size
               << L"  " << HexU32(it.dataRva, 8)
               << L"  " << HexU32(it.rawOffset, 8)
               << L"\n";
            ++shown;
        }
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
            PrintExportDirectory(out, parser, opt);
            PrintExportsSummary(out, parser.GetExports(), maxExports);
        }
        if (opt.showResources) {
            PrintResources(out, parser, opt.resourcesAll);
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

