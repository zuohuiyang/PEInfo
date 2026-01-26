#include "stdafx.h"

#include "PECore.h"
#include "PEResource.h"
#include "ReportJsonWriter.h"
#include "ReportTextWriter.h"
#include "ReportUtil.h"
#include "ShellContextMenu.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <process.h>

#include <algorithm>
#include <cwctype>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

static const wchar_t* kMainClassName = L"PEInfoGuiMainWindow";

static const UINT WM_APP_ANALYSIS_DONE = WM_APP + 1;
static const UINT WM_APP_VERIFY_DONE = WM_APP + 2;
static const UINT WM_APP_HASH_PROGRESS = WM_APP + 3;
static const UINT_PTR kTimerImportsFilter = 1;
static const WPARAM IDM_SYS_SETTINGS = 0x1FF0;
static const WPARAM IDM_SYS_CANCEL = 0x1FF2;

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
DECLARE_HANDLE(DPI_AWARENESS_CONTEXT);
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif

enum : UINT {
    IDC_BTN_OPEN_SMALL = 1001,
    IDC_BTN_SETTINGS_GEAR = 1002,
    IDC_BTN_OPEN_BIG = 1003,
    IDC_TAB = 1010,
    IDC_FILEINFO = 1020,
    IDC_SUMMARY = 2001,
    IDC_SECTIONS = 2002,
    IDC_IMPORTS = 2003,
    IDC_EXPORTS = 2004,
    IDC_RESOURCES = 2009,
    IDC_PDB = 2005,
    IDC_SIGNATURE = 2006,
    IDC_HASH = 2007,
    IDC_IMPORTS_DLLS = 2008,
    IDC_IMPORTS_FILTER = 2101
};

enum class TabIndex : int {
    Summary = 0,
    Sections = 1,
    Imports = 2,
    Exports = 3,
    Resources = 4,
    DebugPdb = 5,
    Signature = 6,
    Hash = 7
};

struct VerifyResultMessage {
    std::wstring filePath;
    std::optional<PESignatureVerifyResult> embedded;
    std::optional<PESignatureVerifyResult> catalog;
    bool ok = true;
    std::wstring error;
};

struct AnalysisResultMessage {
    std::unique_ptr<PEAnalysisResult> result;
    bool ok = true;
    std::wstring error;
};

struct GuiState {
    HWND hwnd = nullptr;
    HWND btnOpenSmall = nullptr;
    HWND btnSettingsGear = nullptr;
    HWND btnOpenBig = nullptr;
    HWND fileInfo = nullptr;
    HWND tab = nullptr;

    HWND pageSummary = nullptr;
    HWND pageSections = nullptr;
    HWND pageImportsDlls = nullptr;
    HWND pageImports = nullptr;
    HWND pageExports = nullptr;
    HWND pageResources = nullptr;
    HWND pagePdb = nullptr;
    HWND pageSignature = nullptr;
    HWND pageHash = nullptr;
    HWND importsFilterLabel = nullptr;
    HWND importsFilterEdit = nullptr;

    bool busy = false;
    bool verifyInFlight = false;
    bool importsSyncingSelection = false;
    std::wstring currentFile;
    std::wstring pendingFile;
    std::wstring verifyInFlightFile;
    std::unique_ptr<PEAnalysisResult> analysis;

    HFONT uiFont = nullptr;
    HFONT iconFont = nullptr;
    UINT dpi = 96;

    HICON iconOpen = nullptr;

    struct ImportRow {
        std::wstring type;
        std::wstring dll;
        std::wstring function;
        std::wstring haystackLower;
    };
    std::vector<ImportRow> importsAllRows;
    std::wstring importsSelectedDll;
    std::atomic<bool>* analysisCancel = nullptr;
    int hashProgressPercent = -1;
};

static UINT GetBestWindowDpi(HWND hwnd);
static HFONT CreateUiFontForDpi(UINT dpi);
static void FitImportsDllColumns(GuiState* s);
static void FitImportsFuncColumns(GuiState* s);

static void CenterWindowOnWorkArea(HWND hwnd) {
    if (!hwnd) {
        return;
    }

    RECT wndRc = {};
    if (!GetWindowRect(hwnd, &wndRc)) {
        return;
    }
    LONG w = wndRc.right - wndRc.left;
    LONG h = wndRc.bottom - wndRc.top;
    if (w <= 0 || h <= 0) {
        return;
    }

    POINT pt = {};
    GetCursorPos(&pt);
    HMONITOR mon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = {};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) {
        return;
    }

    LONG x = mi.rcWork.left + ((mi.rcWork.right - mi.rcWork.left) - w) / 2;
    LONG y = mi.rcWork.top + ((mi.rcWork.bottom - mi.rcWork.top) - h) / 2;

    LONG minX = mi.rcWork.left;
    LONG maxX = mi.rcWork.right - w;
    if (maxX < minX) {
        maxX = minX;
    }
    if (x < minX) {
        x = minX;
    }
    if (x > maxX) {
        x = maxX;
    }

    LONG minY = mi.rcWork.top;
    LONG maxY = mi.rcWork.bottom - h;
    if (maxY < minY) {
        maxY = minY;
    }
    if (y < minY) {
        y = minY;
    }
    if (y > maxY) {
        y = maxY;
    }

    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
}

static void SetWindowTextWString(HWND hwnd, const std::wstring& s) {
    SetWindowTextW(hwnd, s.c_str());
}

static void MessageBoxError(HWND hwnd, const std::wstring& msg, const std::wstring& title = L"\u9519\u8bef") {
    MessageBoxW(hwnd, msg.c_str(), title.c_str(), MB_ICONERROR | MB_OK);
}

static std::wstring GetControlText(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    if (len <= 0) {
        return {};
    }
    std::wstring s(static_cast<size_t>(len + 1), L'\0');
    GetWindowTextW(hwnd, s.data(), len + 1);
    s.resize(wcslen(s.c_str()));
    return s;
}

static std::wstring ToLowerString(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return out;
}

static std::vector<std::wstring> TokenizeQueryLower(const std::wstring& qLower) {
    std::vector<std::wstring> tokens;
    size_t i = 0;
    while (i < qLower.size()) {
        while (i < qLower.size() && iswspace(qLower[i])) {
            ++i;
        }
        size_t start = i;
        while (i < qLower.size() && !iswspace(qLower[i])) {
            ++i;
        }
        if (i > start) {
            tokens.push_back(qLower.substr(start, i - start));
        }
    }
    return tokens;
}

static std::wstring SigPresenceToText(const PESignaturePresence& p) {
    if (p.hasEmbedded && p.hasCatalog) return L"both";
    if (p.hasEmbedded) return L"embedded";
    if (p.hasCatalog) return L"catalog";
    return L"none";
}

static std::wstring FormatSummaryText(const PEAnalysisResult& ar) {
    const auto& h = ar.parser.GetHeaderInfo();
    std::wostringstream out;
    out << L"\u6587\u4ef6: " << ar.filePath << L"\r\n";
    out << L"Bitness: " << (h.is64Bit ? L"x64" : (h.is32Bit ? L"x86" : L"Unknown")) << L"\r\n";
    out << L"Machine: " << HexU32(h.machine, 4) << L"\r\n";
    out << L"Sections: " << h.numberOfSections << L"\r\n";
    out << L"TimeDateStamp: " << HexU32(h.timeDateStamp, 8) << L" (" << FormatCoffTime(h.timeDateStamp, ReportTimeFormat::Local) << L")\r\n";
    out << L"SizeOfImage: " << HexU32(h.sizeOfImage, 8) << L"\r\n";
    out << L"EntryPointRVA: " << HexU32(h.entryPoint, 8) << L"\r\n";
    out << L"ImageBase: " << HexU64(h.imageBase, 16) << L"\r\n";
    out << L"Subsystem: " << ToWStringUtf8BestEffort(h.subsystem) << L"\r\n";

    if (ar.signaturePresenceReady) {
        out << L"Signature: " << SigPresenceToText(ar.signaturePresence) << L"\r\n";
    }
    if (ar.pdb.has_value() && ar.pdb->hasRsds) {
        out << L"PDB: " << ToWStringUtf8BestEffort(ar.pdb->pdbPath) << L"\r\n";
    } else {
        out << L"PDB: (none)\r\n";
    }

    return out.str();
}

static void AddListViewColumn(HWND list, int col, int width, const wchar_t* title) {
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = const_cast<wchar_t*>(title);
    c.cx = width;
    c.iSubItem = col;
    ListView_InsertColumn(list, col, &c);
}

static void SetListViewText(HWND list, int row, int col, const std::wstring& text) {
    if (col == 0) {
        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<wchar_t*>(text.c_str());
        ListView_InsertItem(list, &item);
        return;
    }
    ListView_SetItemText(list, row, col, const_cast<wchar_t*>(text.c_str()));
}

static void PopulateSections(HWND list, const PEParser& parser) {
    ListView_DeleteAllItems(list);
    const auto sections = parser.GetSectionsInfo();
    for (int i = 0; i < static_cast<int>(sections.size()); ++i) {
        const auto& s = sections[static_cast<size_t>(i)];
        SetListViewText(list, i, 0, ToWStringUtf8BestEffort(s.name));
        SetListViewText(list, i, 1, HexU32(s.virtualAddress, 8));
        SetListViewText(list, i, 2, HexU32(s.virtualSize, 8));
        SetListViewText(list, i, 3, HexU32(s.rawAddress, 8));
        SetListViewText(list, i, 4, HexU32(s.rawSize, 8));
        SetListViewText(list, i, 5, HexU32(s.characteristics, 8));
    }
}

static void PopulateExports(HWND list, const PEParser& parser) {
    ListView_DeleteAllItems(list);
    const auto& exports = parser.GetExports();
    for (int i = 0; i < static_cast<int>(exports.size()); ++i) {
        const auto& e = exports[static_cast<size_t>(i)];
        SetListViewText(list, i, 0, std::to_wstring(e.ordinal));
        SetListViewText(list, i, 1, HexU32(e.rva, 8));
        SetListViewText(list, i, 2, e.hasName ? ToWStringUtf8BestEffort(e.name) : L"(no-name)");
    }
}

static void PopulateImportDlls(HWND list, const std::vector<std::pair<std::wstring, int>>& rows) {
    ListView_DeleteAllItems(list);

    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
        const auto& r = rows[static_cast<size_t>(i)];
        SetListViewText(list, i, 0, r.first);
        SetListViewText(list, i, 1, std::to_wstring(r.second));
    }
}

static void PopulateImportFunctions(HWND list, const std::vector<const GuiState::ImportRow*>& rows) {
    ListView_DeleteAllItems(list);

    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
        const auto& r = *rows[static_cast<size_t>(i)];
        SetListViewText(list, i, 0, r.type);
        SetListViewText(list, i, 1, r.function);
    }
}

static void BuildImportRowsFromParser(std::vector<GuiState::ImportRow>& out, const PEParser& parser) {
    out.clear();

    auto addDlls = [&](const std::vector<PEImportDLL>& dlls, const wchar_t* type) {
        for (const auto& d : dlls) {
            std::wstring dllName = ToWStringUtf8BestEffort(d.dllName);
            for (const auto& fn : d.functions) {
                GuiState::ImportRow r;
                r.type = type;
                r.dll = dllName;
                r.function = ToWStringUtf8BestEffort(fn.name);
                r.haystackLower = ToLowerString(r.type + L" " + r.dll + L" " + r.function);
                out.push_back(std::move(r));
            }
        }
    };

    addDlls(parser.GetImports(), L"Import");
    addDlls(parser.GetDelayImports(), L"Delay");
}

static void ApplyImportsFilterNow(GuiState* s) {
    if (!s->importsFilterEdit) {
        return;
    }

    std::wstring q = GetControlText(s->importsFilterEdit);
    std::wstring qLower = ToLowerString(q);
    std::vector<std::wstring> tokens = TokenizeQueryLower(qLower);
    std::vector<const GuiState::ImportRow*> matched;
    matched.reserve(s->importsAllRows.size());
    for (const auto& r : s->importsAllRows) {
        bool ok = true;
        for (const auto& t : tokens) {
            if (r.haystackLower.find(t) == std::wstring::npos) {
                ok = false;
                break;
            }
        }
        if (ok) {
            matched.push_back(&r);
        }
    }

    std::map<std::wstring, int> dllCounts;
    for (const auto* r : matched) {
        ++dllCounts[r->dll];
    }

    std::vector<std::pair<std::wstring, int>> dllRows;
    dllRows.reserve(dllCounts.size());
    for (const auto& it : dllCounts) {
        dllRows.push_back({it.first, it.second});
    }
    PopulateImportDlls(s->pageImportsDlls, dllRows);

    if (dllRows.empty()) {
        s->importsSelectedDll.clear();
        PopulateImportFunctions(s->pageImports, {});
        return;
    }

    if (dllCounts.find(s->importsSelectedDll) == dllCounts.end()) {
        s->importsSelectedDll = dllRows[0].first;
    }

    int selectIndex = 0;
    for (int i = 0; i < static_cast<int>(dllRows.size()); ++i) {
        if (dllRows[static_cast<size_t>(i)].first == s->importsSelectedDll) {
            selectIndex = i;
            break;
        }
    }

    s->importsSyncingSelection = true;
    ListView_SetItemState(s->pageImportsDlls, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(s->pageImportsDlls, selectIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(s->pageImportsDlls, selectIndex, FALSE);
    s->importsSyncingSelection = false;

    std::vector<const GuiState::ImportRow*> funcs;
    funcs.reserve(static_cast<size_t>(dllRows[static_cast<size_t>(selectIndex)].second));
    for (const auto* r : matched) {
        if (r->dll == s->importsSelectedDll) {
            funcs.push_back(r);
        }
    }
    std::sort(funcs.begin(), funcs.end(), [](const GuiState::ImportRow* a, const GuiState::ImportRow* b) {
        if (a->type != b->type) return a->type < b->type;
        return a->function < b->function;
    });
    PopulateImportFunctions(s->pageImports, funcs);
}

static void UpdateImportFunctionsForSelection(GuiState* s) {
    if (!s->importsFilterEdit) {
        return;
    }
    if (s->importsSelectedDll.empty()) {
        PopulateImportFunctions(s->pageImports, {});
        return;
    }

    std::wstring q = GetControlText(s->importsFilterEdit);
    std::wstring qLower = ToLowerString(q);
    std::vector<std::wstring> tokens = TokenizeQueryLower(qLower);

    std::vector<const GuiState::ImportRow*> funcs;
    funcs.reserve(s->importsAllRows.size());
    for (const auto& r : s->importsAllRows) {
        if (r.dll != s->importsSelectedDll) {
            continue;
        }
        bool ok = true;
        for (const auto& t : tokens) {
            if (r.haystackLower.find(t) == std::wstring::npos) {
                ok = false;
                break;
            }
        }
        if (ok) {
            funcs.push_back(&r);
        }
    }

    std::sort(funcs.begin(), funcs.end(), [](const GuiState::ImportRow* a, const GuiState::ImportRow* b) {
        if (a->type != b->type) return a->type < b->type;
        return a->function < b->function;
    });
    PopulateImportFunctions(s->pageImports, funcs);
}

static void PopulatePdb(HWND edit, const std::optional<PEPdbInfo>& pdb) {
    std::wostringstream out;
    if (pdb.has_value() && pdb->hasRsds) {
        out << L"GUID: " << ToWStringUtf8BestEffort(FormatGuidLower(pdb->guid)) << L"\r\n";
        out << L"Age: " << pdb->age << L"\r\n";
        out << L"Path: " << ToWStringUtf8BestEffort(pdb->pdbPath) << L"\r\n";
    } else {
        out << L"(none)\r\n";
    }
    SetWindowTextWString(edit, out.str());
}

static std::wstring FormatResourceIdOrName(const PEResourceNameOrId& v) {
    if (v.isString) {
        return v.name;
    }
    return std::to_wstring(v.id);
}

static std::wstring FormatResourceTypeLabel(bool isString, WORD typeId, const std::wstring& typeName) {
    if (isString) {
        return typeName;
    }
    if (!typeName.empty()) {
        return typeName + L"(" + std::to_wstring(typeId) + L")";
    }
    return HexU32(typeId, 4);
}

static void PopulateResources(HWND edit, const PEParser& parser) {
    DWORD rva = 0;
    DWORD size = 0;
    if (!parser.GetResourceDirectory(rva, size)) {
        SetWindowTextWString(edit, L"(none)\r\n");
        return;
    }

    std::vector<PEResourceItem> items;
    std::wstring err;
    if (!EnumerateResources(parser, items, err)) {
        std::wostringstream out;
        out << L"(error)\r\n";
        if (!err.empty()) {
            out << L"Error: " << err << L"\r\n";
        }
        SetWindowTextWString(edit, out.str());
        return;
    }

    PEResourceSummary s = BuildResourceSummary(items);
    std::wostringstream out;
    out << L"Types: " << s.typeCount << L"  Items: " << s.itemCount << L"  TotalBytes: " << s.totalBytes << L"\r\n";

    if (!s.types.empty()) {
        out << L"\r\nTypes:\r\n";
        for (const auto& t : s.types) {
            out << L"  " << FormatResourceTypeLabel(t.isString, t.typeId, t.typeName) << L": items=" << t.items << L" bytes=" << t.totalBytes << L"\r\n";
        }
    }

    auto vi = TryParseVersionInfo(items, parser);
    if (vi.has_value()) {
        out << L"\r\nVersion:\r\n";
        if (!vi->fileVersion.empty()) out << L"  FileVersion: " << vi->fileVersion << L"\r\n";
        if (!vi->productVersion.empty()) out << L"  ProductVersion: " << vi->productVersion << L"\r\n";
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
                out << L"  " << k << L": " << it->second << L"\r\n";
            }
        }
    }

    auto mi = TryParseManifest(items, parser, false);
    if (mi.has_value() && mi->present) {
        out << L"\r\nManifest:\r\n";
        out << L"  Encoding: " << (mi->encoding.empty() ? L"unknown" : mi->encoding) << L"  Size: " << mi->size << L"\r\n";
        if (!mi->requestedExecutionLevel.empty()) {
            out << L"  requestedExecutionLevel: " << mi->requestedExecutionLevel << L"\r\n";
        }
        if (mi->uiAccess.has_value()) {
            out << L"  uiAccess: " << (*mi->uiAccess ? L"true" : L"false") << L"\r\n";
        }
    }

    auto groups = TryParseIconGroups(items, parser);
    if (!groups.empty()) {
        out << L"\r\nIcons:\r\n";
        out << L"  Groups: " << groups.size() << L"\r\n";
        for (const auto& g : groups) {
            out << L"  Group " << FormatResourceIdOrName(g.name) << L" (lang " << HexU32(g.language, 4) << L") images=" << g.images.size() << L"\r\n";
            for (const auto& img : g.images) {
                out << L"    " << img.width << L"x" << img.height << L" @" << img.bitCount << L"bpp bytes=" << img.bytesInRes << L" iconId=" << img.iconId << L"\r\n";
            }
        }
    }

    if (!items.empty()) {
        out << L"\r\nItems:\r\n";
        out << L"  Type | Name | Lang | Size | DataRVA | RawOff\r\n";
        size_t shown = 0;
        for (const auto& it : items) {
            if (shown >= 500) {
                out << L"  ...\r\n";
                break;
            }
            std::wstring type = it.type.isString ? it.type.name : (!it.type.name.empty() ? it.type.name : HexU32(it.type.id, 4));
            std::wstring name = FormatResourceIdOrName(it.name);
            out << L"  " << type << L" | " << name << L" | " << HexU32(it.language, 4) << L" | " << it.size << L" | " << HexU32(it.dataRva, 8) << L" | " << HexU32(it.rawOffset, 8) << L"\r\n";
            ++shown;
        }
    }

    SetWindowTextWString(edit, out.str());
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

static void AppendSigner(std::wostringstream& out, const PESignerInfo& si) {
    if (!si.subject.empty()) out << L"Subject: " << si.subject << L"\r\n";
    if (!si.issuer.empty()) out << L"Issuer: " << si.issuer << L"\r\n";
    if (!si.sha1Thumbprint.empty()) out << L"Thumbprint(SHA1): " << si.sha1Thumbprint << L"\r\n";
    if (!si.notBefore.empty()) out << L"NotBefore: " << si.notBefore << L"\r\n";
    if (!si.notAfter.empty()) out << L"NotAfter: " << si.notAfter << L"\r\n";
    if (!si.timestamp.empty()) out << L"Timestamp: " << si.timestamp << L"\r\n";
}

static void PopulateSignature(HWND edit, const PEAnalysisResult& ar, bool verifying) {
    std::wostringstream out;
    if (ar.signaturePresenceReady) {
        out << L"Presence: " << SigPresenceToText(ar.signaturePresence) << L"\r\n";
    } else {
        out << L"Presence: (unknown)\r\n";
    }

    if (ar.embeddedVerify.has_value()) {
        out << L"\r\nEmbedded:\r\n";
        out << L"Status: " << VerifyStatusToString(ar.embeddedVerify->status) << L" (0x" << std::hex << ar.embeddedVerify->winVerifyTrustStatus << std::dec << L")\r\n";
        AppendSigner(out, ar.embeddedVerify->signer);
    }
    if (ar.catalogVerify.has_value()) {
        out << L"\r\nCatalog:\r\n";
        out << L"Status: " << VerifyStatusToString(ar.catalogVerify->status) << L" (0x" << std::hex << ar.catalogVerify->winVerifyTrustStatus << std::dec << L")\r\n";
        if (!ar.catalogVerify->catalogPath.empty()) {
            out << L"CatalogFile: " << ar.catalogVerify->catalogPath << L"\r\n";
        }
        AppendSigner(out, ar.catalogVerify->signer);
    }
    if (!ar.embeddedVerify.has_value() && !ar.catalogVerify.has_value()) {
        out << L"\r\n\u9a8c\u8bc1\uff1a" << (verifying ? L"\u8fdb\u884c\u4e2d..." : L"\u672a\u6267\u884c") << L"\r\n";
    }
    SetWindowTextWString(edit, out.str());
}

static bool IsVerifyInFlightForCurrent(const GuiState* s) {
    return s->verifyInFlight && !s->verifyInFlightFile.empty() && s->verifyInFlightFile == s->currentFile;
}

static void PopulateHash(HWND edit, const std::vector<HashResult>& hashes) {
    std::wostringstream out;
    if (hashes.empty()) {
        out << L"(none)\r\n";
        SetWindowTextWString(edit, out.str());
        return;
    }
    for (const auto& h : hashes) {
        if (!h.success) {
            out << h.algorithm << L": (error) " << h.errorMessage << L"\r\n";
            continue;
        }
        out << h.algorithm << L": " << h.result << L"\r\n";
    }
    SetWindowTextWString(edit, out.str());
}

static void SetBusy(GuiState* s, bool busy) {
    s->busy = busy;
    EnableWindow(s->btnOpenSmall, !busy);
    EnableWindow(s->btnOpenBig, !busy);
    EnableWindow(s->btnSettingsGear, !busy);
}

static std::wstring GetSelfExePath() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return buf;
}

enum : UINT {
    IDC_SETTINGS_CONTEXT_MENU = 5001,
    IDC_SETTINGS_INFO = 5002
};

struct SettingsDialogState {
    HWND hwnd = nullptr;
    HWND chkContextMenu = nullptr;
    HWND info = nullptr;
    HWND btnOk = nullptr;
    HWND btnCancel = nullptr;
    bool installedBefore = false;
    HFONT uiFont = nullptr;
    UINT dpi = 96;
};

static LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    SettingsDialogState* s = reinterpret_cast<SettingsDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    if (!s) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_CREATE: {
            s->hwnd = hwnd;
            s->dpi = GetBestWindowDpi(hwnd);
            s->uiFont = CreateUiFontForDpi(s->dpi);

            int padX = MulDiv(12, static_cast<int>(s->dpi), 96);
            int padY = MulDiv(16, static_cast<int>(s->dpi), 96);
            int rowGap = MulDiv(10, static_cast<int>(s->dpi), 96);
            int chkH = MulDiv(24, static_cast<int>(s->dpi), 96);
            int infoH = MulDiv(24, static_cast<int>(s->dpi), 96);
            int btnW = MulDiv(92, static_cast<int>(s->dpi), 96);
            int btnH = MulDiv(32, static_cast<int>(s->dpi), 96);

            s->chkContextMenu = CreateWindowW(L"BUTTON",
                                              L"\u5728\u8d44\u6e90\u7ba1\u7406\u5668\u53f3\u952e\u83dc\u5355\u4e2d\u6dfb\u52a0\u201c\u7528 PEInfo \u6253\u5f00\u201d",
                                              WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                              padX, padY, MulDiv(520, static_cast<int>(s->dpi), 96), chkH,
                                              hwnd,
                                              reinterpret_cast<HMENU>(IDC_SETTINGS_CONTEXT_MENU),
                                              nullptr,
                                              nullptr);
            s->info = CreateWindowW(L"STATIC",
                                    L"Windows 11 \u4e0b\u53ef\u80fd\u5728\u201c\u663e\u793a\u66f4\u591a\u9009\u9879\u201d\u91cc\u51fa\u73b0",
                                    WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    padX, padY + chkH + rowGap, MulDiv(520, static_cast<int>(s->dpi), 96), infoH,
                                    hwnd,
                                    reinterpret_cast<HMENU>(IDC_SETTINGS_INFO),
                                    nullptr,
                                    nullptr);

            int btnY = padY + chkH + rowGap + infoH + MulDiv(16, static_cast<int>(s->dpi), 96);
            int btnRight = MulDiv(536, static_cast<int>(s->dpi), 96);
            s->btnCancel = CreateWindowW(L"BUTTON", L"\u53d6\u6d88", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         btnRight - btnW, btnY, btnW, btnH, hwnd, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);
            s->btnOk = CreateWindowW(L"BUTTON", L"\u786e\u5b9a", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                     btnRight - (2 * btnW) - MulDiv(10, static_cast<int>(s->dpi), 96), btnY, btnW, btnH, hwnd, reinterpret_cast<HMENU>(IDOK), nullptr, nullptr);

            if (s->installedBefore) {
                SendMessageW(s->chkContextMenu, BM_SETCHECK, BST_CHECKED, 0);
            }

            HWND controls[] = {s->chkContextMenu, s->info, s->btnOk, s->btnCancel};
            for (HWND c : controls) {
                SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(s->uiFont), TRUE);
            }
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDOK: {
                    bool enable = (SendMessageW(s->chkContextMenu, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    std::wstring err;
                    if (enable && !s->installedBefore) {
                        std::wstring guiPath = GetSelfExePath();
                        if (guiPath.empty()) {
                            MessageBoxError(hwnd, L"\u83b7\u53d6\u7a0b\u5e8f\u8def\u5f84\u5931\u8d25");
                            return 0;
                        }
                        if (!InstallPeInfoShellContextMenuForCurrentUser(guiPath, err)) {
                            MessageBoxError(hwnd, err.empty() ? L"\u5b89\u88c5\u53f3\u952e\u83dc\u5355\u5931\u8d25" : err);
                            return 0;
                        }
                        MessageBoxW(hwnd, L"\u5df2\u5b89\u88c5\u53f3\u952e\u83dc\u5355", L"\u8bbe\u7f6e", MB_OK | MB_ICONINFORMATION);
                    }
                    if (!enable && s->installedBefore) {
                        if (!UninstallPeInfoShellContextMenuForCurrentUser(err)) {
                            MessageBoxError(hwnd, err.empty() ? L"\u5378\u8f7d\u53f3\u952e\u83dc\u5355\u5931\u8d25" : err);
                            return 0;
                        }
                        MessageBoxW(hwnd, L"\u5df2\u5378\u8f7d\u53f3\u952e\u83dc\u5355", L"\u8bbe\u7f6e", MB_OK | MB_ICONINFORMATION);
                    }
                    DestroyWindow(hwnd);
                    return 0;
                }
                case IDCANCEL: {
                    DestroyWindow(hwnd);
                    return 0;
                }
            }
            break;
        }
        case WM_CLOSE: {
            DestroyWindow(hwnd);
            return 0;
        }
        case WM_DESTROY: {
            if (s->uiFont) {
                DeleteObject(s->uiFont);
                s->uiFont = nullptr;
            }
            break;
        }
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ShowSettingsDialog(HWND owner) {
    static const wchar_t* kSettingsClassName = L"PEInfoGuiSettingsWindow";
    static bool classRegistered = false;
    if (!classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = SettingsWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = kSettingsClassName;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        RegisterClassExW(&wc);
        classRegistered = true;
    }

    SettingsDialogState state;
    state.installedBefore = IsPeInfoShellContextMenuInstalled();

    RECT ownerRc = {};
    GetWindowRect(owner, &ownerRc);
    UINT dpi = GetBestWindowDpi(owner);
    int w = MulDiv(560, static_cast<int>(dpi), 96);
    int h = MulDiv(170, static_cast<int>(dpi), 96);
    int x = ownerRc.left + ((ownerRc.right - ownerRc.left) - w) / 2;
    int y = ownerRc.top + ((ownerRc.bottom - ownerRc.top) - h) / 2;

    EnableWindow(owner, FALSE);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME,
                               kSettingsClassName,
                               L"\u8bbe\u7f6e",
                               WS_CAPTION | WS_SYSMENU,
                               x, y, w, h,
                               owner,
                               nullptr,
                               GetModuleHandleW(nullptr),
                               &state);
    if (!dlg) {
        EnableWindow(owner, TRUE);
        return;
    }
    state.hwnd = dlg;
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);

    MSG msg = {};
    while (IsWindow(dlg) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(dlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

static RECT GetTabPageRect(HWND hwndMain, HWND hwndTab) {
    RECT rcTab = {};
    GetClientRect(hwndTab, &rcTab);
    TabCtrl_AdjustRect(hwndTab, FALSE, &rcTab);
    POINT tl = {rcTab.left, rcTab.top};
    POINT br = {rcTab.right, rcTab.bottom};
    ClientToScreen(hwndTab, &tl);
    ClientToScreen(hwndTab, &br);
    ScreenToClient(hwndMain, &tl);
    ScreenToClient(hwndMain, &br);
    RECT rc = {tl.x, tl.y, br.x, br.y};
    return rc;
}

static void ShowOnlyTab(GuiState* s, TabIndex idx) {
    HWND pages[] = {s->pageSummary, s->pageSections, s->pageImports, s->pageExports, s->pageResources, s->pagePdb, s->pageSignature, s->pageHash};
    for (int i = 0; i < static_cast<int>(std::size(pages)); ++i) {
        ShowWindow(pages[i], (i == static_cast<int>(idx)) ? SW_SHOW : SW_HIDE);
    }
    bool showImportsFilter = (idx == TabIndex::Imports);
    ShowWindow(s->pageImportsDlls, showImportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->importsFilterLabel, showImportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->importsFilterEdit, showImportsFilter ? SW_SHOW : SW_HIDE);
    if (showImportsFilter) {
        FitImportsDllColumns(s);
        FitImportsFuncColumns(s);
        InvalidateRect(s->pageImportsDlls, nullptr, TRUE);
        InvalidateRect(s->pageImports, nullptr, TRUE);
    }
}

static void UpdateFileInfo(GuiState* s) {
    if (s->analysis == nullptr) {
        if (!s->currentFile.empty()) {
            SetWindowTextWString(s->fileInfo, s->currentFile);
        } else {
            SetWindowTextWString(s->fileInfo, L"\u672a\u6253\u5f00\u6587\u4ef6");
        }
        return;
    }

    SetWindowTextWString(s->fileInfo, s->analysis->filePath);
}

static void RefreshAllViews(GuiState* s) {
    if (s->analysis == nullptr) {
        std::wstring hint = L"\u62d6\u62fd EXE/DLL/SYS \u5230\u7a97\u53e3\uff0c\u6216\u70b9\u51fb\u201c\u9009\u62e9\u6587\u4ef6...\u201d";
        SetWindowTextWString(s->pageSummary, hint);
        ListView_DeleteAllItems(s->pageSections);
        ListView_DeleteAllItems(s->pageImportsDlls);
        ListView_DeleteAllItems(s->pageImports);
        ListView_DeleteAllItems(s->pageExports);
        s->importsAllRows.clear();
        SetWindowTextWString(s->pageResources, hint);
        SetWindowTextWString(s->pagePdb, L"");
        SetWindowTextWString(s->pageSignature, L"");
        SetWindowTextWString(s->pageHash, L"");
        UpdateFileInfo(s);
        ShowWindow(s->btnOpenBig, SW_SHOW);
        return;
    }

    SetWindowTextWString(s->pageSummary, FormatSummaryText(*s->analysis));
    PopulateSections(s->pageSections, s->analysis->parser);
    BuildImportRowsFromParser(s->importsAllRows, s->analysis->parser);
    ApplyImportsFilterNow(s);
    PopulateExports(s->pageExports, s->analysis->parser);
    PopulateResources(s->pageResources, s->analysis->parser);
    PopulatePdb(s->pagePdb, s->analysis->pdb);
    PopulateSignature(s->pageSignature, *s->analysis, IsVerifyInFlightForCurrent(s));
    PopulateHash(s->pageHash, s->analysis->hashes);
    UpdateFileInfo(s);
    ShowWindow(s->btnOpenBig, SW_HIDE);
}

static unsigned __stdcall AnalysisThreadProc(void* param) {
    struct Payload { HWND hwnd; std::wstring file; std::atomic<bool>* cancel; };
    auto* pl = reinterpret_cast<Payload*>(param);
    HWND hwnd = pl->hwnd;
    std::wstring filePath = pl->file;

    auto* resultMsg = new AnalysisResultMessage();
    auto ar = std::make_unique<PEAnalysisResult>();

    PEAnalysisOptions opt;
    opt.computePdb = true;
    opt.computeSignaturePresence = true;
    opt.verifySignature = false;
    opt.computeHashes = true;
    opt.hashAlgorithms = {HashAlgorithm::MD5, HashAlgorithm::SHA1, HashAlgorithm::SHA256};
    opt.timeFormat = ReportTimeFormat::Local;
    opt.hashCancel = pl->cancel;
    opt.hashProgress = [hwnd](uint64_t total, uint64_t processed) {
        int pct = 0;
        if (total > 0) {
            pct = static_cast<int>((processed * 100) / total);
            if (pct > 100) pct = 100;
        }
        PostMessageW(hwnd, WM_APP_HASH_PROGRESS, static_cast<WPARAM>(pct), 0);
    };

    std::wstring err;
    if (!AnalyzePeFile(filePath, opt, *ar, err)) {
        resultMsg->ok = false;
        resultMsg->error = err;
    } else {
        resultMsg->ok = true;
        resultMsg->result = std::move(ar);
    }

    PostMessageW(hwnd, WM_APP_ANALYSIS_DONE, 0, reinterpret_cast<LPARAM>(resultMsg));
    delete pl;
    return 0;
}

static unsigned __stdcall VerifyThreadProc(void* param) {
    auto* msg = reinterpret_cast<std::pair<HWND, std::wstring>*>(param);
    HWND hwnd = msg->first;
    std::wstring filePath = msg->second;
    delete msg;

    auto* vr = new VerifyResultMessage();
    vr->filePath = filePath;
    try {
        vr->embedded = VerifyEmbeddedSignature(filePath);
        vr->catalog = VerifyCatalogSignature(filePath);
        vr->ok = true;
    } catch (...) {
        vr->ok = false;
        vr->error = L"\u9a8c\u8bc1\u5931\u8d25";
    }

    PostMessageW(hwnd, WM_APP_VERIFY_DONE, 0, reinterpret_cast<LPARAM>(vr));
    return 0;
}

static bool HasAnyVerifyResult(const PEAnalysisResult& ar) {
    return ar.embeddedVerify.has_value() || ar.catalogVerify.has_value();
}

static void StartVerifyIfNeeded(GuiState* s, bool force) {
    if (s->analysis == nullptr || s->currentFile.empty()) {
        return;
    }
    if (!s->analysis->signaturePresenceReady) {
        return;
    }
    if (!force) {
        if (HasAnyVerifyResult(*s->analysis)) {
            return;
        }
    }
    if (s->busy) {
        return;
    }
    if (s->verifyInFlight) {
        return;
    }

    s->verifyInFlight = true;
    s->verifyInFlightFile = s->currentFile;
    s->analysis->embeddedVerify.reset();
    s->analysis->catalogVerify.reset();
    PopulateSignature(s->pageSignature, *s->analysis, IsVerifyInFlightForCurrent(s));

    auto* payload = new std::pair<HWND, std::wstring>(s->hwnd, s->currentFile);
    uintptr_t th = _beginthreadex(nullptr, 0, VerifyThreadProc, payload, 0, nullptr);
    if (th == 0) {
        delete payload;
        s->verifyInFlight = false;
        s->verifyInFlightFile.clear();
        PopulateSignature(s->pageSignature, *s->analysis, IsVerifyInFlightForCurrent(s));
        MessageBoxError(s->hwnd, L"\u542f\u52a8\u9a8c\u8bc1\u7ebf\u7a0b\u5931\u8d25");
        return;
    }
    CloseHandle(reinterpret_cast<HANDLE>(th));
}

static void StartAnalysis(GuiState* s, const std::wstring& filePath) {
    if (s->busy) {
        return;
    }
    if (s->verifyInFlight && !s->verifyInFlightFile.empty() && s->verifyInFlightFile == filePath) {
        return;
    }
    s->currentFile = filePath;
    s->analysis.reset();
    s->hashProgressPercent = -1;
    if (s->analysisCancel) {
        delete s->analysisCancel;
        s->analysisCancel = nullptr;
    }
    s->analysisCancel = new std::atomic<bool>(false);
    SetBusy(s, true);
    SetWindowTextWString(s->pageSummary, L"\u6b63\u5728\u89e3\u6790...");
    SetWindowTextWString(s->pageHash, L"\u6b63\u5728\u8ba1\u7b97\u54c8\u5e0c...");
    SetWindowTextWString(s->pageResources, L"\u6b63\u5728\u89e3\u6790...");
    UpdateFileInfo(s);

    struct Payload { HWND hwnd; std::wstring file; std::atomic<bool>* cancel; };
    auto* payload = new Payload{s->hwnd, filePath, s->analysisCancel};
    uintptr_t th = _beginthreadex(nullptr, 0, AnalysisThreadProc, payload, 0, nullptr);
    if (th == 0) {
        delete payload;
        SetBusy(s, false);
        MessageBoxError(s->hwnd, L"\u542f\u52a8\u89e3\u6790\u7ebf\u7a0b\u5931\u8d25");
        return;
    }
    CloseHandle(reinterpret_cast<HANDLE>(th));
}

static std::wstring PromptOpenFile(HWND hwnd) {
    wchar_t fileName[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"PE Files (*.exe;*.dll;*.sys;*.ocx)\0*.exe;*.dll;*.sys;*.ocx\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
        return {};
    }
    return fileName;
}

static void FitImportsDllColumns(GuiState* s) {
    if (!s || !s->pageImportsDlls) {
        return;
    }

    HWND header = ListView_GetHeader(s->pageImportsDlls);
    if (!header || Header_GetItemCount(header) < 2) {
        return;
    }

    RECT rc = {};
    GetClientRect(s->pageImportsDlls, &rc);
    int clientW = rc.right - rc.left;
    if (clientW <= 0) {
        return;
    }

    int gap = MulDiv(12, static_cast<int>(s->dpi), 96);
    int minDllW = MulDiv(80, static_cast<int>(s->dpi), 96);
    int minCountW = MulDiv(52, static_cast<int>(s->dpi), 96);
    int maxCountW = clientW - minDllW - gap;
    if (maxCountW < minCountW) {
        maxCountW = minCountW;
    }
    int countW = MulDiv(64, static_cast<int>(s->dpi), 96);
    ListView_SetColumnWidth(s->pageImportsDlls, 1, LVSCW_AUTOSIZE);
    countW = ListView_GetColumnWidth(s->pageImportsDlls, 1);
    if (countW < minCountW) countW = minCountW;
    if (countW > maxCountW) countW = maxCountW;
    ListView_SetColumnWidth(s->pageImportsDlls, 1, countW);

    int dllW = clientW - countW - gap;
    if (dllW < minDllW) dllW = minDllW;
    ListView_SetColumnWidth(s->pageImportsDlls, 0, dllW);
}

static void FitImportsFuncColumns(GuiState* s) {
    if (!s || !s->pageImports) {
        return;
    }

    HWND header = ListView_GetHeader(s->pageImports);
    if (!header || Header_GetItemCount(header) < 2) {
        return;
    }

    RECT rc = {};
    GetClientRect(s->pageImports, &rc);
    int clientW = rc.right - rc.left;
    if (clientW <= 0) {
        return;
    }

    int gap = MulDiv(12, static_cast<int>(s->dpi), 96);
    int minTypeW = MulDiv(70, static_cast<int>(s->dpi), 96);
    int maxTypeW = MulDiv(120, static_cast<int>(s->dpi), 96);
    int minFuncW = MulDiv(120, static_cast<int>(s->dpi), 96);

    ListView_SetColumnWidth(s->pageImports, 0, LVSCW_AUTOSIZE);
    int typeW = ListView_GetColumnWidth(s->pageImports, 0);
    if (typeW < minTypeW) typeW = minTypeW;
    if (typeW > maxTypeW) typeW = maxTypeW;
    ListView_SetColumnWidth(s->pageImports, 0, typeW);

    int funcW = clientW - typeW - gap;
    if (funcW < minFuncW) funcW = minFuncW;
    ListView_SetColumnWidth(s->pageImports, 1, funcW);
}

static void UpdateLayout(GuiState* s) {
    RECT rc = {};
    GetClientRect(s->hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    int pad = MulDiv(10, static_cast<int>(s->dpi), 96);
    int iconBtn = MulDiv(32, static_cast<int>(s->dpi), 96);
    int fileInfoY = pad;
    int fileInfoH = MulDiv(24, static_cast<int>(s->dpi), 96);
    int btnGap = MulDiv(6, static_cast<int>(s->dpi), 96);
    int btnY = fileInfoY - MulDiv(4, static_cast<int>(s->dpi), 96);
    int gearX = w - pad - iconBtn;
    int openSmallX = gearX - btnGap - iconBtn;
    MoveWindow(s->btnOpenSmall, openSmallX, btnY, iconBtn, iconBtn, TRUE);
    MoveWindow(s->btnSettingsGear, gearX, btnY, iconBtn, iconBtn, TRUE);

    int fileInfoW = w - 2 * pad - (2 * iconBtn + btnGap) - pad;
    if (fileInfoW < MulDiv(120, static_cast<int>(s->dpi), 96)) {
        fileInfoW = MulDiv(120, static_cast<int>(s->dpi), 96);
    }
    MoveWindow(s->fileInfo, pad, fileInfoY, fileInfoW, fileInfoH, TRUE);

    int tabY = fileInfoY + fileInfoH + pad;
    int tabH = h - tabY - pad;
    MoveWindow(s->tab, pad, tabY, w - 2 * pad, tabH, TRUE);

    RECT pageRc = GetTabPageRect(s->hwnd, s->tab);
    int pageW = pageRc.right - pageRc.left;
    int pageH = pageRc.bottom - pageRc.top;

    MoveWindow(s->pageSummary, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageSections, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    int filterH = MulDiv(28, static_cast<int>(s->dpi), 96);
    int filterLabelW = MulDiv(28, static_cast<int>(s->dpi), 96);
    int filterY = pageRc.top;
    int filterX = pageRc.left;
    int filterGap = pad;
    int filterEditX = filterX + filterLabelW + filterGap;
    int filterEditW = pageW - filterLabelW - filterGap;
    if (filterEditW < MulDiv(100, static_cast<int>(s->dpi), 96)) {
        filterEditW = MulDiv(100, static_cast<int>(s->dpi), 96);
    }

    MoveWindow(s->importsFilterLabel, filterX, filterY, filterLabelW, filterH, TRUE);
    MoveWindow(s->importsFilterEdit, filterEditX, filterY, filterEditW, filterH, TRUE);
    int importsY = pageRc.top + filterH + pad;
    int importsH = pageH - filterH - pad;
    int splitGap = pad;
    int minLeftW = MulDiv(220, static_cast<int>(s->dpi), 96);
    int minRightW = MulDiv(240, static_cast<int>(s->dpi), 96);
    int leftW = pageW / 3;
    if (leftW < minLeftW) leftW = minLeftW;
    if (leftW > pageW - splitGap - minRightW) leftW = pageW - splitGap - minRightW;
    if (leftW < MulDiv(120, static_cast<int>(s->dpi), 96)) leftW = MulDiv(120, static_cast<int>(s->dpi), 96);
    int rightW = pageW - leftW - splitGap;
    if (rightW < MulDiv(80, static_cast<int>(s->dpi), 96)) rightW = MulDiv(80, static_cast<int>(s->dpi), 96);

    MoveWindow(s->pageImportsDlls, pageRc.left, importsY, leftW, importsH, TRUE);
    MoveWindow(s->pageImports, pageRc.left + leftW + splitGap, importsY, rightW, importsH, TRUE);
    FitImportsDllColumns(s);
    FitImportsFuncColumns(s);
    InvalidateRect(s->pageImportsDlls, nullptr, TRUE);
    InvalidateRect(s->pageImports, nullptr, TRUE);
    MoveWindow(s->pageExports, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageResources, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pagePdb, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageSignature, pageRc.left, pageRc.top, pageW, pageH, TRUE);

    MoveWindow(s->pageHash, pageRc.left, pageRc.top, pageW, pageH, TRUE);

    int bigBtnW = MulDiv(300, static_cast<int>(s->dpi), 96);
    int bigBtnH = MulDiv(56, static_cast<int>(s->dpi), 96);
    int bigX = pageRc.left + (pageW - bigBtnW) / 2;
    int bigY = pageRc.top + (pageH - bigBtnH) / 2;
    MoveWindow(s->btnOpenBig, bigX, bigY, bigBtnW, bigBtnH, TRUE);
}

static UINT GetBestWindowDpi(HWND hwnd) {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
        auto fn = reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(user32, "GetDpiForWindow"));
        if (fn) {
            UINT dpi = fn(hwnd);
            if (dpi != 0) {
                return dpi;
            }
        }
    }
    HDC dc = GetDC(hwnd);
    int dpi = dc ? GetDeviceCaps(dc, LOGPIXELSY) : 96;
    if (dc) {
        ReleaseDC(hwnd, dc);
    }
    return (dpi > 0) ? static_cast<UINT>(dpi) : 96;
}

static HFONT CreateUiFontForDpi(UINT dpi) {
    NONCLIENTMETRICSW ncm = {};
    ncm.cbSize = sizeof(ncm);

    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using SystemParametersInfoForDpiFn = BOOL(WINAPI*)(UINT, UINT, PVOID, UINT, UINT);
        auto fn = reinterpret_cast<SystemParametersInfoForDpiFn>(GetProcAddress(user32, "SystemParametersInfoForDpi"));
        if (fn && fn(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, dpi)) {
            return CreateFontIndirectW(&ncm.lfMessageFont);
        }
    }
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        return CreateFontIndirectW(&ncm.lfMessageFont);
    }
    return reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
}

static HFONT CreateIconFontForDpi(UINT dpi) {
    int px = MulDiv(18, static_cast<int>(dpi), 96);
    return CreateFontW(-px,
                       0,
                       0,
                       0,
                       FW_NORMAL,
                       FALSE,
                       FALSE,
                       FALSE,
                       DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE,
                       L"Segoe MDL2 Assets");
}

static void ApplyUiFontAndTheme(GuiState* s) {
    if (!s->uiFont) {
        return;
    }

    HWND controls[] = {
        s->btnOpenSmall,
        s->btnSettingsGear,
        s->btnOpenBig,
        s->fileInfo,
        s->tab,
        s->pageSummary,
        s->pageSections,
        s->pageImportsDlls,
        s->pageImports,
        s->pageExports,
        s->pageResources,
        s->pagePdb,
        s->pageSignature,
        s->pageHash,
        s->importsFilterLabel,
        s->importsFilterEdit,
    };
    for (HWND hwnd : controls) {
        if (hwnd) {
            SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(s->uiFont), TRUE);
        }
    }
    if (s->btnSettingsGear && s->iconFont) {
        SendMessageW(s->btnSettingsGear, WM_SETFONT, reinterpret_cast<WPARAM>(s->iconFont), TRUE);
    }
    if (s->importsFilterLabel && s->iconFont) {
        SendMessageW(s->importsFilterLabel, WM_SETFONT, reinterpret_cast<WPARAM>(s->iconFont), TRUE);
    }

    SetWindowTheme(s->tab, L"Explorer", nullptr);
    SetWindowTheme(s->pageSections, L"Explorer", nullptr);
    SetWindowTheme(s->pageImportsDlls, L"Explorer", nullptr);
    SetWindowTheme(s->pageImports, L"Explorer", nullptr);
    SetWindowTheme(s->pageExports, L"Explorer", nullptr);

    int editMargin = MulDiv(8, static_cast<int>(s->dpi), 96);
    SendMessageW(s->pageSummary, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageResources, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pagePdb, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageSignature, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageHash, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));

    DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;
    ListView_SetExtendedListViewStyleEx(s->pageSections, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageImportsDlls, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageImports, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageExports, ex, ex);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GuiState* s = reinterpret_cast<GuiState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    if (!s) {
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    switch (msg) {
        case WM_CREATE: {
            DragAcceptFiles(hwnd, TRUE);
            s->hwnd = hwnd;
            s->dpi = GetBestWindowDpi(hwnd);
            s->uiFont = CreateUiFontForDpi(s->dpi);
            s->iconFont = CreateIconFontForDpi(s->dpi);

            s->btnSettingsGear = CreateWindowW(L"BUTTON", L"\xE713", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_SETTINGS_GEAR), nullptr, nullptr);

            s->fileInfo = CreateWindowW(L"STATIC",
                                        L"\u672a\u6253\u5f00\u6587\u4ef6",
                                        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                                        0,
                                        0,
                                        0,
                                        0,
                                        hwnd,
                                        reinterpret_cast<HMENU>(IDC_FILEINFO),
                                        nullptr,
                                        nullptr);

            s->btnOpenSmall = CreateWindowW(L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_ICON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_OPEN_SMALL), nullptr, nullptr);
            s->btnOpenBig = CreateWindowW(L"BUTTON", L"\u9009\u62e9\u6587\u4ef6...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_OPEN_BIG), nullptr, nullptr);

            SHSTOCKICONINFO sii = {};
            sii.cbSize = sizeof(sii);
            if (SUCCEEDED(SHGetStockIconInfo(SIID_FOLDEROPEN, SHGSI_ICON | SHGSI_SMALLICON, &sii))) {
                s->iconOpen = sii.hIcon;
                SendMessageW(s->btnOpenSmall, BM_SETIMAGE, IMAGE_ICON, reinterpret_cast<LPARAM>(s->iconOpen));
            }

            HMENU sys = GetSystemMenu(hwnd, FALSE);
            if (sys) {
                AppendMenuW(sys, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(sys, MF_STRING, IDM_SYS_SETTINGS, L"\u8bbe\u7f6e...");
                AppendMenuW(sys, MF_STRING, IDM_SYS_CANCEL, L"\u53d6\u6d88\u89e3\u6790");
            }

            s->tab = CreateWindowW(WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TAB), nullptr, nullptr);

            TCITEMW ti = {};
            ti.mask = TCIF_TEXT;
            ti.pszText = const_cast<wchar_t*>(L"Summary");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Summary), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Sections");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Sections), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Imports");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Imports), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Exports");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Exports), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Resources");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Resources), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Debug/PDB");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::DebugPdb), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Signature");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Signature), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Hash");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Hash), &ti);

            DWORD editStyle = WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_READONLY;
            s->pageSummary = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUMMARY), nullptr, nullptr);
            s->pageResources = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_RESOURCES), nullptr, nullptr);
            s->pagePdb = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PDB), nullptr, nullptr);
            s->pageSignature = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SIGNATURE), nullptr, nullptr);
            s->pageHash = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_HASH), nullptr, nullptr);

            DWORD listStyle = WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS;
            s->pageSections = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SECTIONS), nullptr, nullptr);
            s->pageImportsDlls = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS_DLLS), nullptr, nullptr);
            s->pageImports = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS), nullptr, nullptr);
            s->pageExports = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORTS), nullptr, nullptr);

            DWORD filterLabelStyle = WS_CHILD | SS_CENTER | SS_CENTERIMAGE;
            s->importsFilterLabel = CreateWindowW(L"STATIC", L"\uE721", filterLabelStyle, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            DWORD filterEditStyle = WS_CHILD | ES_LEFT | ES_AUTOHSCROLL;
            s->importsFilterEdit = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", filterEditStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS_FILTER), nullptr, nullptr);

            auto colW = [&](int base) { return MulDiv(base, static_cast<int>(s->dpi), 96); };
            AddListViewColumn(s->pageSections, 0, colW(140), L"Name");
            AddListViewColumn(s->pageSections, 1, colW(120), L"RVA");
            AddListViewColumn(s->pageSections, 2, colW(120), L"VSize");
            AddListViewColumn(s->pageSections, 3, colW(120), L"RawOff");
            AddListViewColumn(s->pageSections, 4, colW(120), L"RawSize");
            AddListViewColumn(s->pageSections, 5, colW(140), L"Chars");

            AddListViewColumn(s->pageImportsDlls, 0, colW(320), L"DLL");
            AddListViewColumn(s->pageImportsDlls, 1, colW(90), L"Count");

            AddListViewColumn(s->pageImports, 0, colW(92), L"Type");
            AddListViewColumn(s->pageImports, 1, colW(520), L"Function");

            AddListViewColumn(s->pageExports, 0, colW(100), L"Ordinal");
            AddListViewColumn(s->pageExports, 1, colW(120), L"RVA");
            AddListViewColumn(s->pageExports, 2, colW(380), L"Name");

            ApplyUiFontAndTheme(s);
            ShowOnlyTab(s, TabIndex::Summary);
            SetBusy(s, false);
            RefreshAllViews(s);
            UpdateLayout(s);
            if (!s->pendingFile.empty()) {
                std::wstring path = s->pendingFile;
                s->pendingFile.clear();
                StartAnalysis(s, path);
            }
            return 0;
        }
        case WM_SIZE: {
            UpdateLayout(s);
            return 0;
        }
        case WM_DPICHANGED: {
            auto* suggested = reinterpret_cast<RECT*>(lParam);
            if (suggested) {
                SetWindowPos(hwnd,
                             nullptr,
                             suggested->left,
                             suggested->top,
                             suggested->right - suggested->left,
                             suggested->bottom - suggested->top,
                             SWP_NOZORDER | SWP_NOACTIVATE);
            }
            s->dpi = static_cast<UINT>(HIWORD(wParam));
            if (s->uiFont) {
                DeleteObject(s->uiFont);
            }
            s->uiFont = CreateUiFontForDpi(s->dpi);
            if (s->iconFont) {
                DeleteObject(s->iconFont);
            }
            s->iconFont = CreateIconFontForDpi(s->dpi);
            ApplyUiFontAndTheme(s);
            UpdateLayout(s);
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_OPEN_SMALL:
                case IDC_BTN_OPEN_BIG: {
                    std::wstring path = PromptOpenFile(hwnd);
                    if (!path.empty()) {
                        StartAnalysis(s, path);
                    }
                    return 0;
                }
                case IDC_BTN_SETTINGS_GEAR: {
                    ShowSettingsDialog(hwnd);
                    return 0;
                }
                case IDC_IMPORTS_FILTER: {
                    if (HIWORD(wParam) == EN_CHANGE) {
                        SetTimer(hwnd, kTimerImportsFilter, 200, nullptr);
                    }
                    return 0;
                }
                case VK_ESCAPE: {
                    if (s->busy && s->analysisCancel) {
                        s->analysisCancel->store(true);
                    }
                    return 0;
                }
            }
            break;
        }
        case WM_SYSCOMMAND: {
            if ((wParam & 0xFFF0) == IDM_SYS_SETTINGS) {
                ShowSettingsDialog(hwnd);
                return 0;
            }
            if ((wParam & 0xFFF0) == IDM_SYS_CANCEL) {
                if (s->busy && s->analysisCancel) {
                    s->analysisCancel->store(true);
                }
                return 0;
            }
            break;
        }
        case WM_TIMER: {
            if (wParam == kTimerImportsFilter) {
                KillTimer(hwnd, kTimerImportsFilter);
                ApplyImportsFilterNow(s);
                return 0;
            }
            break;
        }
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<NMHDR*>(lParam);
            if (nm->hwndFrom == s->tab && nm->code == TCN_SELCHANGE) {
                int idx = TabCtrl_GetCurSel(s->tab);
                ShowOnlyTab(s, static_cast<TabIndex>(idx));
                UpdateLayout(s);
                if (idx == static_cast<int>(TabIndex::Signature)) {
                    StartVerifyIfNeeded(s, false);
                }
                return 0;
            }
            if (nm->hwndFrom == s->pageImportsDlls && nm->code == LVN_ITEMCHANGED) {
                if (s->importsSyncingSelection) {
                    return 0;
                }
                auto* nmlv = reinterpret_cast<NMLISTVIEW*>(lParam);
                if (nmlv->iItem >= 0 && (nmlv->uNewState & LVIS_SELECTED) && !(nmlv->uOldState & LVIS_SELECTED)) {
                    wchar_t buf[1024] = {};
                    ListView_GetItemText(s->pageImportsDlls, nmlv->iItem, 0, buf, static_cast<int>(std::size(buf)));
                    s->importsSelectedDll = buf;
                    UpdateImportFunctionsForSelection(s);
                    return 0;
                }
            }
            break;
        }
        case WM_DROPFILES: {
            HDROP drop = reinterpret_cast<HDROP>(wParam);
            wchar_t path[MAX_PATH] = {};
            if (DragQueryFileW(drop, 0, path, MAX_PATH)) {
                StartAnalysis(s, path);
            }
            DragFinish(drop);
            return 0;
        }
        case WM_APP_ANALYSIS_DONE: {
            auto* r = reinterpret_cast<AnalysisResultMessage*>(lParam);
            if (!r->ok) {
                SetBusy(s, false);
                if (s->analysisCancel) { delete s->analysisCancel; s->analysisCancel = nullptr; }
                s->analysis.reset();
                RefreshAllViews(s);
                MessageBoxError(s->hwnd, r->error.empty() ? L"\u89e3\u6790\u5931\u8d25" : r->error);
                delete r;
                return 0;
            }
            s->analysis = std::move(r->result);
            SetBusy(s, false);
            if (s->analysisCancel) { delete s->analysisCancel; s->analysisCancel = nullptr; }
            RefreshAllViews(s);
            delete r;
            return 0;
        }
        case WM_APP_HASH_PROGRESS: {
            int pct = static_cast<int>(wParam);
            s->hashProgressPercent = pct;
            if (pct >= 0 && pct <= 100) {
                std::wostringstream out;
                out << L"\u6b63\u5728\u8ba1\u7b97\u54c8\u5e0c: " << pct << L"%\r\n";
                SetWindowTextWString(s->pageHash, out.str());
            }
            return 0;
        }
        case WM_APP_VERIFY_DONE: {
            auto* vr = reinterpret_cast<VerifyResultMessage*>(lParam);
            if (s->verifyInFlight && !s->verifyInFlightFile.empty() && vr->filePath == s->verifyInFlightFile) {
                s->verifyInFlight = false;
                s->verifyInFlightFile.clear();
            }
            if (!vr->filePath.empty() && vr->filePath != s->currentFile) {
                delete vr;
                return 0;
            }
            if (s->analysis != nullptr) {
                if (vr->ok) {
                    s->analysis->embeddedVerify = vr->embedded;
                    s->analysis->catalogVerify = vr->catalog;
                    PopulateSignature(s->pageSignature, *s->analysis, IsVerifyInFlightForCurrent(s));
                } else {
                    MessageBoxError(s->hwnd, vr->error.empty() ? L"\u9a8c\u8bc1\u5931\u8d25" : vr->error);
                }
            }
            delete vr;
            return 0;
        }
        case WM_DESTROY: {
            if (s->iconOpen) {
                DestroyIcon(s->iconOpen);
                s->iconOpen = nullptr;
            }
            if (s->iconFont) {
                DeleteObject(s->iconFont);
                s->iconFont = nullptr;
            }
            if (s->uiFont) {
                DeleteObject(s->uiFont);
                s->uiFont = nullptr;
            }
            if (s->analysisCancel) {
                delete s->analysisCancel;
                s->analysisCancel = nullptr;
            }
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void EnableBestDpiAwareness() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using SetProcessDpiAwarenessContextFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto fn = reinterpret_cast<SetProcessDpiAwarenessContextFn>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (fn) {
            fn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            return;
        }
    }
    SetProcessDPIAware();
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    EnableBestDpiAwareness();
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv != nullptr && argc >= 4) {
            std::wstring mode = argv[1];
            if (mode == L"--export-json" || mode == L"--export-text") {
                std::wstring inPath = argv[2];
                std::wstring outPath = argv[3];

                PEAnalysisResult ar;
                PEAnalysisOptions opt;
                opt.computePdb = true;
                opt.computeSignaturePresence = true;
                opt.verifySignature = false;
                opt.computeHashes = true;
                opt.hashAlgorithms = {HashAlgorithm::SHA256};
                opt.timeFormat = ReportTimeFormat::Local;

                std::wstring err;
                if (!AnalyzePeFile(inPath, opt, ar, err)) {
                    LocalFree(argv);
                    return 2;
                }

                ReportOptions ro;
                ro.showSummary = true;
                ro.showSections = true;
                ro.showImports = true;
                ro.showExports = true;
                ro.showResources = true;
                ro.resourcesAll = true;
                ro.showPdb = true;
                ro.showSignature = true;
                ro.importsAll = true;
                ro.quiet = false;
                ro.timeFormat = ReportTimeFormat::Local;

                if (mode == L"--export-json") {
                    std::string json = BuildJsonReport(ro,
                                                       ar.filePath,
                                                       ar.parser,
                                                       ar.pdb,
                                                       ar.signaturePresenceReady ? &ar.signaturePresence : nullptr,
                                                       &ar.embeddedVerify,
                                                       &ar.catalogVerify,
                                                       ar.reportHash.has_value() ? &ar.reportHash : nullptr);
                    json.push_back('\n');
                    bool ok = WriteAllBytes(outPath, json);
                    LocalFree(argv);
                    return ok ? 0 : 3;
                }

                std::wstring text = BuildTextReport(ro,
                                                    ar.filePath,
                                                    ar.parser,
                                                    ar.pdb,
                                                    ar.signaturePresenceReady ? &ar.signaturePresence : nullptr,
                                                    ar.embeddedVerify,
                                                    ar.catalogVerify,
                                                    ar.reportHash,
                                                    0,
                                                    500);
                std::string utf8 = WStringToUtf8(text);
                bool ok = WriteAllBytes(outPath, utf8);
                LocalFree(argv);
                return ok ? 0 : 3;
            }
        }
        if (argv != nullptr) {
            LocalFree(argv);
        }
    }

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icc);

    GuiState state;
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv != nullptr && argc >= 2) {
            std::wstring arg1 = argv[1];
            if (!arg1.empty() && arg1.rfind(L"--", 0) != 0) {
                DWORD attr = GetFileAttributesW(arg1.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                    state.pendingFile = arg1;
                }
            }
        }
        if (argv != nullptr) {
            LocalFree(argv);
        }
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = kMainClassName;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, kMainClassName, L"PEInfo GUI", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720,
                                nullptr, nullptr, hInstance, &state);
    if (!hwnd) {
        return 1;
    }
    state.hwnd = hwnd;

    if (nCmdShow != SW_SHOWMAXIMIZED && nCmdShow != SW_MAXIMIZE && nCmdShow != SW_MINIMIZE && nCmdShow != SW_SHOWMINIMIZED && nCmdShow != SW_FORCEMINIMIZE) {
        CenterWindowOnWorkArea(hwnd);
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

