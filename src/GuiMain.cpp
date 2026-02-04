#include "stdafx.h"

#include "PECore.h"
#include "PEResource.h"
#include "ReportJsonWriter.h"
#include "ReportTextWriter.h"
#include "ReportUtil.h"
#include "ShellContextMenu.h"
#include "StringsScanner.h"
#include "StringsSearchHistory.h"
#include "PdbFileInfo.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <windowsx.h>
#include <process.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

static const wchar_t* kMainClassName = L"PEInfoGuiMainWindow";

static const UINT WM_APP_ANALYSIS_DONE = WM_APP + 1;
static const UINT WM_APP_VERIFY_DONE = WM_APP + 2;
static const UINT WM_APP_HASH_PROGRESS = WM_APP + 3;
static const UINT WM_APP_STRINGS_DONE = WM_APP + 4;
static const UINT WM_APP_STRINGS_ROWS_DONE = WM_APP + 5;
static const UINT_PTR kTimerImportsFilter = 1;
static const UINT_PTR kTimerExportsFilter = 2;
static const UINT_PTR kTimerStringsFilter = 3;
static const UINT_PTR kTimerStringsFilterWork = 4;
static const UINT_PTR kTimerStringsHistorySave = 5;
static const WPARAM IDM_SYS_SETTINGS = 0x1FF0;
static const WPARAM IDM_SYS_CANCEL = 0x1FF2;
static const size_t kStringsUiMaxRows = 200000;
static const int kStringsUiPageSize = 50000;

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
DECLARE_HANDLE(DPI_AWARENESS_CONTEXT);
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif

enum : UINT {
    IDC_BTN_OPEN_SMALL = 1001,
    IDC_BTN_SETTINGS_GEAR = 1002,
    IDC_TAB = 1010,
    IDC_FILEINFO = 1020,
    IDC_SUMMARY = 2001,
    IDC_HEADERS = 2014,
    IDC_SECTIONS = 2002,
    IDC_IMPORTS = 2003,
    IDC_EXPORTS = 2004,
    IDC_STRINGS = 2010,
    IDC_RESOURCES = 2009,
    IDC_PDB = 2005,
    IDC_SIGNATURE = 2006,
    IDC_HASH = 2007,
    IDC_IMPORTS_DLLS = 2008,
    IDC_IMPORTS_FILTER = 2101,
    IDC_EXPORTS_FILTER = 2102,
    IDC_EXPORTS_INFO = 2103,
    IDC_EXPORTS_SEPARATOR = 2104,
    IDC_STRINGS_SEARCH = 2201,
    IDC_STRINGS_TYPE = 2202,
    IDC_STRINGS_MINLEN = 2203,
    IDC_STRINGS_UNIQUE = 2204,
    IDC_STRINGS_DETAIL = 2205,
    IDC_STRINGS_COPYDETAIL = 2206,
    IDC_STRINGS_REGEX = 2207,
    IDC_STRINGS_HISTORY_CLEAR = 2208,
    IDC_STRINGS_HISTORY_TAG0 = 2210,
    IDC_STRINGS_HISTORY_TAG1 = 2211,
    IDC_STRINGS_HISTORY_TAG2 = 2212,
    IDC_STRINGS_HISTORY_TAG3 = 2213,
    IDC_STRINGS_HISTORY_TAG4 = 2214,
    IDC_STRINGS_HISTORY_TAG5 = 2215,
    IDC_STRINGS_HISTORY_TAG6 = 2216,
    IDC_STRINGS_HISTORY_TAG7 = 2217,
    IDC_STRINGS_PAGE_PREV = 2218,
    IDC_STRINGS_PAGE_NEXT = 2219,
    IDC_STRINGS_PAGE_LABEL = 2220,
    IDC_ABOUT = 2011,
    IDC_ABOUT_INFO = 2012,
    IDC_ABOUT_LINK = 2013
};

enum class TabIndex : int {
    Summary = 0,
    Headers = 1,
    Sections = 2,
    Imports = 3,
    Exports = 4,
    Strings = 5,
    Resources = 6,
    DebugPdb = 7,
    Signature = 8,
    Hash = 9,
    About = 10
};

enum : UINT {
    IDM_STRINGS_COPY_TEXT = 41001,
    IDM_STRINGS_COPY_LINE = 41002,
    IDM_STRINGS_COPY_DETAIL = 41003,
    IDM_STRINGS_EXPORT_TEXT = 41004,
    IDM_STRINGS_EXPORT_JSON = 41005,
    IDM_STRINGS_HISTORY_CLEAR_UNPINNED = 41010,
    IDM_STRINGS_HISTORY_CLEAR_ALL = 41011,
    IDM_STRINGS_HISTORY_PIN = 41012,
    IDM_STRINGS_HISTORY_UNPIN = 41013,
    IDM_STRINGS_HISTORY_DELETE = 41014,
    IDM_HEADERS_COPY_ROW = 42001
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

struct StringsResultMessage {
    std::wstring filePath;
    std::vector<StringsHit> hits;
    std::atomic<bool>* cancel = nullptr;
    bool ok = true;
    std::wstring error;
    bool truncated = false;
    size_t hitLimit = 0;
    int minLen = 5;
    bool scanAscii = true;
    bool scanUtf16Le = true;
};

struct GuiState {
    HWND hwnd = nullptr;
    HWND btnOpenSmall = nullptr;
    HWND btnSettingsGear = nullptr;
    HWND fileInfo = nullptr;
    HWND tab = nullptr;

    HWND pageSummary = nullptr;
    HWND pageHeaders = nullptr;
    HWND pageSections = nullptr;
    HWND pageImportsDlls = nullptr;
    HWND pageImports = nullptr;
    HWND pageExports = nullptr;
    HWND pageStrings = nullptr;
    HWND pageResources = nullptr;
    HWND pagePdb = nullptr;
    HWND pageSignature = nullptr;
    HWND pageHash = nullptr;
    HWND pageAbout = nullptr;
    HWND aboutInfo = nullptr;
    HWND aboutLink = nullptr;
    HWND importsFilterLabel = nullptr;
    HWND importsFilterEdit = nullptr;
    HWND exportsFilterLabel = nullptr;
    HWND exportsFilterEdit = nullptr;
    HWND exportsInfo = nullptr;
    HWND exportsSeparator = nullptr;
    HWND stringsSearchLabel = nullptr;
    HWND stringsSearchEdit = nullptr;
    HWND stringsRegexCheck = nullptr;
    HWND stringsTypeLabel = nullptr;
    HWND stringsTypeCombo = nullptr;
    HWND stringsMinLenLabel = nullptr;
    HWND stringsMinLenEdit = nullptr;
    HWND stringsUniqueCheck = nullptr;
    HWND stringsHistoryLabel = nullptr;
    HWND stringsHistoryClearBtn = nullptr;
    HWND stringsHistoryTags[8] = {};

    HBRUSH bgBrush = nullptr;
    HBRUSH regexErrorBrush = nullptr;

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

    struct ExportRow {
        std::wstring ordinal;
        std::wstring rva;
        std::wstring offset;
        std::wstring name;
        std::wstring forwarder;
        std::wstring haystackLower;
    };
    std::vector<ExportRow> exportsAllRows;

    struct StringsRow {
        uint64_t fileOffset = 0;
        StringsHitType type = StringsHitType::Ascii;
        std::wstring fileOffsetHex;
        std::wstring section;
        std::optional<DWORD> rva;
        std::optional<ULONGLONG> va;
        std::wstring typeText;
        std::wstring lenText;
        std::wstring text;
        std::wstring haystackLower;
    };
    std::vector<StringsRow> stringsAllRows;
    std::vector<int> stringsVisible;
    std::vector<int> stringsVisibleAll;
    HWND stringsPagePrev = nullptr;
    HWND stringsPageNext = nullptr;
    HWND stringsPageLabel = nullptr;
    int stringsPageIndex = 0;
    int stringsPageCount = 0;
    int stringsPageSize = kStringsUiPageSize;
    bool stringsFilterRunning = false;
    size_t stringsFilterPos = 0;
    uint64_t stringsFilterGen = 0;
    std::vector<std::wstring> stringsFilterTokens;
    int stringsFilterMinLen = 5;
    int stringsFilterType = 0;
    bool stringsFilterUnique = true;
    bool stringsFilterUseRegex = false;
    bool stringsFilterRegexValid = true;
    std::wstring stringsFilterRegexPattern;
    std::wregex stringsFilterRegex;
    std::vector<int> stringsFilterResult;
    std::unordered_set<std::wstring_view> stringsFilterSeen;

    StringsSearchHistory stringsHistory;
    bool stringsHistoryDirty = false;
    std::vector<StringsSearchHistoryEntry> stringsHistoryDisplay;
    int stringsHistoryContextTag = -1;
    int stringsHistoryMaxTagsVisible = 8;

    std::wstring droppedPdbPath;
    std::optional<PdbFileInfo> droppedPdbInfo;
    std::wstring droppedPdbError;

    std::atomic<bool>* analysisCancel = nullptr;
    std::atomic<bool>* stringsCancel = nullptr;
    int hashProgressPercent = -1;
};

struct StringsRowsResultMessage {
    std::wstring filePath;
    std::vector<GuiState::StringsRow> rows;
    bool ok = true;
    std::wstring error;
};

struct StringsRowsBuildPayload {
    HWND hwnd = nullptr;
    std::wstring filePath;
    std::vector<StringsHit> hits;
    std::vector<PESectionInfo> sections;
    ULONGLONG imageBase = 0;
};

struct StringsScanPayload {
    HWND hwnd = nullptr;
    std::wstring filePath;
    std::atomic<bool>* cancel = nullptr;
    StringsScanOptions opt;
};

static UINT GetBestWindowDpi(HWND hwnd);
static HFONT CreateUiFontForDpi(UINT dpi);
static void FitImportsDllColumns(GuiState* s);
static void FitImportsFuncColumns(GuiState* s);
static void UpdateStringsDisplayCount(GuiState* s);
static void ApplyStringsFilterNow(GuiState* s);

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

static bool CopyTextToClipboard(HWND owner, const std::wstring& text) {
    if (!OpenClipboard(owner)) {
        return false;
    }
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!h) {
        CloseClipboard();
        return false;
    }
    void* p = GlobalLock(h);
    if (!p) {
        GlobalFree(h);
        CloseClipboard();
        return false;
    }
    memcpy(p, text.c_str(), bytes);
    GlobalUnlock(h);
    if (!SetClipboardData(CF_UNICODETEXT, h)) {
        GlobalFree(h);
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}

static bool CopySelectedHeadersRow(HWND owner, HWND list) {
    int sel = ListView_GetNextItem(list, -1, LVNI_SELECTED);
    if (sel < 0) {
        return false;
    }
    wchar_t f[512] = {};
    wchar_t v[2048] = {};
    wchar_t r[512] = {};
    ListView_GetItemText(list, sel, 0, f, static_cast<int>(std::size(f)));
    ListView_GetItemText(list, sel, 1, v, static_cast<int>(std::size(v)));
    ListView_GetItemText(list, sel, 2, r, static_cast<int>(std::size(r)));
    std::wstring line = std::wstring(f) + L"\t" + v + L"\t" + r;
    return CopyTextToClipboard(owner, line);
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

static std::wstring BuildAboutText() {
    std::wostringstream out;
    out << L"PEInfo\r\n\r\n";
    out << L"\u7248\u672c\uff1a v1.0.0\r\n";
    out << L"Build\uff1a " << TEXT(__DATE__) << L" " << TEXT(__TIME__) << L"\r\n";
    out << L"\u514d\u8d23\u58f0\u660e\uff1a\u672c\u5de5\u7a0b\u7531 vibe coding \u751f\u6210\uff0c\u4f7f\u7528\u98ce\u9669\u7531\u4f7f\u7528\u8005\u81ea\u884c\u627f\u62c5\u3002\r\n";
    return out.str();
}

static std::wstring FormatSummaryText(const PEAnalysisResult& ar) {
    const auto& h = ar.parser.GetHeaderInfo();
    std::wostringstream out;
    out << L"Path: " << ar.filePath << L"\r\n";
    const wchar_t* bitness = h.is64Bit ? L"x64" : (h.is32Bit ? L"x86" : L"Unknown");
    out << L"Architecture: " << bitness << L" (" << CoffMachineToName(h.machine) << L", " << HexU32(h.machine, 4) << L")\r\n";
    out << L"Subsystem: " << ToWStringUtf8BestEffort(h.subsystem) << L"\r\n";
    out << L"TimeDateStamp: " << HexU32(h.timeDateStamp, 8) << L" (" << FormatCoffTime(h.timeDateStamp, ReportTimeFormat::Local)
        << L")  [\u94fe\u63a5\u5668\u5199\u5165\uff0c\u4ec5\u4f9b\u53c2\u8003]\r\n";

    std::wstring md5 = L"(not computed)";
    for (const auto& r : ar.hashes) {
        if (r.success && r.algorithm == L"MD5") {
            md5 = r.result;
            break;
        }
    }
    out << L"MD5: " << md5 << L"\r\n";

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

static void InsertHeaderRow(HWND list, int row, int groupId, const std::wstring& field, const std::wstring& value, const std::wstring& raw) {
    LVITEMW item = {};
    item.mask = LVIF_TEXT | LVIF_GROUPID;
    item.iItem = row;
    item.iSubItem = 0;
    item.iGroupId = groupId;
    item.pszText = const_cast<wchar_t*>(field.c_str());
    ListView_InsertItem(list, &item);
    ListView_SetItemText(list, row, 1, const_cast<wchar_t*>(value.c_str()));
    ListView_SetItemText(list, row, 2, const_cast<wchar_t*>(raw.c_str()));
}

static void PopulateHeaders(HWND list, const PEParser& parser) {
    ListView_DeleteAllItems(list);
    if (!parser.IsValidPE()) {
        InsertHeaderRow(list, 0, 1, L"Error", L"Not a valid PE file", L"");
        return;
    }

    const auto& h = parser.GetHeaderInfo();
    int row = 0;

    auto addU16 = [&](int groupId, const wchar_t* name, WORD v) {
        InsertHeaderRow(list, row++, groupId, name, std::to_wstring(v), HexU32(v, 4));
    };
    auto addU32 = [&](int groupId, const wchar_t* name, DWORD v) {
        InsertHeaderRow(list, row++, groupId, name, std::to_wstring(v), HexU32(v, 8));
    };
    auto addU64 = [&](int groupId, const wchar_t* name, ULONGLONG v) {
        InsertHeaderRow(list, row++, groupId, name, std::to_wstring(v), HexU64(v, 16));
    };
    auto addByte = [&](int groupId, const wchar_t* name, BYTE v) {
        InsertHeaderRow(list, row++, groupId, name, std::to_wstring(v), HexU32(v, 2));
    };

    InsertHeaderRow(list, row++, 1, L"e_magic", (h.dosMagic == IMAGE_DOS_SIGNATURE) ? L"MZ" : L"(invalid)", HexU32(h.dosMagic, 4));
    addU16(1, L"e_cblp (Bytes on last page)", h.dosBytesOnLastPage);
    addU16(1, L"e_cp (Pages in file)", h.dosPagesInFile);
    addU16(1, L"e_crlc (Relocations)", h.dosRelocations);
    addU16(1, L"e_cparhdr (Size of header)", h.dosSizeOfHeader);
    addU16(1, L"e_minalloc (Min alloc)", h.dosMinAlloc);
    addU16(1, L"e_maxalloc (Max alloc)", h.dosMaxAlloc);
    addU16(1, L"e_ss (Initial SS)", h.dosInitialSS);
    addU16(1, L"e_sp (Initial SP)", h.dosInitialSP);
    addU16(1, L"e_csum (Checksum)", h.dosChecksum);
    addU16(1, L"e_ip (Initial IP)", h.dosInitialIP);
    addU16(1, L"e_cs (Initial CS)", h.dosInitialCS);
    addU16(1, L"e_lfarlc (Table of relocations)", h.dosTableOfRelocations);
    addU16(1, L"e_ovno (Overlay number)", h.dosOverlayNumber);
    addU16(1, L"e_oemid (OEM identifier)", h.dosOemIdentifier);
    addU16(1, L"e_oeminfo (OEM information)", h.dosOemInformation);
    InsertHeaderRow(list, row++, 1, L"e_lfanew (PE header offset)", std::to_wstring(h.dosPeHeaderOffset), HexU32(static_cast<DWORD>(h.dosPeHeaderOffset), 8));

    InsertHeaderRow(list, row++, 2, L"Signature", (h.peSignature == IMAGE_NT_SIGNATURE) ? L"PE\\0\\0" : L"(invalid)", HexU32(h.peSignature, 8));
    InsertHeaderRow(list, row++, 2, L"Machine", CoffMachineToName(h.machine), HexU32(h.machine, 4));
    addU32(2, L"NumberOfSections", h.numberOfSections);
    InsertHeaderRow(list, row++, 2, L"TimeDateStamp", FormatCoffTime(h.timeDateStamp, ReportTimeFormat::Local), HexU32(h.timeDateStamp, 8));
    addU32(2, L"PointerToSymbolTable", h.pointerToSymbolTable);
    addU32(2, L"NumberOfSymbols", h.numberOfSymbols);
    addU16(2, L"SizeOfOptionalHeader", h.sizeOfOptionalHeader);
    addU16(2, L"Characteristics", h.characteristics);

    InsertHeaderRow(list, row++, 3, L"Magic", (h.peOptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? L"PE32+" : L"PE32", HexU32(h.peOptionalMagic, 4));
    addByte(3, L"MajorLinkerVersion", h.majorLinkerVersion);
    addByte(3, L"MinorLinkerVersion", h.minorLinkerVersion);
    addU32(3, L"SizeOfCode", h.sizeOfCode);
    addU32(3, L"SizeOfInitializedData", h.sizeOfInitializedData);
    addU32(3, L"SizeOfUninitializedData", h.sizeOfUninitializedData);
    addU32(3, L"AddressOfEntryPoint", h.entryPoint);
    addU32(3, L"BaseOfCode", h.baseOfCode);
    if (h.peOptionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        addU32(3, L"BaseOfData", h.baseOfData);
    }
    addU64(3, L"ImageBase", h.imageBase);
    addU32(3, L"SectionAlignment", h.sectionAlignment);
    addU32(3, L"FileAlignment", h.fileAlignment);
    addU16(3, L"MajorOperatingSystemVersion", h.majorOperatingSystemVersion);
    addU16(3, L"MinorOperatingSystemVersion", h.minorOperatingSystemVersion);
    addU16(3, L"MajorImageVersion", h.majorImageVersion);
    addU16(3, L"MinorImageVersion", h.minorImageVersion);
    addU16(3, L"MajorSubsystemVersion", h.majorSubsystemVersion);
    addU16(3, L"MinorSubsystemVersion", h.minorSubsystemVersion);
    addU32(3, L"Win32VersionValue", h.win32VersionValue);
    addU32(3, L"SizeOfImage", h.sizeOfImage);
    addU32(3, L"SizeOfHeaders", h.sizeOfHeaders);
    addU32(3, L"CheckSum", h.checksum);
    InsertHeaderRow(list, row++, 3, L"Subsystem", ToWStringUtf8BestEffort(h.subsystem), HexU32(h.subsystemValue, 4));
    addU16(3, L"DllCharacteristics", h.dllCharacteristics);
    addU64(3, L"SizeOfStackReserve", h.sizeOfStackReserve);
    addU64(3, L"SizeOfStackCommit", h.sizeOfStackCommit);
    addU64(3, L"SizeOfHeapReserve", h.sizeOfHeapReserve);
    addU64(3, L"SizeOfHeapCommit", h.sizeOfHeapCommit);
    addU32(3, L"LoaderFlags", h.loaderFlags);
    addU32(3, L"NumberOfRvaAndSizes", h.numberOfRvaAndSizes);

    const wchar_t* dirNames[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
        L"Export",
        L"Import",
        L"Resource",
        L"Exception",
        L"Security",
        L"Base Relocation",
        L"Debug",
        L"Architecture",
        L"Global Ptr",
        L"TLS",
        L"Load Config",
        L"Bound Import",
        L"IAT",
        L"Delay Import",
        L"CLR Runtime",
        L"Reserved",
    };

    for (size_t i = 0; i < h.dataDirectories.size() && i < std::size(dirNames); ++i) {
        const auto& d = h.dataDirectories[i];
        std::wstring name = dirNames[i];
        name += L" Directory";
        InsertHeaderRow(list, row++, 4, name, HexU32(d.VirtualAddress, 8), HexU32(d.Size, 8));
    }
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

static void BuildExportRowsFromParser(std::vector<GuiState::ExportRow>& out, const PEParser& parser) {
    out.clear();

    const auto& exports = parser.GetExports();
    out.reserve(exports.size());
    for (const auto& e : exports) {
        GuiState::ExportRow r;
        r.ordinal = std::to_wstring(e.ordinal);
        r.rva = HexU32(e.rva, 8);
        r.offset = (e.fileOffset != 0) ? HexU32(e.fileOffset, 8) : L"";
        r.name = e.hasName ? ToWStringUtf8BestEffort(e.name) : L"(no-name)";
        r.forwarder = e.isForwarded ? ToWStringUtf8BestEffort(e.forwarder) : L"";
        r.haystackLower = ToLowerString(r.ordinal + L" " + r.rva + L" " + r.offset + L" " + r.name + L" " + r.forwarder);
        out.push_back(std::move(r));
    }
}

static std::wstring BuildExportsInfoText(const PEParser& parser) {
    if (!parser.IsValidPE()) {
        return L"Export Directory: (invalid)\r\n";
    }
    const auto& infoOpt = parser.GetExportDirectoryInfo();
    if (!infoOpt.has_value() || !infoOpt->present) {
        return L"Export Directory: (none)\r\n";
    }

    const auto& i = *infoOpt;
    std::wostringstream out;
    out << L"Export Directory\r\n";
    out << L"  DirectoryRva:  " << HexU32(i.directoryRva, 8) << L"  Size: " << HexU32(i.directorySize, 8) << L"\r\n";
    out << L"  DirectoryOff:  " << HexU32(i.directoryFileOffset, 8) << L"\r\n";
    out << L"  Characteristics: " << HexU32(i.characteristics, 8) << L"\r\n";
    out << L"  TimeDateStamp:   " << FormatCoffTime(i.timeDateStamp, ReportTimeFormat::Local) << L"  (" << HexU32(i.timeDateStamp, 8) << L")\r\n";
    out << L"  MajorVersion:    " << HexU32(i.majorVersion, 4) << L"\r\n";
    out << L"  MinorVersion:    " << HexU32(i.minorVersion, 4) << L"\r\n";
    out << L"  NameRva:         " << HexU32(i.nameRva, 8);
    if (i.nameFileOffset != 0) {
        out << L"  NameOff: " << HexU32(i.nameFileOffset, 8);
    }
    out << L"\r\n";
    out << L"  DllName:         " << ToWStringUtf8BestEffort(i.dllName) << L"\r\n";
    out << L"  Base:            " << i.base << L"  (" << HexU32(i.base, 8) << L")\r\n";
    out << L"  NumberOfFunctions: " << i.numberOfFunctions << L"  (" << HexU32(i.numberOfFunctions, 8) << L")\r\n";
    out << L"  NumberOfNames:     " << i.numberOfNames << L"  (" << HexU32(i.numberOfNames, 8) << L")\r\n";

    out << L"  AddressOfFunctions:      " << HexU32(i.addressOfFunctionsRva, 8);
    if (i.addressOfFunctionsFileOffset != 0) out << L"  Off: " << HexU32(i.addressOfFunctionsFileOffset, 8);
    out << L"\r\n";
    out << L"  AddressOfNames:          " << HexU32(i.addressOfNamesRva, 8);
    if (i.addressOfNamesFileOffset != 0) out << L"  Off: " << HexU32(i.addressOfNamesFileOffset, 8);
    out << L"\r\n";
    out << L"  AddressOfNameOrdinals:   " << HexU32(i.addressOfNameOrdinalsRva, 8);
    if (i.addressOfNameOrdinalsFileOffset != 0) out << L"  Off: " << HexU32(i.addressOfNameOrdinalsFileOffset, 8);
    out << L"\r\n";

    return out.str();
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

static void ApplyExportsFilterNow(GuiState* s) {
    if (!s->exportsFilterEdit) {
        return;
    }

    std::wstring q = GetControlText(s->exportsFilterEdit);
    std::wstring qLower = ToLowerString(q);
    std::vector<std::wstring> tokens = TokenizeQueryLower(qLower);

    ListView_DeleteAllItems(s->pageExports);
    int outRow = 0;
    for (const auto& r : s->exportsAllRows) {
        bool ok = true;
        for (const auto& t : tokens) {
            if (r.haystackLower.find(t) == std::wstring::npos) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            continue;
        }
        SetListViewText(s->pageExports, outRow, 0, r.ordinal);
        SetListViewText(s->pageExports, outRow, 1, r.rva);
        SetListViewText(s->pageExports, outRow, 2, r.offset);
        SetListViewText(s->pageExports, outRow, 3, r.name);
        SetListViewText(s->pageExports, outRow, 4, r.forwarder);
        ++outRow;
    }

    if (s->exportsInfo) {
        if (qLower.empty()) {
            SendMessageW(s->exportsInfo, EM_SETSEL, 0, 0);
        } else {
            int len = GetWindowTextLengthW(s->exportsInfo);
            if (len > 0) {
                std::wstring buf(static_cast<size_t>(len) + 1, L'\0');
                GetWindowTextW(s->exportsInfo, buf.data(), len + 1);
                std::wstring hayLower = ToLowerString(buf);
                size_t pos = hayLower.find(qLower);
                if (pos != std::wstring::npos) {
                    int start = static_cast<int>(pos);
                    int end = static_cast<int>(pos + qLower.size());
                    SendMessageW(s->exportsInfo, EM_SETSEL, start, end);
                    SendMessageW(s->exportsInfo, EM_SCROLLCARET, 0, 0);
                } else {
                    SendMessageW(s->exportsInfo, EM_SETSEL, 0, 0);
                }
            } else {
                SendMessageW(s->exportsInfo, EM_SETSEL, 0, 0);
            }
        }
    }
}

static std::wstring StringsTypeToText(StringsHitType t) {
    switch (t) {
        case StringsHitType::Ascii: return L"ascii";
        case StringsHitType::Utf16Le: return L"utf16le";
    }
    return L"unknown";
}

static int GetStringsMinLenClamped(GuiState* s) {
    if (!s || !s->stringsMinLenEdit) {
        return 5;
    }
    std::wstring v = GetControlText(s->stringsMinLenEdit);
    int n = 5;
    try {
        if (!v.empty()) {
            n = std::stoi(v);
        }
    } catch (...) {
        n = 5;
    }
    if (n < 5) n = 5;
    if (n > 64) n = 64;
    std::wstring normalized = std::to_wstring(n);
    if (v != normalized) {
        SetWindowTextWString(s->stringsMinLenEdit, normalized);
    }
    return n;
}

static int GetStringsTypeFilterIndex(const GuiState* s) {
    if (!s || !s->stringsTypeCombo) {
        return 0;
    }
    int sel = static_cast<int>(SendMessageW(s->stringsTypeCombo, CB_GETCURSEL, 0, 0));
    if (sel < 0) sel = 0;
    return sel;
}

static bool IsStringsUniqueEnabled(const GuiState* s) {
    if (!s || !s->stringsUniqueCheck) {
        return false;
    }
    return SendMessageW(s->stringsUniqueCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

static bool IsStringsRegexEnabled(const GuiState* s) {
    if (!s || !s->stringsRegexCheck) {
        return false;
    }
    return SendMessageW(s->stringsRegexCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

static std::wstring BuildStringsHistoryTagText(const StringsSearchHistoryEntry& e) {
    std::wstring text;
    if (e.pinned) {
        text += L"\u2605";
    }
    if (e.mode == StringsSearchMode::Regex) {
        text += L"re:";
    }
    text += e.query;
    return text;
}

static void UpdateStringsHistoryBar(GuiState* s) {
    if (!s || !s->stringsHistoryLabel || !s->stringsHistoryClearBtn) {
        return;
    }
    if (!IsWindowVisible(s->stringsSearchEdit)) {
        return;
    }
    s->stringsHistoryDisplay = s->stringsHistory.ListForDisplay();
    int maxVisible = s->stringsHistoryMaxTagsVisible;
    if (maxVisible < 0) maxVisible = 0;
    if (maxVisible > 8) maxVisible = 8;
    size_t shown = std::min<size_t>(static_cast<size_t>(maxVisible), s->stringsHistoryDisplay.size());
    for (int i = 0; i < 8; ++i) {
        if (static_cast<size_t>(i) < shown) {
            const auto& e = s->stringsHistoryDisplay[static_cast<size_t>(i)];
            SetWindowTextWString(s->stringsHistoryTags[i], BuildStringsHistoryTagText(e));
            ShowWindow(s->stringsHistoryTags[i], SW_SHOW);
        } else {
            ShowWindow(s->stringsHistoryTags[i], SW_HIDE);
        }
    }
    ShowWindow(s->stringsHistoryClearBtn, (!s->stringsHistoryDisplay.empty()) ? SW_SHOW : SW_HIDE);
}

static void UpdateStringsDisplayCount(GuiState* s) {
    if (!s || !s->pageStrings) {
        return;
    }
    size_t total = s->stringsVisibleAll.size();
    size_t displayLimit = total;
    if (displayLimit > kStringsUiMaxRows) {
        displayLimit = kStringsUiMaxRows;
    }
    int pageSize = s->stringsPageSize;
    if (pageSize <= 0) {
        pageSize = kStringsUiPageSize;
    }
    size_t pageSizeSz = static_cast<size_t>(pageSize);
    size_t pageCount = 0;
    if (displayLimit > 0 && pageSizeSz > 0) {
        pageCount = (displayLimit + pageSizeSz - 1) / pageSizeSz;
    }
    if (pageCount == 0) {
        s->stringsPageIndex = 0;
    } else if (static_cast<size_t>(s->stringsPageIndex) >= pageCount) {
        s->stringsPageIndex = 0;
    }
    s->stringsPageCount = static_cast<int>(pageCount);

    size_t pageStart = 0;
    size_t pageEnd = 0;
    if (pageCount > 0) {
        pageStart = static_cast<size_t>(s->stringsPageIndex) * pageSizeSz;
        if (pageStart > displayLimit) {
            pageStart = displayLimit;
        }
        pageEnd = pageStart + pageSizeSz;
        if (pageEnd > displayLimit) {
            pageEnd = displayLimit;
        }
    }

    s->stringsVisible.clear();
    if (pageEnd > pageStart) {
        s->stringsVisible.reserve(pageEnd - pageStart);
        for (size_t i = pageStart; i < pageEnd; ++i) {
            s->stringsVisible.push_back(s->stringsVisibleAll[i]);
        }
    }
    ListView_SetItemCountEx(s->pageStrings, static_cast<int>(s->stringsVisible.size()), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

    if (s->stringsPagePrev) {
        EnableWindow(s->stringsPagePrev, (pageCount > 0 && s->stringsPageIndex > 0) ? TRUE : FALSE);
    }
    if (s->stringsPageNext) {
        EnableWindow(s->stringsPageNext, (pageCount > 0 && (static_cast<size_t>(s->stringsPageIndex + 1) < pageCount)) ? TRUE : FALSE);
    }
    if (s->stringsPageLabel) {
        std::wostringstream out;
        if (displayLimit == 0) {
            out << L"0 / 0";
        } else {
            out << L"\u7b2c " << (s->stringsPageIndex + 1) << L" / " << pageCount << L" \u9875";
            out << L"  \u663e\u793a " << (pageStart + 1) << L"-" << pageEnd << L" / " << displayLimit;
            if (total > displayLimit) {
                out << L"  \u603b " << total;
            }
        }
        SetWindowTextWString(s->stringsPageLabel, out.str());
    }
}

static void ApplyStringsHistoryEntry(GuiState* s, const StringsSearchHistoryEntry& e) {
    if (!s) {
        return;
    }
    SetWindowTextWString(s->stringsSearchEdit, e.query);
    SendMessageW(s->stringsRegexCheck, BM_SETCHECK, (e.mode == StringsSearchMode::Regex) ? BST_CHECKED : BST_UNCHECKED, 0);
    int typeIdx = e.typeFilter;
    if (typeIdx < 0) typeIdx = 0;
    if (typeIdx > 2) typeIdx = 2;
    SendMessageW(s->stringsTypeCombo, CB_SETCURSEL, typeIdx, 0);
    SetWindowTextWString(s->stringsMinLenEdit, std::to_wstring(e.minLen));
    SendMessageW(s->stringsUniqueCheck, BM_SETCHECK, e.unique ? BST_CHECKED : BST_UNCHECKED, 0);
    ApplyStringsFilterNow(s);
}

static std::optional<int> GetSelectedStringsRowIndex(const GuiState* s) {
    if (!s || !s->pageStrings) {
        return std::nullopt;
    }
    int item = ListView_GetNextItem(s->pageStrings, -1, LVNI_SELECTED);
    if (item < 0) {
        return std::nullopt;
    }
    if (item >= static_cast<int>(s->stringsVisible.size())) {
        return std::nullopt;
    }
    return s->stringsVisible[static_cast<size_t>(item)];
}

static std::wstring FormatStringsDetailLine(const GuiState::StringsRow& r) {
    std::wostringstream out;
    out << L"Offset=" << HexU64(r.fileOffset, 8);
    if (!r.section.empty()) {
        out << L"  Section=" << r.section;
    }
    if (r.rva.has_value()) {
        out << L"  RVA=" << HexU32(*r.rva, 8);
    }
    if (r.va.has_value()) {
        out << L"  VA=" << HexU64(*r.va, 16);
    }
    out << L"  " << StringsTypeToText(r.type) << L"  Len=" << r.text.size();
    return out.str();
}

static void UpdateStringsDetail(GuiState* s) {
    (void)s;
}

static void ApplyStringsFilterNow(GuiState* s) {
    if (!s || !s->stringsSearchEdit || !s->pageStrings) {
        return;
    }

    if (s->stringsFilterRunning) {
        s->stringsFilterRunning = false;
        KillTimer(s->hwnd, kTimerStringsFilterWork);
    }
    ++s->stringsFilterGen;
    s->stringsFilterRunning = true;
    s->stringsFilterPos = 0;
    s->stringsFilterResult.clear();
    s->stringsFilterSeen.clear();
    s->stringsVisibleAll.clear();
    s->stringsVisible.clear();
    s->stringsPageIndex = 0;
    s->stringsPageCount = 0;
    UpdateStringsDisplayCount(s);

    std::wstring qRaw = GetControlText(s->stringsSearchEdit);
    bool useRegex = IsStringsRegexEnabled(s);
    s->stringsFilterUseRegex = useRegex;
    s->stringsFilterRegexValid = true;
    s->stringsFilterRegexPattern.clear();
    if (useRegex) {
        if (!qRaw.empty()) {
            try {
                s->stringsFilterRegex = std::wregex(qRaw, std::regex_constants::ECMAScript | std::regex_constants::icase);
                s->stringsFilterRegexPattern = qRaw;
            } catch (...) {
                s->stringsFilterRegexValid = false;
            }
        }
        s->stringsFilterTokens.clear();
        if (!s->stringsFilterRegexValid) {
            s->stringsFilterRunning = false;
            InvalidateRect(s->stringsSearchEdit, nullptr, TRUE);
            return;
        }
    } else {
        std::wstring qLower = ToLowerString(qRaw);
        s->stringsFilterTokens = TokenizeQueryLower(qLower);
    }
    s->stringsFilterMinLen = GetStringsMinLenClamped(s);
    s->stringsFilterType = GetStringsTypeFilterIndex(s);
    s->stringsFilterUnique = IsStringsUniqueEnabled(s);
    if (s->stringsFilterUnique) {
        s->stringsFilterSeen.reserve(std::min<size_t>(s->stringsAllRows.size(), 250000));
    }

    int nonSpace = 0;
    for (wchar_t ch : qRaw) {
        if (!iswspace(ch)) {
            ++nonSpace;
        }
    }
    if (nonSpace >= 2) {
        StringsSearchHistoryEntry he;
        he.mode = useRegex ? StringsSearchMode::Regex : StringsSearchMode::Plain;
        he.query = qRaw;
        he.typeFilter = s->stringsFilterType;
        he.minLen = s->stringsFilterMinLen;
        he.unique = s->stringsFilterUnique;
        s->stringsHistory.Record(he);
        s->stringsHistoryDirty = true;
        SetTimer(s->hwnd, kTimerStringsHistorySave, 1000, nullptr);
        UpdateStringsHistoryBar(s);
    }

    s->stringsVisible.clear();
    ListView_SetItemState(s->pageStrings, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemCountEx(s->pageStrings, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    UpdateStringsDetail(s);
    SetTimer(s->hwnd, kTimerStringsFilterWork, 1, nullptr);
}

static void ContinueStringsFilterWork(GuiState* s) {
    if (!s || !s->stringsFilterRunning) {
        return;
    }
    uint64_t start = GetTickCount64();
    size_t n = s->stringsAllRows.size();
    while (s->stringsFilterPos < n) {
        size_t i = s->stringsFilterPos++;
        const auto& r = s->stringsAllRows[i];
        if (static_cast<int>(r.text.size()) < s->stringsFilterMinLen) {
            goto next_item;
        }
        if (s->stringsFilterType == 1 && r.type != StringsHitType::Ascii) {
            goto next_item;
        }
        if (s->stringsFilterType == 2 && r.type != StringsHitType::Utf16Le) {
            goto next_item;
        }
        if (s->stringsFilterUseRegex) {
            if (!s->stringsFilterRegexPattern.empty()) {
                try {
                    if (!std::regex_search(r.text, s->stringsFilterRegex)) {
                        goto next_item;
                    }
                } catch (...) {
                    goto next_item;
                }
            }
        } else {
            for (const auto& t : s->stringsFilterTokens) {
                if (r.haystackLower.find(t) == std::wstring::npos) {
                    goto next_item;
                }
            }
        }
        if (s->stringsFilterUnique) {
            if (!s->stringsFilterSeen.insert(std::wstring_view(r.text)).second) {
                goto next_item;
            }
        }
        s->stringsFilterResult.push_back(static_cast<int>(i));
    next_item:
        if ((GetTickCount64() - start) >= 8) {
            break;
        }
    }

    if (s->stringsFilterPos < n) {
        return;
    }
    s->stringsFilterRunning = false;
    KillTimer(s->hwnd, kTimerStringsFilterWork);
    s->stringsVisibleAll = std::move(s->stringsFilterResult);
    s->stringsFilterResult.clear();
    s->stringsFilterSeen.clear();
    UpdateStringsDisplayCount(s);
    InvalidateRect(s->pageStrings, nullptr, TRUE);
    UpdateStringsDetail(s);
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

static std::wstring BasenameW(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

static std::wstring BuildPdbSymbolKey(const GUID& guid, DWORD age) {
    std::wstring guidStr = ToWStringUtf8BestEffort(FormatGuidLower(guid));
    std::wstring guidNoDashUpper;
    guidNoDashUpper.reserve(guidStr.size());
    for (wchar_t ch : guidStr) {
        if (ch == L'-') {
            continue;
        }
        guidNoDashUpper.push_back(static_cast<wchar_t>(towupper(ch)));
    }
    std::wostringstream out;
    out << guidNoDashUpper;
    out << std::hex << std::nouppercase;
    out << age;
    return out.str();
}

static std::wstring FormatAgeDecHex(DWORD age) {
    std::wostringstream out;
    out << age << L" (0x" << std::hex << std::nouppercase << age << L")";
    return out.str();
}

static void PopulatePdb(HWND edit, const GuiState* s) {
    std::wostringstream out;

    out << L"\u628a .pdb \u6587\u4ef6\u62d6\u5230\u7a97\u53e3\u91cc\uff0c\u5373\u53ef\u6838\u5bf9\u5b83\u662f\u5426\u5339\u914d\u5f53\u524d\u6587\u4ef6\u3002\r\n";
    out << L"\r\n";

    std::wstring verdict = L"\u5c1a\u672a\u6821\u9a8c\uff08\u62d6\u5165\u4e00\u4e2a PDB \u5f00\u59cb\uff09";
    if (!s || s->analysis == nullptr) {
        verdict = L"\u65e0\u6cd5\u6821\u9a8c\uff08\u8bf7\u5148\u6253\u5f00\u4e00\u4e2a EXE/DLL/SYS\uff09";
    } else if (!s->analysis->pdb.has_value() || !s->analysis->pdb->hasRsds) {
        if (!s->droppedPdbPath.empty()) {
            verdict = L"\u65e0\u6cd5\u5224\u65ad\uff08\u5f53\u524d\u6587\u4ef6\u4e0d\u5305\u542b RSDS \u8c03\u8bd5\u6807\u8bc6\uff09";
        } else {
            verdict = L"\u5c1a\u672a\u6821\u9a8c\uff08\u8be5\u6587\u4ef6\u4e0d\u5305\u542b RSDS\uff09";
        }
    } else if (!s->droppedPdbPath.empty()) {
        if (!s->droppedPdbError.empty()) {
            verdict = L"\u65e0\u6cd5\u6821\u9a8c\uff08PDB \u89e3\u6790\u5931\u8d25\uff09";
        } else if (s->droppedPdbInfo.has_value()) {
            const auto& pe = *s->analysis->pdb;
            const auto& pdb = *s->droppedPdbInfo;
            if (pe.guid == pdb.guid && pe.age == pdb.age) {
                verdict = L"\u5339\u914d";
            } else if (pe.guid != pdb.guid) {
                verdict = L"\u4e0d\u5339\u914d\uff08GUID \u4e0d\u540c\uff09";
            } else {
                verdict = L"\u4e0d\u5339\u914d\uff08Age \u4e0d\u540c\uff09";
            }
        }
    }

    out << L"\u7ed3\u8bba: " << verdict << L"\r\n";
    out << L"\r\n";

    out << L"\u2500\u2500 \u5f53\u524d\u6587\u4ef6\uff08PE\uff0cRSDS\uff09 \u2500\u2500\r\n";
    if (!s || s->analysis == nullptr) {
        out << L"(none)\r\n";
    } else if (s->analysis->pdb.has_value() && s->analysis->pdb->hasRsds) {
        const auto& pe = *s->analysis->pdb;
        std::wstring pePdbPath = ToWStringUtf8BestEffort(pe.pdbPath);
        std::wstring pePdbName = BasenameW(pePdbPath);
        out << L"GUID: " << ToWStringUtf8BestEffort(FormatGuidLower(pe.guid)) << L"\r\n";
        out << L"Age: " << FormatAgeDecHex(pe.age) << L"\r\n";
        out << L"Path: " << pePdbPath << L"\r\n";
        std::wstring key = BuildPdbSymbolKey(pe.guid, pe.age);
        out << L"Symbol key: " << key << L"\r\n";
        if (!pePdbName.empty()) {
            out << L"Symbol path: " << pePdbName << L"\\" << key << L"\\" << pePdbName << L"\r\n";
        }
    } else {
        out << L"(none)\r\n";
    }

    out << L"\r\n";
    out << L"\u2500\u2500 \u6700\u8fd1\u62d6\u5165\u7684 PDB \u2500\u2500\r\n";
    if (!s || s->droppedPdbPath.empty()) {
        out << L"(none)\r\n";
    } else {
        out << L"Path: " << s->droppedPdbPath << L"\r\n";
        if (!s->droppedPdbError.empty()) {
            out << L"Error: " << s->droppedPdbError << L"\r\n";
        } else if (s->droppedPdbInfo.has_value()) {
            const auto& pdb = *s->droppedPdbInfo;
            out << L"GUID: " << ToWStringUtf8BestEffort(FormatGuidLower(pdb.guid)) << L"\r\n";
            out << L"Age: " << FormatAgeDecHex(pdb.age) << L"\r\n";
            std::wstring key = BuildPdbSymbolKey(pdb.guid, pdb.age);
            out << L"Symbol key: " << key << L"\r\n";
            if (!pdb.fileName.empty()) {
                out << L"Symbol path: " << pdb.fileName << L"\\" << key << L"\\" << pdb.fileName << L"\r\n";
            }
        } else {
            out << L"(none)\r\n";
        }
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
    bool firstBlock = true;
    auto beginBlock = [&]() {
        if (!firstBlock) {
            out << L"\r\n";
        }
        firstBlock = false;
    };

    if (ar.embeddedVerify.has_value()) {
        beginBlock();
        out << L"Embedded:\r\n";
        out << L"Status: " << VerifyStatusToString(ar.embeddedVerify->status) << L" (0x" << std::hex << ar.embeddedVerify->winVerifyTrustStatus << std::dec << L")\r\n";
        AppendSigner(out, ar.embeddedVerify->signer);
    }
    if (ar.catalogVerify.has_value()) {
        beginBlock();
        out << L"Catalog:\r\n";
        out << L"Status: " << VerifyStatusToString(ar.catalogVerify->status) << L" (0x" << std::hex << ar.catalogVerify->winVerifyTrustStatus << std::dec << L")\r\n";
        if (!ar.catalogVerify->catalogPath.empty()) {
            out << L"CatalogFile: " << ar.catalogVerify->catalogPath << L"\r\n";
        }
        AppendSigner(out, ar.catalogVerify->signer);
    }
    if (!ar.embeddedVerify.has_value() && !ar.catalogVerify.has_value()) {
        beginBlock();
        out << L"\u9a8c\u8bc1\uff1a" << (verifying ? L"\u8fdb\u884c\u4e2d..." : L"\u672a\u6267\u884c") << L"\r\n";
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
    HFONT hintFont = nullptr;
    HBRUSH bgBrush = nullptr;
    UINT dpi = 96;
};

static void GetSettingsDialogWindowSizeForDpi(UINT dpi, int& w, int& h) {
    int padY = MulDiv(16, static_cast<int>(dpi), 96);
    int rowGap = MulDiv(10, static_cast<int>(dpi), 96);
    int chkH = MulDiv(24, static_cast<int>(dpi), 96);
    int hintH = MulDiv(24, static_cast<int>(dpi), 96);
    int btnH = MulDiv(32, static_cast<int>(dpi), 96);
    int gapAfterHint = MulDiv(16, static_cast<int>(dpi), 96);

    int clientW = MulDiv(560, static_cast<int>(dpi), 96);
    int clientH = padY + chkH + rowGap + hintH + gapAfterHint + btnH + padY;

    RECT rc = {0, 0, clientW, clientH};
    DWORD style = WS_CAPTION | WS_SYSMENU;
    DWORD exStyle = WS_EX_DLGMODALFRAME;

    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using AdjustWindowRectExForDpiFn = BOOL(WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
        auto fn = reinterpret_cast<AdjustWindowRectExForDpiFn>(GetProcAddress(user32, "AdjustWindowRectExForDpi"));
        if (fn && fn(&rc, style, FALSE, exStyle, dpi)) {
            w = rc.right - rc.left;
            h = rc.bottom - rc.top;
            return;
        }
    }
    AdjustWindowRectEx(&rc, style, FALSE, exStyle);
    w = rc.right - rc.left;
    h = rc.bottom - rc.top;
}

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
            s->bgBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
            if (s->uiFont) {
                LOGFONTW lf = {};
                if (GetObjectW(s->uiFont, sizeof(lf), &lf) == sizeof(lf)) {
                    LONG delta = static_cast<LONG>(MulDiv(2, static_cast<int>(s->dpi), 96));
                    if (lf.lfHeight < 0) {
                        lf.lfHeight = (std::min)(lf.lfHeight + delta, static_cast<LONG>(-1));
                    } else if (lf.lfHeight > 0) {
                        lf.lfHeight = (std::max)(lf.lfHeight - delta, static_cast<LONG>(1));
                    }
                    s->hintFont = CreateFontIndirectW(&lf);
                }
            }

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
                                    L"\u63d0\u793a\uff1aWindows 11 \u4e2d\u8be5\u83dc\u5355\u9879\u53ef\u80fd\u4f4d\u4e8e\u201c\u663e\u793a\u66f4\u591a\u9009\u9879\u201d",
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
            if (s->hintFont) {
                SendMessageW(s->info, WM_SETFONT, reinterpret_cast<WPARAM>(s->hintFont), TRUE);
            }
            return 0;
        }
        case WM_CTLCOLORBTN: {
            if (reinterpret_cast<HWND>(lParam) != s->chkContextMenu || !s->bgBrush) {
                break;
            }
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetBkMode(dc, TRANSPARENT);
            return reinterpret_cast<INT_PTR>(s->bgBrush);
        }
        case WM_CTLCOLORSTATIC: {
            if (!s->bgBrush) {
                break;
            }
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetBkMode(dc, TRANSPARENT);
            if (reinterpret_cast<HWND>(lParam) == s->info) {
                SetTextColor(dc, GetSysColor(COLOR_GRAYTEXT));
                return reinterpret_cast<INT_PTR>(s->bgBrush);
            }
            break;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDOK: {
                    bool enable = (SendMessageW(s->chkContextMenu, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    std::wstring err;
                    if (enable) {
                        std::wstring guiPath = GetSelfExePath();
                        if (guiPath.empty()) {
                            MessageBoxError(hwnd, L"\u83b7\u53d6\u7a0b\u5e8f\u8def\u5f84\u5931\u8d25");
                            return 0;
                        }
                        if (!InstallPeInfoShellContextMenuForCurrentUser(guiPath, err)) {
                            MessageBoxError(hwnd, err.empty() ? L"\u5b89\u88c5\u53f3\u952e\u83dc\u5355\u5931\u8d25" : err);
                            return 0;
                        }
                        MessageBoxW(hwnd,
                                    s->installedBefore ? L"\u5df2\u66f4\u65b0\u53f3\u952e\u83dc\u5355" : L"\u5df2\u5b89\u88c5\u53f3\u952e\u83dc\u5355",
                                    L"\u8bbe\u7f6e",
                                    MB_OK | MB_ICONINFORMATION);
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
            if (s->hintFont) {
                DeleteObject(s->hintFont);
                s->hintFont = nullptr;
            }
            if (s->bgBrush) {
                DeleteObject(s->bgBrush);
                s->bgBrush = nullptr;
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
    int w = 0;
    int h = 0;
    GetSettingsDialogWindowSizeForDpi(dpi, w, h);
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
    HWND pages[] = {s->pageSummary,
                    s->pageHeaders,
                    s->pageSections,
                    s->pageImports,
                    s->pageExports,
                    s->pageStrings,
                    s->pageResources,
                    s->pagePdb,
                    s->pageSignature,
                    s->pageHash,
                    s->pageAbout};
    for (int i = 0; i < static_cast<int>(std::size(pages)); ++i) {
        ShowWindow(pages[i], (i == static_cast<int>(idx)) ? SW_SHOW : SW_HIDE);
    }
    bool showImportsFilter = (idx == TabIndex::Imports);
    ShowWindow(s->pageImportsDlls, showImportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->importsFilterLabel, showImportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->importsFilterEdit, showImportsFilter ? SW_SHOW : SW_HIDE);
    bool showExportsFilter = (idx == TabIndex::Exports);
    ShowWindow(s->exportsFilterLabel, showExportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->exportsFilterEdit, showExportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->exportsInfo, showExportsFilter ? SW_SHOW : SW_HIDE);
    ShowWindow(s->exportsSeparator, showExportsFilter ? SW_SHOW : SW_HIDE);
    bool showStringsControls = (idx == TabIndex::Strings);
    ShowWindow(s->stringsSearchLabel, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsSearchEdit, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsRegexCheck, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsTypeLabel, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsTypeCombo, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsMinLenLabel, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsMinLenEdit, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsUniqueCheck, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsHistoryLabel, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsPagePrev, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsPageNext, showStringsControls ? SW_SHOW : SW_HIDE);
    ShowWindow(s->stringsPageLabel, showStringsControls ? SW_SHOW : SW_HIDE);
    if (!showStringsControls) {
        for (HWND h : s->stringsHistoryTags) {
            ShowWindow(h, SW_HIDE);
        }
        ShowWindow(s->stringsHistoryClearBtn, SW_HIDE);
    }
    if (showImportsFilter) {
        FitImportsDllColumns(s);
        FitImportsFuncColumns(s);
        InvalidateRect(s->pageImportsDlls, nullptr, TRUE);
        InvalidateRect(s->pageImports, nullptr, TRUE);
    }
    if (showStringsControls) {
        UpdateStringsHistoryBar(s);
        if (s->stringsVisible.empty() && !s->stringsAllRows.empty()) {
            ApplyStringsFilterNow(s);
        } else {
            InvalidateRect(s->pageStrings, nullptr, TRUE);
            UpdateStringsDetail(s);
        }
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
    SetWindowTextWString(s->aboutInfo, BuildAboutText());
    if (s->analysis == nullptr) {
        std::wstring hint = L"\u62d6\u62fd EXE/DLL/SYS \u5230\u7a97\u53e3";
        SetWindowTextWString(s->pageSummary, hint);
        ListView_DeleteAllItems(s->pageHeaders);
        ListView_DeleteAllItems(s->pageSections);
        ListView_DeleteAllItems(s->pageImportsDlls);
        ListView_DeleteAllItems(s->pageImports);
        ListView_DeleteAllItems(s->pageExports);
        SetWindowTextWString(s->exportsInfo, L"");
        ListView_SetItemCountEx(s->pageStrings, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
        s->importsAllRows.clear();
        s->exportsAllRows.clear();
        s->stringsAllRows.clear();
        s->stringsVisible.clear();
        s->stringsVisibleAll.clear();
        s->stringsPageIndex = 0;
        s->stringsPageCount = 0;
        if (s->stringsFilterRunning) {
            s->stringsFilterRunning = false;
            KillTimer(s->hwnd, kTimerStringsFilterWork);
        }
        SetWindowTextWString(s->pageResources, hint);
        PopulatePdb(s->pagePdb, s);
        SetWindowTextWString(s->pageSignature, L"");
        SetWindowTextWString(s->pageHash, L"");
        UpdateStringsDisplayCount(s);
        UpdateFileInfo(s);
        return;
    }

    SetWindowTextWString(s->pageSummary, FormatSummaryText(*s->analysis));
    PopulateHeaders(s->pageHeaders, s->analysis->parser);
    PopulateSections(s->pageSections, s->analysis->parser);
    BuildImportRowsFromParser(s->importsAllRows, s->analysis->parser);
    ApplyImportsFilterNow(s);
    SetWindowTextWString(s->exportsInfo, BuildExportsInfoText(s->analysis->parser));
    BuildExportRowsFromParser(s->exportsAllRows, s->analysis->parser);
    ApplyExportsFilterNow(s);
    PopulateResources(s->pageResources, s->analysis->parser);
    PopulatePdb(s->pagePdb, s);
    PopulateSignature(s->pageSignature, *s->analysis, IsVerifyInFlightForCurrent(s));
    PopulateHash(s->pageHash, s->analysis->hashes);
    UpdateFileInfo(s);
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

static unsigned __stdcall StringsThreadProc(void* param) {
    auto* pl = reinterpret_cast<StringsScanPayload*>(param);
    HWND hwnd = pl->hwnd;
    std::wstring filePath = pl->filePath;
    std::atomic<bool>* cancel = pl->cancel;
    StringsScanOptions opt = pl->opt;
    delete pl;

    auto* msg = new StringsResultMessage();
    msg->filePath = filePath;
    msg->cancel = cancel;
    msg->hitLimit = opt.maxHits;
    msg->minLen = opt.minLen;
    msg->scanAscii = opt.scanAscii;
    msg->scanUtf16Le = opt.scanUtf16Le;

    std::wstring err;
    if (!ScanStringsFromFile(filePath, opt, msg->hits, err, cancel, {}, &msg->truncated)) {
        msg->ok = false;
        msg->error = err.empty() ? L"\u626b\u63cf\u5931\u8d25" : err;
    } else {
        msg->ok = true;
    }

    PostMessageW(hwnd, WM_APP_STRINGS_DONE, 0, reinterpret_cast<LPARAM>(msg));
    return 0;
}

static unsigned __stdcall StringsRowsBuildThreadProc(void* param) {
    auto* pl = reinterpret_cast<StringsRowsBuildPayload*>(param);
    HWND hwnd = pl->hwnd;
    auto* msg = new StringsRowsResultMessage();
    msg->filePath = pl->filePath;

    try {
        msg->rows.clear();
        msg->rows.reserve(pl->hits.size());
        for (const auto& h : pl->hits) {
            GuiState::StringsRow r;
            r.fileOffset = h.fileOffset;
            r.type = h.type;
            r.fileOffsetHex = HexU64(h.fileOffset, 8);
            r.typeText = StringsTypeToText(r.type);
            r.text = h.text;
            r.lenText = std::to_wstring(r.text.size());

            for (const auto& sec : pl->sections) {
                if (sec.rawSize == 0) {
                    continue;
                }
                uint64_t rawStart = sec.rawAddress;
                uint64_t rawEnd = rawStart + sec.rawSize;
                if (h.fileOffset < rawStart || h.fileOffset >= rawEnd) {
                    continue;
                }
                uint64_t delta = h.fileOffset - rawStart;
                DWORD rva = sec.virtualAddress + static_cast<DWORD>(delta);
                r.section = ToWStringUtf8BestEffort(sec.name);
                r.rva = rva;
                r.va = pl->imageBase + static_cast<ULONGLONG>(rva);
                break;
            }

            r.haystackLower = ToLowerString(r.section + L" " + r.typeText + L" " + r.text);
            msg->rows.push_back(std::move(r));
        }
        msg->ok = true;
    } catch (...) {
        msg->ok = false;
        msg->error = L"\u5904\u7406\u5931\u8d25";
    }

    PostMessageW(hwnd, WM_APP_STRINGS_ROWS_DONE, 0, reinterpret_cast<LPARAM>(msg));
    delete pl;
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
    s->droppedPdbPath.clear();
    s->droppedPdbInfo.reset();
    s->droppedPdbError.clear();
    if (s->stringsCancel) {
        s->stringsCancel->store(true);
    }
    s->stringsAllRows.clear();
    s->stringsVisible.clear();
    if (s->stringsFilterRunning) {
        s->stringsFilterRunning = false;
        KillTimer(s->hwnd, kTimerStringsFilterWork);
    }
    if (s->pageStrings) {
        ListView_SetItemCountEx(s->pageStrings, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    }
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

static void StartStringsScan(GuiState* s) {
    if (!s || s->currentFile.empty() || !s->pageStrings) {
        return;
    }
    if (s->stringsCancel) {
        s->stringsCancel->store(true);
    }
    s->stringsAllRows.clear();
    s->stringsVisible.clear();
    s->stringsVisibleAll.clear();
    s->stringsPageIndex = 0;
    s->stringsPageCount = 0;
    if (s->stringsFilterRunning) {
        s->stringsFilterRunning = false;
        KillTimer(s->hwnd, kTimerStringsFilterWork);
    }
    ListView_SetItemCountEx(s->pageStrings, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    UpdateStringsDetail(s);
    UpdateStringsDisplayCount(s);
 

    StringsScanOptions opt;
    opt.minLen = GetStringsMinLenClamped(s);
    opt.maxLen = 4096;
    int typeIdx = GetStringsTypeFilterIndex(s);
    opt.scanAscii = (typeIdx != 2);
    opt.scanUtf16Le = (typeIdx != 1);
    opt.maxHits = 3000000;

    auto* cancel = new std::atomic<bool>(false);
    s->stringsCancel = cancel;
    auto* payload = new StringsScanPayload();
    payload->hwnd = s->hwnd;
    payload->filePath = s->currentFile;
    payload->cancel = cancel;
    payload->opt = opt;
    uintptr_t th = _beginthreadex(nullptr, 0, StringsThreadProc, payload, 0, nullptr);
    if (th == 0) {
        delete payload;
        if (s->stringsCancel == cancel) {
            s->stringsCancel = nullptr;
        }
        delete cancel;
        MessageBoxError(s->hwnd, L"\u542f\u52a8\u626b\u63cf\u7ebf\u7a0b\u5931\u8d25");
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
    ofn.lpstrFilter = L"PE Files (*.exe;*.dll;*.sys;*.ocx;*.node;*.cpl;*.scr;*.efi)\0*.exe;*.dll;*.sys;*.ocx;*.node;*.cpl;*.scr;*.efi\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
        return {};
    }
    return fileName;
}

static std::wstring GetBaseNameFromPath(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

static std::wstring PromptSaveFile(HWND hwnd, const std::wstring& defaultName, const wchar_t* filter, const wchar_t* defExt) {
    wchar_t fileName[MAX_PATH] = {};
    wcsncpy_s(fileName, defaultName.c_str(), _TRUNCATE);
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrDefExt = defExt;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) {
        return {};
    }
    return fileName;
}

static std::vector<const GuiState::StringsRow*> GetStringsRowsForSelectionOrVisible(const GuiState* s) {
    std::vector<const GuiState::StringsRow*> out;
    if (!s || !s->pageStrings) {
        return out;
    }
    int item = -1;
    while (true) {
        item = ListView_GetNextItem(s->pageStrings, item, LVNI_SELECTED);
        if (item < 0) {
            break;
        }
        if (item >= static_cast<int>(s->stringsVisible.size())) {
            continue;
        }
        int idx = s->stringsVisible[static_cast<size_t>(item)];
        if (idx < 0 || idx >= static_cast<int>(s->stringsAllRows.size())) {
            continue;
        }
        out.push_back(&s->stringsAllRows[static_cast<size_t>(idx)]);
    }
    if (!out.empty()) {
        return out;
    }
    out.reserve(s->stringsVisible.size());
    for (int idx : s->stringsVisible) {
        if (idx < 0 || idx >= static_cast<int>(s->stringsAllRows.size())) {
            continue;
        }
        out.push_back(&s->stringsAllRows[static_cast<size_t>(idx)]);
    }
    return out;
}

static std::wstring BuildStringsExportText(const std::vector<const GuiState::StringsRow*>& rows) {
    std::wostringstream out;
    for (const auto* r : rows) {
        if (!r) continue;
        out << HexU64(r->fileOffset, 8) << L"  " << StringsTypeToText(r->type) << L"  len=" << r->text.size();
        if (!r->section.empty()) {
            out << L"  section=" << r->section;
        }
        if (r->rva.has_value()) {
            out << L"  rva=" << HexU32(*r->rva, 8);
        }
        if (r->va.has_value()) {
            out << L"  va=" << HexU64(*r->va, 16);
        }
        out << L"  " << r->text << L"\r\n";
    }
    return out.str();
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char ch : s) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[7] = {};
                    sprintf_s(buf, "\\u%04x", static_cast<unsigned int>(ch));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }
    return out;
}

static std::string BuildStringsExportJson(const std::vector<const GuiState::StringsRow*>& rows) {
    std::ostringstream out;
    out << "{\n  \"strings\": [\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto* r = rows[i];
        if (!r) continue;
        std::string textUtf8 = WStringToUtf8(r->text);
        std::string secUtf8 = WStringToUtf8(r->section);
        out << "    {";
        out << "\"type\":\"" << (r->type == StringsHitType::Ascii ? "ascii" : "utf16le") << "\",";
        out << "\"text\":\"" << JsonEscape(textUtf8) << "\",";
        out << "\"length\":" << r->text.size() << ",";
        out << "\"fileOffset\":" << r->fileOffset << ",";
        out << "\"fileOffsetHex\":\"" << WStringToUtf8(HexU64(r->fileOffset, 8)) << "\"";
        if (!r->section.empty()) {
            out << ",\"section\":\"" << JsonEscape(secUtf8) << "\"";
        }
        if (r->rva.has_value()) {
            out << ",\"rvaHex\":\"" << WStringToUtf8(HexU32(*r->rva, 8)) << "\"";
        }
        if (r->va.has_value()) {
            out << ",\"vaHex\":\"" << WStringToUtf8(HexU64(*r->va, 16)) << "\"";
        }
        out << "}";
        if (i + 1 < rows.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "  ]\n}\n";
    return out.str();
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
    MoveWindow(s->pageHeaders, pageRc.left, pageRc.top, pageW, pageH, TRUE);
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
    MoveWindow(s->exportsFilterLabel, filterX, filterY, filterLabelW, filterH, TRUE);
    MoveWindow(s->exportsFilterEdit, filterEditX, filterY, filterEditW, filterH, TRUE);

    int stringsBarY = pageRc.top;
    int stringsBarH = filterH;
    int stringsHistoryGapY = MulDiv(6, static_cast<int>(s->dpi), 96);
    int stringsHistoryY = stringsBarY + stringsBarH + stringsHistoryGapY;
    int stringsHistoryH = filterH;
    int stringsPageBarGapY = MulDiv(6, static_cast<int>(s->dpi), 96);
    int stringsPageBarH = filterH;
    int stringsListY = stringsHistoryY + stringsHistoryH + pad;
    int stringsListH = pageH - (stringsBarH + stringsHistoryGapY + stringsHistoryH + pad + stringsPageBarGapY + stringsPageBarH);
    if (stringsListH < MulDiv(80, static_cast<int>(s->dpi), 96)) {
        stringsListH = MulDiv(80, static_cast<int>(s->dpi), 96);
    }
    int stringsPageBarY = stringsListY + stringsListH + stringsPageBarGapY;

    int stringsIconW = filterLabelW;
    int typeLabelW = MulDiv(46, static_cast<int>(s->dpi), 96);
    int minLenLabelW = MulDiv(86, static_cast<int>(s->dpi), 96);
    int labelGap = MulDiv(6, static_cast<int>(s->dpi), 96);
    int typeW = MulDiv(110, static_cast<int>(s->dpi), 96);
    int minLenW = MulDiv(56, static_cast<int>(s->dpi), 96);
    int uniqueW = MulDiv(74, static_cast<int>(s->dpi), 96);
    int regexW = MulDiv(70, static_cast<int>(s->dpi), 96);
    int stringsBarGap = pad;
    int fixedW = stringsIconW + stringsBarGap +
                 regexW + stringsBarGap +
                 typeLabelW + labelGap + typeW + stringsBarGap +
                 minLenLabelW + labelGap + minLenW + stringsBarGap +
                 uniqueW;
    int stringsSearchW = pageW - fixedW;
    if (stringsSearchW < MulDiv(120, static_cast<int>(s->dpi), 96)) {
        stringsSearchW = MulDiv(120, static_cast<int>(s->dpi), 96);
    }
    int stringsSearchX = pageRc.left;
    int stringsIconX = stringsSearchX;
    int stringsSearchEditX = stringsIconX + stringsIconW + stringsBarGap;
    int stringsRegexX = stringsSearchEditX + stringsSearchW + stringsBarGap;
    int stringsTypeLabelX = stringsRegexX + regexW + stringsBarGap;
    int stringsTypeComboX = stringsTypeLabelX + typeLabelW + labelGap;
    int stringsMinLenLabelX = stringsTypeComboX + typeW + stringsBarGap;
    int stringsMinLenEditX = stringsMinLenLabelX + minLenLabelW + labelGap;
    int stringsUniqueX = stringsMinLenEditX + minLenW + stringsBarGap;

    MoveWindow(s->stringsSearchLabel, stringsIconX, stringsBarY, stringsIconW, stringsBarH, TRUE);
    MoveWindow(s->stringsSearchEdit, stringsSearchEditX, stringsBarY, stringsSearchW, stringsBarH, TRUE);
    MoveWindow(s->stringsRegexCheck, stringsRegexX, stringsBarY, regexW, stringsBarH, TRUE);
    MoveWindow(s->stringsTypeLabel, stringsTypeLabelX, stringsBarY, typeLabelW, stringsBarH, TRUE);
    MoveWindow(s->stringsTypeCombo, stringsTypeComboX, stringsBarY, typeW, stringsBarH, TRUE);
    MoveWindow(s->stringsMinLenLabel, stringsMinLenLabelX, stringsBarY, minLenLabelW, stringsBarH, TRUE);
    MoveWindow(s->stringsMinLenEdit, stringsMinLenEditX, stringsBarY, minLenW, stringsBarH, TRUE);
    MoveWindow(s->stringsUniqueCheck, stringsUniqueX, stringsBarY, uniqueW, stringsBarH, TRUE);

    int historyGap = MulDiv(6, static_cast<int>(s->dpi), 96);
    int historyLabelW = MulDiv(46, static_cast<int>(s->dpi), 96);
    int historyClearW = MulDiv(64, static_cast<int>(s->dpi), 96);
    int historyLabelX = pageRc.left;
    int historyLabelY = stringsHistoryY;
    int historyRightX = pageRc.left + pageW;
    int historyClearX = historyRightX - historyClearW;
    int historyTagsX = historyLabelX + historyLabelW + historyGap;
    int historyTagsW = historyClearX - historyGap - historyTagsX;
    int historyTagW = MulDiv(120, static_cast<int>(s->dpi), 96);
    int historyTagGap = historyGap;
    int maxFit = 0;
    if (historyTagsW > 0) {
        maxFit = (historyTagsW + historyTagGap) / (historyTagW + historyTagGap);
        if (maxFit < 0) maxFit = 0;
        if (maxFit > 8) maxFit = 8;
    }
    s->stringsHistoryMaxTagsVisible = maxFit;

    MoveWindow(s->stringsHistoryLabel, historyLabelX, historyLabelY, historyLabelW, stringsHistoryH, TRUE);
    MoveWindow(s->stringsHistoryClearBtn, historyClearX, historyLabelY, historyClearW, stringsHistoryH, TRUE);
    for (int i = 0; i < 8; ++i) {
        int x = historyTagsX + i * (historyTagW + historyTagGap);
        MoveWindow(s->stringsHistoryTags[i], x, historyLabelY, historyTagW, stringsHistoryH, TRUE);
    }

    int pageGap = MulDiv(6, static_cast<int>(s->dpi), 96);
    int pageBtnW = MulDiv(72, static_cast<int>(s->dpi), 96);
    int pageLabelW = MulDiv(200, static_cast<int>(s->dpi), 96);
    int pageRightX = pageRc.left + pageW;
    int pageNextX = pageRightX - pageBtnW;
    int pagePrevX = pageNextX - pageGap - pageBtnW;
    int pageLabelX = pagePrevX - pageGap - pageLabelW;
    if (pageLabelX < pageRc.left) {
        pageLabelX = pageRc.left;
        pageLabelW = pagePrevX - pageGap - pageLabelX;
        if (pageLabelW < 0) pageLabelW = 0;
    }
    MoveWindow(s->stringsPagePrev, pagePrevX, stringsPageBarY, pageBtnW, stringsPageBarH, TRUE);
    MoveWindow(s->stringsPageNext, pageNextX, stringsPageBarY, pageBtnW, stringsPageBarH, TRUE);
    MoveWindow(s->stringsPageLabel, pageLabelX, stringsPageBarY, pageLabelW, stringsPageBarH, TRUE);

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
    int exportsInfoMinH = MulDiv(60, static_cast<int>(s->dpi), 96);
    int exportsInfoH = MulDiv(140, static_cast<int>(s->dpi), 96);
    int exportsListMinH = MulDiv(80, static_cast<int>(s->dpi), 96);
    int sepH = MulDiv(2, static_cast<int>(s->dpi), 96);
    int sepGapY = MulDiv(8, static_cast<int>(s->dpi), 96);
    if (sepH < 2) sepH = 2;
    if (exportsInfoH < exportsInfoMinH) exportsInfoH = exportsInfoMinH;

    int exportsInfoY = pageRc.top;
    int exportsSearchY = exportsInfoY + exportsInfoH + sepGapY + sepH + sepGapY;
    int exportsListY = exportsSearchY + filterH + pad;
    int exportsListH = pageH - (exportsListY - pageRc.top);
    if (exportsListH < exportsListMinH) {
        exportsInfoH = pageH - (sepGapY + sepH + sepGapY + filterH + pad + exportsListMinH);
        if (exportsInfoH < exportsInfoMinH) exportsInfoH = exportsInfoMinH;
        exportsSearchY = exportsInfoY + exportsInfoH + sepGapY + sepH + sepGapY;
        exportsListY = exportsSearchY + filterH + pad;
        exportsListH = pageH - (exportsListY - pageRc.top);
    }
    if (exportsListH < 0) exportsListH = 0;

    int exportsSepY = exportsInfoY + exportsInfoH + sepGapY;
    MoveWindow(s->exportsInfo, pageRc.left, exportsInfoY, pageW, exportsInfoH, TRUE);
    MoveWindow(s->exportsSeparator, pageRc.left, exportsSepY, pageW, sepH, TRUE);
    MoveWindow(s->exportsFilterLabel, filterX, exportsSearchY, filterLabelW, filterH, TRUE);
    MoveWindow(s->exportsFilterEdit, filterEditX, exportsSearchY, filterEditW, filterH, TRUE);
    MoveWindow(s->pageExports, pageRc.left, exportsListY, pageW, exportsListH, TRUE);
    MoveWindow(s->pageStrings, pageRc.left, stringsListY, pageW, stringsListH, TRUE);
    MoveWindow(s->pageResources, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pagePdb, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageSignature, pageRc.left, pageRc.top, pageW, pageH, TRUE);

    MoveWindow(s->pageHash, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageAbout, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    if (s->pageAbout) {
        RECT arc = {};
        GetClientRect(s->pageAbout, &arc);
        int aw = arc.right - arc.left;
        int apad = MulDiv(12, static_cast<int>(s->dpi), 96);
        int agap = MulDiv(10, static_cast<int>(s->dpi), 96);
        int infoH = MulDiv(94, static_cast<int>(s->dpi), 96);
        int linkH = MulDiv(24, static_cast<int>(s->dpi), 96);
        int contentW = aw - 2 * apad;
        if (contentW < MulDiv(120, static_cast<int>(s->dpi), 96)) {
            contentW = MulDiv(120, static_cast<int>(s->dpi), 96);
        }
        MoveWindow(s->aboutInfo, apad, apad, contentW, infoH, TRUE);
        MoveWindow(s->aboutLink, apad, apad + infoH + agap, contentW, linkH, TRUE);
    }

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
        s->fileInfo,
        s->tab,
        s->pageSummary,
        s->pageHeaders,
        s->pageSections,
        s->pageImportsDlls,
        s->pageImports,
        s->pageExports,
        s->pageStrings,
        s->pageResources,
        s->pagePdb,
        s->pageSignature,
        s->pageHash,
        s->pageAbout,
        s->aboutInfo,
        s->aboutLink,
        s->importsFilterLabel,
        s->importsFilterEdit,
        s->exportsFilterLabel,
        s->exportsFilterEdit,
        s->exportsInfo,
        s->stringsSearchLabel,
        s->stringsSearchEdit,
        s->stringsRegexCheck,
        s->stringsTypeLabel,
        s->stringsTypeCombo,
        s->stringsMinLenLabel,
        s->stringsMinLenEdit,
        s->stringsUniqueCheck,
        s->stringsHistoryLabel,
        s->stringsHistoryClearBtn,
        s->stringsPagePrev,
        s->stringsPageNext,
        s->stringsPageLabel,
    };
    for (HWND hwnd : controls) {
        if (hwnd) {
            SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(s->uiFont), TRUE);
        }
    }
    for (HWND hwnd : s->stringsHistoryTags) {
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
    if (s->exportsFilterLabel && s->iconFont) {
        SendMessageW(s->exportsFilterLabel, WM_SETFONT, reinterpret_cast<WPARAM>(s->iconFont), TRUE);
    }
    if (s->stringsSearchLabel && s->iconFont) {
        SendMessageW(s->stringsSearchLabel, WM_SETFONT, reinterpret_cast<WPARAM>(s->iconFont), TRUE);
    }

    SetWindowTheme(s->tab, L"Explorer", nullptr);
    SetWindowTheme(s->pageHeaders, L"Explorer", nullptr);
    SetWindowTheme(s->pageSections, L"Explorer", nullptr);
    SetWindowTheme(s->pageImportsDlls, L"Explorer", nullptr);
    SetWindowTheme(s->pageImports, L"Explorer", nullptr);
    SetWindowTheme(s->pageExports, L"Explorer", nullptr);
    SetWindowTheme(s->pageStrings, L"Explorer", nullptr);

    int editMargin = MulDiv(8, static_cast<int>(s->dpi), 96);
    SendMessageW(s->pageSummary, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageResources, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pagePdb, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageSignature, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageHash, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->aboutInfo, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    if (s->exportsInfo) {
        SendMessageW(s->exportsInfo, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    }

    DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;
    ListView_SetExtendedListViewStyleEx(s->pageHeaders, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageSections, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageImportsDlls, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageImports, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageExports, ex, ex);
    ListView_SetExtendedListViewStyleEx(s->pageStrings, ex, ex);
}

static LRESULT CALLBACK StringsListSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR, DWORD_PTR) {
    if (msg == WM_GETOBJECT) {
        return 0;
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
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
            s->bgBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
            s->regexErrorBrush = CreateSolidBrush(RGB(255, 235, 238));

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
            ti.pszText = const_cast<wchar_t*>(L"Headers");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Headers), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Sections");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Sections), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Imports");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Imports), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Exports");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Exports), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Strings");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Strings), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Resources");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Resources), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Debug/PDB");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::DebugPdb), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Signature");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Signature), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Hash");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Hash), &ti);
            ti.pszText = const_cast<wchar_t*>(L"About");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::About), &ti);

            DWORD editStyle = WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_READONLY;
            s->pageSummary = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUMMARY), nullptr, nullptr);
            s->pageResources = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_RESOURCES), nullptr, nullptr);
            s->pagePdb = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PDB), nullptr, nullptr);
            s->pageSignature = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SIGNATURE), nullptr, nullptr);
            s->pageHash = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_HASH), nullptr, nullptr);
            s->pageAbout = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_ABOUT), nullptr, nullptr);
            s->aboutInfo = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_READONLY, 0, 0, 0, 0, s->pageAbout, reinterpret_cast<HMENU>(IDC_ABOUT_INFO), nullptr, nullptr);
            s->aboutLink = CreateWindowW(WC_LINK,
                                         L"GitHub\uff1a <a href=\"https://github.com/zuohuiyang/PEInfo\">https://github.com/zuohuiyang/PEInfo</a>",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                         0,
                                         0,
                                         0,
                                         0,
                                         s->pageAbout,
                                         reinterpret_cast<HMENU>(IDC_ABOUT_LINK),
                                         nullptr,
                                         nullptr);

            DWORD listStyle = WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS;
            s->pageHeaders = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_HEADERS), nullptr, nullptr);
            s->pageSections = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SECTIONS), nullptr, nullptr);
            s->pageImportsDlls = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS_DLLS), nullptr, nullptr);
            s->pageImports = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS), nullptr, nullptr);
            s->pageExports = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORTS), nullptr, nullptr);
            s->pageStrings = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle | LVS_OWNERDATA, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS), nullptr, nullptr);

            DWORD filterLabelStyle = WS_CHILD | SS_CENTER | SS_CENTERIMAGE;
            s->importsFilterLabel = CreateWindowW(L"STATIC", L"\uE721", filterLabelStyle, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            DWORD filterEditStyle = WS_CHILD | ES_LEFT | ES_AUTOHSCROLL;
            s->importsFilterEdit = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", filterEditStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS_FILTER), nullptr, nullptr);
            s->exportsFilterLabel = CreateWindowW(L"STATIC", L"\uE721", filterLabelStyle, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            s->exportsFilterEdit = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", filterEditStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORTS_FILTER), nullptr, nullptr);
            s->exportsInfo = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_READONLY, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORTS_INFO), nullptr, nullptr);
            s->exportsSeparator = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORTS_SEPARATOR), nullptr, nullptr);

            s->stringsSearchLabel = CreateWindowW(L"STATIC", L"\uE721", filterLabelStyle, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            s->stringsSearchEdit = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", filterEditStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_SEARCH), nullptr, nullptr);
            s->stringsRegexCheck = CreateWindowW(L"BUTTON", L"\u6b63\u5219", WS_CHILD | BS_AUTOCHECKBOX, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_REGEX), nullptr, nullptr);
            s->stringsTypeLabel = CreateWindowW(L"STATIC", L"\u7c7b\u578b\uff1a", WS_CHILD | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            DWORD comboStyle = WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL;
            s->stringsTypeCombo = CreateWindowExW(WS_EX_STATICEDGE, WC_COMBOBOXW, L"", comboStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_TYPE), nullptr, nullptr);
            DWORD minLenStyle = WS_CHILD | ES_LEFT | ES_AUTOHSCROLL | ES_NUMBER;
            s->stringsMinLenLabel = CreateWindowW(L"STATIC", L"\u6700\u5c0f\u957f\u5ea6\uff1a", WS_CHILD | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            s->stringsMinLenEdit = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"5", minLenStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_MINLEN), nullptr, nullptr);
            DWORD chkStyle = WS_CHILD | BS_AUTOCHECKBOX;
            s->stringsUniqueCheck = CreateWindowW(L"BUTTON", L"\u53bb\u91cd", chkStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_UNIQUE), nullptr, nullptr);

            s->stringsHistoryLabel = CreateWindowW(L"STATIC", L"\u5386\u53f2\uff1a", WS_CHILD | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            s->stringsHistoryClearBtn = CreateWindowW(L"BUTTON", L"\u6e05\u7a7a", WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_CLEAR), nullptr, nullptr);
            DWORD tagStyle = WS_CHILD | BS_PUSHBUTTON;
            s->stringsHistoryTags[0] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG0), nullptr, nullptr);
            s->stringsHistoryTags[1] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG1), nullptr, nullptr);
            s->stringsHistoryTags[2] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG2), nullptr, nullptr);
            s->stringsHistoryTags[3] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG3), nullptr, nullptr);
            s->stringsHistoryTags[4] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG4), nullptr, nullptr);
            s->stringsHistoryTags[5] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG5), nullptr, nullptr);
            s->stringsHistoryTags[6] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG6), nullptr, nullptr);
            s->stringsHistoryTags[7] = CreateWindowW(L"BUTTON", L"", tagStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_HISTORY_TAG7), nullptr, nullptr);

            s->stringsPagePrev = CreateWindowW(L"BUTTON", L"\u4e0a\u4e00\u9875", WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_PAGE_PREV), nullptr, nullptr);
            s->stringsPageNext = CreateWindowW(L"BUTTON", L"\u4e0b\u4e00\u9875", WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_PAGE_NEXT), nullptr, nullptr);
            s->stringsPageLabel = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_STRINGS_PAGE_LABEL), nullptr, nullptr);
            SetWindowSubclass(s->pageStrings, StringsListSubclassProc, 1, 0);

            auto colW = [&](int base) { return MulDiv(base, static_cast<int>(s->dpi), 96); };
            AddListViewColumn(s->pageHeaders, 0, colW(220), L"Field");
            AddListViewColumn(s->pageHeaders, 1, colW(560), L"Value");
            AddListViewColumn(s->pageHeaders, 2, colW(160), L"Raw");
            ListView_EnableGroupView(s->pageHeaders, TRUE);
            {
                LVGROUP g = {};
                g.cbSize = sizeof(g);
                g.mask = LVGF_GROUPID | LVGF_HEADER;

                g.iGroupId = 1;
                g.pszHeader = const_cast<wchar_t*>(L"DOS Header");
                ListView_InsertGroup(s->pageHeaders, -1, &g);

                g.iGroupId = 2;
                g.pszHeader = const_cast<wchar_t*>(L"COFF File Header");
                ListView_InsertGroup(s->pageHeaders, -1, &g);

                g.iGroupId = 3;
                g.pszHeader = const_cast<wchar_t*>(L"Optional Header");
                ListView_InsertGroup(s->pageHeaders, -1, &g);

                g.iGroupId = 4;
                g.pszHeader = const_cast<wchar_t*>(L"Data Directories");
                ListView_InsertGroup(s->pageHeaders, -1, &g);
            }
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
            AddListViewColumn(s->pageExports, 2, colW(120), L"Offset");
            AddListViewColumn(s->pageExports, 3, colW(300), L"Name");
            AddListViewColumn(s->pageExports, 4, colW(360), L"Forwarder");

            AddListViewColumn(s->pageStrings, 0, colW(120), L"Offset");
            AddListViewColumn(s->pageStrings, 1, colW(120), L"Section");
            AddListViewColumn(s->pageStrings, 2, colW(70), L"Len");
            AddListViewColumn(s->pageStrings, 3, colW(520), L"Text");

            SendMessageW(s->stringsTypeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"All"));
            SendMessageW(s->stringsTypeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"ASCII"));
            SendMessageW(s->stringsTypeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"UTF-16LE"));
            SendMessageW(s->stringsTypeCombo, CB_SETCURSEL, 0, 0);
            SendMessageW(s->stringsUniqueCheck, BM_SETCHECK, BST_CHECKED, 0);

            s->stringsHistory.Load();

            ApplyUiFontAndTheme(s);
            ShowOnlyTab(s, TabIndex::Summary);
            SetBusy(s, false);
            RefreshAllViews(s);
            UpdateStringsHistoryBar(s);
            UpdateLayout(s);
            if (!s->pendingFile.empty()) {
                std::wstring path = s->pendingFile;
                s->pendingFile.clear();
                StartAnalysis(s, path);
            }
            return 0;
        }
        case WM_CTLCOLORBTN: {
            if (!s->bgBrush) {
                break;
            }
            HWND ctrl = reinterpret_cast<HWND>(lParam);
            if (ctrl != s->stringsUniqueCheck && ctrl != s->stringsRegexCheck) {
                break;
            }
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetBkMode(dc, TRANSPARENT);
            return reinterpret_cast<INT_PTR>(s->bgBrush);
        }
        case WM_CTLCOLORSTATIC: {
            if (!s->bgBrush) {
                break;
            }
            HWND ctrl = reinterpret_cast<HWND>(lParam);
            if (ctrl != s->importsFilterLabel &&
                ctrl != s->exportsFilterLabel &&
                ctrl != s->stringsSearchLabel &&
                ctrl != s->stringsTypeLabel &&
                ctrl != s->stringsMinLenLabel &&
                ctrl != s->stringsHistoryLabel &&
                ctrl != s->stringsPageLabel) {
                break;
            }
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
            return reinterpret_cast<INT_PTR>(s->bgBrush);
        }
        case WM_CTLCOLOREDIT: {
            HWND ctrl = reinterpret_cast<HWND>(lParam);
            if (ctrl == s->stringsSearchEdit && s->stringsFilterUseRegex && !s->stringsFilterRegexValid && s->regexErrorBrush) {
                HDC dc = reinterpret_cast<HDC>(wParam);
                SetTextColor(dc, RGB(183, 28, 28));
                SetBkColor(dc, RGB(255, 235, 238));
                return reinterpret_cast<INT_PTR>(s->regexErrorBrush);
            }
            break;
        }
        case WM_SIZE: {
            UpdateLayout(s);
            UpdateStringsHistoryBar(s);
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
            UpdateStringsHistoryBar(s);
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_OPEN_SMALL: {
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
                case IDC_EXPORTS_FILTER: {
                    if (HIWORD(wParam) == EN_CHANGE) {
                        SetTimer(hwnd, kTimerExportsFilter, 200, nullptr);
                    }
                    return 0;
                }
                case IDC_STRINGS_SEARCH:
                case IDC_STRINGS_MINLEN: {
                    if (HIWORD(wParam) == EN_CHANGE) {
                        SetTimer(hwnd, kTimerStringsFilter, 200, nullptr);
                    }
                    return 0;
                }
                case IDC_STRINGS_TYPE: {
                    if (HIWORD(wParam) == CBN_SELCHANGE) {
                        ApplyStringsFilterNow(s);
                    }
                    return 0;
                }
                case IDC_STRINGS_REGEX: {
                    ApplyStringsFilterNow(s);
                    return 0;
                }
                case IDC_STRINGS_UNIQUE: {
                    ApplyStringsFilterNow(s);
                    return 0;
                }
                case IDC_STRINGS_PAGE_PREV: {
                    if (s->stringsPageIndex > 0) {
                        --s->stringsPageIndex;
                        UpdateStringsDisplayCount(s);
                        InvalidateRect(s->pageStrings, nullptr, TRUE);
                        UpdateStringsDetail(s);
                    }
                    return 0;
                }
                case IDC_STRINGS_PAGE_NEXT: {
                    if ((s->stringsPageIndex + 1) < s->stringsPageCount) {
                        ++s->stringsPageIndex;
                        UpdateStringsDisplayCount(s);
                        InvalidateRect(s->pageStrings, nullptr, TRUE);
                        UpdateStringsDetail(s);
                    }
                    return 0;
                }
                case IDC_STRINGS_HISTORY_TAG0:
                case IDC_STRINGS_HISTORY_TAG1:
                case IDC_STRINGS_HISTORY_TAG2:
                case IDC_STRINGS_HISTORY_TAG3:
                case IDC_STRINGS_HISTORY_TAG4:
                case IDC_STRINGS_HISTORY_TAG5:
                case IDC_STRINGS_HISTORY_TAG6:
                case IDC_STRINGS_HISTORY_TAG7: {
                    int idx = static_cast<int>(LOWORD(wParam)) - static_cast<int>(IDC_STRINGS_HISTORY_TAG0);
                    if (idx >= 0 && static_cast<size_t>(idx) < s->stringsHistoryDisplay.size()) {
                        ApplyStringsHistoryEntry(s, s->stringsHistoryDisplay[static_cast<size_t>(idx)]);
                    }
                    return 0;
                }
                case IDC_STRINGS_HISTORY_CLEAR: {
                    RECT rc = {};
                    GetWindowRect(s->stringsHistoryClearBtn, &rc);
                    POINT pt = {rc.left, rc.bottom};
                    HMENU menu = CreatePopupMenu();
                    AppendMenuW(menu, MF_STRING, IDM_STRINGS_HISTORY_CLEAR_UNPINNED, L"\u6e05\u7a7a\u672a\u9501\u5b9a");
                    AppendMenuW(menu, MF_STRING, IDM_STRINGS_HISTORY_CLEAR_ALL, L"\u6e05\u7a7a\u5168\u90e8(\u542b\u9501\u5b9a)");
                    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
                    DestroyMenu(menu);
                    return 0;
                }
                case IDM_STRINGS_HISTORY_CLEAR_UNPINNED: {
                    KillTimer(hwnd, kTimerStringsHistorySave);
                    s->stringsHistory.Clear(false);
                    s->stringsHistory.Save();
                    s->stringsHistoryDirty = false;
                    UpdateStringsHistoryBar(s);
                    return 0;
                }
                case IDM_STRINGS_HISTORY_CLEAR_ALL: {
                    KillTimer(hwnd, kTimerStringsHistorySave);
                    s->stringsHistory.Clear(true);
                    s->stringsHistory.Save();
                    s->stringsHistoryDirty = false;
                    UpdateStringsHistoryBar(s);
                    return 0;
                }
                case IDM_STRINGS_HISTORY_PIN:
                case IDM_STRINGS_HISTORY_UNPIN:
                case IDM_STRINGS_HISTORY_DELETE: {
                    int idx = s->stringsHistoryContextTag;
                    if (idx >= 0 && static_cast<size_t>(idx) < s->stringsHistoryDisplay.size()) {
                        const auto& e = s->stringsHistoryDisplay[static_cast<size_t>(idx)];
                        if (LOWORD(wParam) == IDM_STRINGS_HISTORY_DELETE) {
                            s->stringsHistory.Delete(e);
                        } else {
                            bool pin = (LOWORD(wParam) == IDM_STRINGS_HISTORY_PIN);
                            s->stringsHistory.SetPinned(e, pin);
                        }
                        KillTimer(hwnd, kTimerStringsHistorySave);
                        s->stringsHistory.Save();
                        s->stringsHistoryDirty = false;
                        s->stringsHistoryContextTag = -1;
                        UpdateStringsHistoryBar(s);
                    }
                    return 0;
                }
                case IDM_HEADERS_COPY_ROW: {
                    CopySelectedHeadersRow(hwnd, s->pageHeaders);
                    return 0;
                }
                case IDM_STRINGS_COPY_TEXT: {
                    auto idx = GetSelectedStringsRowIndex(s);
                    if (idx.has_value() && *idx >= 0 && *idx < static_cast<int>(s->stringsAllRows.size())) {
                        CopyTextToClipboard(hwnd, s->stringsAllRows[static_cast<size_t>(*idx)].text);
                    }
                    return 0;
                }
                case IDM_STRINGS_COPY_LINE: {
                    auto idx = GetSelectedStringsRowIndex(s);
                    if (idx.has_value() && *idx >= 0 && *idx < static_cast<int>(s->stringsAllRows.size())) {
                        const auto& r = s->stringsAllRows[static_cast<size_t>(*idx)];
                        std::wstring line = BuildStringsExportText({&r});
                        CopyTextToClipboard(hwnd, line);
                    }
                    return 0;
                }
                case IDM_STRINGS_COPY_DETAIL: {
                    auto idx = GetSelectedStringsRowIndex(s);
                    if (idx.has_value() && *idx >= 0 && *idx < static_cast<int>(s->stringsAllRows.size())) {
                        const auto& r = s->stringsAllRows[static_cast<size_t>(*idx)];
                        std::wstring text = FormatStringsDetailLine(r) + L"\r\n" + r.text;
                        CopyTextToClipboard(hwnd, text);
                    }
                    return 0;
                }
                case IDM_STRINGS_EXPORT_TEXT:
                case IDM_STRINGS_EXPORT_JSON: {
                    auto rows = GetStringsRowsForSelectionOrVisible(s);
                    if (rows.empty()) {
                        return 0;
                    }
                    std::wstring base = GetBaseNameFromPath(s->currentFile);
                    std::wstring defaultName = base + (LOWORD(wParam) == IDM_STRINGS_EXPORT_JSON ? L".strings.json" : L".strings.txt");
                    if (LOWORD(wParam) == IDM_STRINGS_EXPORT_JSON) {
                        std::wstring outPath = PromptSaveFile(hwnd, defaultName, L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0", L"json");
                        if (outPath.empty()) {
                            return 0;
                        }
                        std::string json = BuildStringsExportJson(rows);
                        if (!WriteAllBytes(outPath, json)) {
                            MessageBoxError(hwnd, L"\u5199\u5165\u5931\u8d25");
                        }
                        return 0;
                    }
                    std::wstring outPath = PromptSaveFile(hwnd, defaultName, L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0", L"txt");
                    if (outPath.empty()) {
                        return 0;
                    }
                    std::wstring text = BuildStringsExportText(rows);
                    std::string bytes = WStringToUtf8(text);
                    if (!WriteAllBytes(outPath, bytes)) {
                        MessageBoxError(hwnd, L"\u5199\u5165\u5931\u8d25");
                    }
                    return 0;
                }
                case VK_ESCAPE: {
                    if (s->busy && s->analysisCancel) {
                        s->analysisCancel->store(true);
                    }
                    if (s->stringsCancel) {
                        s->stringsCancel->store(true);
                    }
                    return 0;
                }
                default: {
                    break;
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
                if (s->stringsCancel) {
                    s->stringsCancel->store(true);
                }
                return 0;
            }
            break;
        }
        case WM_CONTEXTMENU: {
            HWND src = reinterpret_cast<HWND>(wParam);
            for (int i = 0; i < 8; ++i) {
                if (src == s->stringsHistoryTags[i]) {
                    s->stringsHistoryContextTag = i;
                    POINT pt = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
                    if (pt.x == -1 && pt.y == -1) {
                        RECT rc = {};
                        GetWindowRect(src, &rc);
                        pt.x = rc.left;
                        pt.y = rc.bottom;
                    }
                    HMENU menu = CreatePopupMenu();
                    bool pinned = false;
                    if (static_cast<size_t>(i) < s->stringsHistoryDisplay.size()) {
                        pinned = s->stringsHistoryDisplay[static_cast<size_t>(i)].pinned;
                    }
                    AppendMenuW(menu, MF_STRING, pinned ? IDM_STRINGS_HISTORY_UNPIN : IDM_STRINGS_HISTORY_PIN, pinned ? L"\u53d6\u6d88\u9501\u5b9a" : L"\u9501\u5b9a");
                    AppendMenuW(menu, MF_STRING, IDM_STRINGS_HISTORY_DELETE, L"\u5220\u9664");
                    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
                    DestroyMenu(menu);
                    return 0;
                }
            }
            if (src == s->pageHeaders) {
                POINT pt = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
                if (pt.x != -1 && pt.y != -1) {
                    POINT clientPt = pt;
                    ScreenToClient(s->pageHeaders, &clientPt);
                    LVHITTESTINFO ht = {};
                    ht.pt = clientPt;
                    int hit = ListView_SubItemHitTest(s->pageHeaders, &ht);
                    if (hit >= 0) {
                        ListView_SetItemState(s->pageHeaders, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                        ListView_SetItemState(s->pageHeaders, hit, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                } else {
                    int sel = ListView_GetNextItem(s->pageHeaders, -1, LVNI_SELECTED);
                    if (sel >= 0) {
                        RECT rc = {};
                        ListView_GetItemRect(s->pageHeaders, sel, &rc, LVIR_BOUNDS);
                        POINT p = {rc.left, rc.bottom};
                        ClientToScreen(s->pageHeaders, &p);
                        pt = p;
                    } else {
                        GetCursorPos(&pt);
                    }
                }
                HMENU menu = CreatePopupMenu();
                AppendMenuW(menu, MF_STRING, IDM_HEADERS_COPY_ROW, L"\u590d\u5236\u884c");
                TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
                DestroyMenu(menu);
                return 0;
            }
            if (src != s->pageStrings) {
                break;
            }
            POINT pt = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            if (pt.x != -1 && pt.y != -1) {
                POINT clientPt = pt;
                ScreenToClient(s->pageStrings, &clientPt);
                LVHITTESTINFO ht = {};
                ht.pt = clientPt;
                int hit = ListView_SubItemHitTest(s->pageStrings, &ht);
                if (hit >= 0) {
                    ListView_SetItemState(s->pageStrings, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                    ListView_SetItemState(s->pageStrings, hit, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                }
            } else {
                int sel = ListView_GetNextItem(s->pageStrings, -1, LVNI_SELECTED);
                if (sel >= 0) {
                    RECT rc = {};
                    ListView_GetItemRect(s->pageStrings, sel, &rc, LVIR_BOUNDS);
                    POINT p = {rc.left, rc.bottom};
                    ClientToScreen(s->pageStrings, &p);
                    pt = p;
                } else {
                    GetCursorPos(&pt);
                }
            }

            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, IDM_STRINGS_COPY_TEXT, L"\u590d\u5236\u6587\u672c");
            AppendMenuW(menu, MF_STRING, IDM_STRINGS_COPY_LINE, L"\u590d\u5236\u884c");
            AppendMenuW(menu, MF_STRING, IDM_STRINGS_COPY_DETAIL, L"\u590d\u5236\u8be6\u60c5");
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(menu, MF_STRING, IDM_STRINGS_EXPORT_TEXT, L"\u5bfc\u51fa Text...");
            AppendMenuW(menu, MF_STRING, IDM_STRINGS_EXPORT_JSON, L"\u5bfc\u51fa JSON...");
            TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);
            return 0;
        }
        case WM_TIMER: {
            if (wParam == kTimerImportsFilter) {
                KillTimer(hwnd, kTimerImportsFilter);
                ApplyImportsFilterNow(s);
                return 0;
            }
            if (wParam == kTimerExportsFilter) {
                KillTimer(hwnd, kTimerExportsFilter);
                ApplyExportsFilterNow(s);
                return 0;
            }
            if (wParam == kTimerStringsFilter) {
                KillTimer(hwnd, kTimerStringsFilter);
                ApplyStringsFilterNow(s);
                return 0;
            }
            if (wParam == kTimerStringsFilterWork) {
                ContinueStringsFilterWork(s);
                return 0;
            }
            if (wParam == kTimerStringsHistorySave) {
                KillTimer(hwnd, kTimerStringsHistorySave);
                if (s->stringsHistoryDirty) {
                    s->stringsHistory.Save();
                    s->stringsHistoryDirty = false;
                }
                return 0;
            }
            break;
        }
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<NMHDR*>(lParam);
            if (nm->hwndFrom == s->aboutLink && (nm->code == NM_CLICK || nm->code == NM_RETURN)) {
                auto* link = reinterpret_cast<NMLINK*>(lParam);
                ShellExecuteW(hwnd, L"open", link->item.szUrl, nullptr, nullptr, SW_SHOWNORMAL);
                return 0;
            }
            if (nm->hwndFrom == s->tab && nm->code == TCN_SELCHANGE) {
                int idx = TabCtrl_GetCurSel(s->tab);
                ShowOnlyTab(s, static_cast<TabIndex>(idx));
                UpdateLayout(s);
                UpdateStringsHistoryBar(s);
                if (idx == static_cast<int>(TabIndex::Strings)) {
                    HWND ctrls[] = {s->stringsSearchEdit,
                                    s->stringsRegexCheck,
                                    s->stringsTypeCombo,
                                    s->stringsMinLenEdit,
                                    s->stringsUniqueCheck,
                                    s->stringsHistoryLabel,
                                    s->stringsHistoryClearBtn,
                                    s->stringsPagePrev,
                                    s->stringsPageNext,
                                    s->stringsPageLabel,
                                    s->pageStrings};
                    for (HWND c : ctrls) {
                        if (c) {
                            RedrawWindow(c, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
                        }
                    }
                    for (HWND c : s->stringsHistoryTags) {
                        if (c) {
                            RedrawWindow(c, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
                        }
                    }
                    RECT pageRc = GetTabPageRect(s->hwnd, s->tab);
                    RedrawWindow(s->hwnd, &pageRc, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME | RDW_UPDATENOW);
                }
                if (idx == static_cast<int>(TabIndex::Signature)) {
                    StartVerifyIfNeeded(s, false);
                }
                return 0;
            }
            if (nm->hwndFrom == s->pageHeaders && nm->code == LVN_KEYDOWN) {
                auto* kd = reinterpret_cast<NMLVKEYDOWN*>(lParam);
                if (kd->wVKey == 'C' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                    CopySelectedHeadersRow(hwnd, s->pageHeaders);
                    return 0;
                }
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
            if (nm->hwndFrom == s->pageStrings && nm->code == LVN_GETDISPINFOW) {
                auto* di = reinterpret_cast<NMLVDISPINFOW*>(lParam);
                LVITEMW& item = di->item;
                if (!(item.mask & LVIF_TEXT) || item.pszText == nullptr || item.cchTextMax <= 0) {
                    return 0;
                }
                int viewRow = item.iItem;
                if (viewRow < 0 || viewRow >= static_cast<int>(s->stringsVisible.size())) {
                    item.pszText[0] = L'\0';
                    return 0;
                }
                int idx = s->stringsVisible[static_cast<size_t>(viewRow)];
                if (idx < 0 || idx >= static_cast<int>(s->stringsAllRows.size())) {
                    item.pszText[0] = L'\0';
                    return 0;
                }
                const auto& r = s->stringsAllRows[static_cast<size_t>(idx)];
                const std::wstring* text = nullptr;
                std::wstring dash = L"-";
                switch (item.iSubItem) {
                    case 0: text = &r.fileOffsetHex; break;
                    case 1: text = r.section.empty() ? &dash : &r.section; break;
                    case 2: text = &r.lenText; break;
                    case 3: text = &r.text; break;
                    default: break;
                }
                if (text) {
                    lstrcpynW(item.pszText, text->c_str(), item.cchTextMax);
                } else {
                    item.pszText[0] = L'\0';
                }
                return 0;
            }
            if (nm->hwndFrom == s->pageStrings && nm->code == LVN_ITEMCHANGED) {
                UpdateStringsDetail(s);
                return 0;
            }
            if (nm->hwndFrom == s->pageStrings && nm->code == NM_DBLCLK) {
                auto idx = GetSelectedStringsRowIndex(s);
                if (idx.has_value() && *idx >= 0 && *idx < static_cast<int>(s->stringsAllRows.size())) {
                    CopyTextToClipboard(hwnd, s->stringsAllRows[static_cast<size_t>(*idx)].text);
                }
                return 0;
            }
            break;
        }
        case WM_DROPFILES: {
            HDROP drop = reinterpret_cast<HDROP>(wParam);
            UINT files = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            if (files > 0) {
                UINT len = DragQueryFileW(drop, 0, nullptr, 0);
                std::wstring path(static_cast<size_t>(len + 1), L'\0');
                DragQueryFileW(drop, 0, path.data(), len + 1);
                path.resize(wcslen(path.c_str()));

                std::wstring lower = ToLowerString(path);
                bool isPdb = lower.size() >= 4 && lower.substr(lower.size() - 4) == L".pdb";
                if (isPdb) {
                    s->droppedPdbPath = path;
                    s->droppedPdbInfo.reset();
                    s->droppedPdbError.clear();

                    PdbFileInfo info = {};
                    std::wstring err;
                    if (ReadPdbFileInfo(path, info, err)) {
                        s->droppedPdbInfo = std::move(info);
                    } else {
                        s->droppedPdbError = err.empty() ? L"\u89e3\u6790 PDB \u5931\u8d25" : err;
                    }

                    TabCtrl_SetCurSel(s->tab, static_cast<int>(TabIndex::DebugPdb));
                    ShowOnlyTab(s, TabIndex::DebugPdb);
                    UpdateLayout(s);
                    RefreshAllViews(s);
                } else {
                    StartAnalysis(s, path);
                }
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
            StartStringsScan(s);
            delete r;
            return 0;
        }
        case WM_APP_STRINGS_DONE: {
            auto* m = reinterpret_cast<StringsResultMessage*>(lParam);
            if (m->cancel) {
                if (s->stringsCancel == m->cancel) {
                    s->stringsCancel = nullptr;
                }
                delete m->cancel;
            }
            if (m->filePath != s->currentFile) {
                delete m;
                return 0;
            }
            if (!m->ok) {
                if (m->error != L"\u5df2\u53d6\u6d88") {
                    MessageBoxError(s->hwnd, m->error);
                }
                delete m;
                return 0;
            }
            if (m->truncated && m->hitLimit > 0) {
                std::wostringstream out;
                std::wstring typeText = L"unknown";
                if (m->scanAscii && m->scanUtf16Le) {
                    typeText = L"ASCII+UTF16LE";
                } else if (m->scanAscii) {
                    typeText = L"ASCII";
                } else if (m->scanUtf16Le) {
                    typeText = L"UTF16LE";
                }
                out << L"\u5b57\u7b26\u4e32\u6570\u91cf\u5df2\u8fbe\u4e0a\u9650\uff0c\u4ec5\u5c55\u793a\u524d " << m->hitLimit << L" \u6761\u3002\r\n";
                out << L"\u5f53\u524d\u626b\u63cf\u8bbe\u7f6e\uff1a\u6700\u5c0f\u957f\u5ea6=" << m->minLen << L"\uff0c\u7c7b\u578b=" << typeText << L"\u3002\r\n";
                out << L"\u53ef\u63d0\u9ad8\u6700\u5c0f\u957f\u5ea6\u6216\u4ec5\u9009\u62e9\u4e00\u79cd\u7c7b\u578b\u4ee5\u51cf\u5c11\u566a\u58f0\u3002";
                MessageBoxW(s->hwnd, out.str().c_str(), L"\u63d0\u793a", MB_OK | MB_ICONINFORMATION);
            }

            s->stringsAllRows.clear();
            s->stringsVisible.clear();
            if (s->stringsFilterRunning) {
                s->stringsFilterRunning = false;
                KillTimer(s->hwnd, kTimerStringsFilterWork);
            }
            ListView_SetItemCountEx(s->pageStrings, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

            auto* payload = new StringsRowsBuildPayload();
            payload->hwnd = s->hwnd;
            payload->filePath = m->filePath;
            payload->hits = std::move(m->hits);
            if (s->analysis) {
                payload->sections = s->analysis->parser.GetSectionsInfo();
                payload->imageBase = s->analysis->parser.GetHeaderInfo().imageBase;
            }

            uintptr_t th = _beginthreadex(nullptr, 0, StringsRowsBuildThreadProc, payload, 0, nullptr);
            if (th == 0) {
                delete payload;
                MessageBoxError(s->hwnd, L"\u542f\u52a8\u5904\u7406\u7ebf\u7a0b\u5931\u8d25");
            } else {
                CloseHandle(reinterpret_cast<HANDLE>(th));
            }
            delete m;
            return 0;
        }
        case WM_APP_STRINGS_ROWS_DONE: {
            auto* m = reinterpret_cast<StringsRowsResultMessage*>(lParam);
            if (m->filePath != s->currentFile) {
                delete m;
                return 0;
            }
            if (!m->ok) {
                MessageBoxError(s->hwnd, m->error);
                delete m;
                return 0;
            }
            s->stringsAllRows = std::move(m->rows);
            ApplyStringsFilterNow(s);
            delete m;
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
            KillTimer(hwnd, kTimerStringsHistorySave);
            if (s->stringsHistoryDirty) {
                s->stringsHistory.Save();
                s->stringsHistoryDirty = false;
            }
            if (s->iconOpen) {
                DestroyIcon(s->iconOpen);
                s->iconOpen = nullptr;
            }
            if (s->bgBrush) {
                DeleteObject(s->bgBrush);
                s->bgBrush = nullptr;
            }
            if (s->regexErrorBrush) {
                DeleteObject(s->regexErrorBrush);
                s->regexErrorBrush = nullptr;
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
            if (s->stringsCancel) {
                s->stringsCancel->store(true);
                s->stringsCancel = nullptr;
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
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_LINK_CLASS;
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

    HWND hwnd = CreateWindowExW(0, kMainClassName, L"PEInfo v1.0", WS_OVERLAPPEDWINDOW,
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

