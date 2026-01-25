#include "stdafx.h"

#include "PECore.h"
#include "ReportJsonWriter.h"
#include "ReportTextWriter.h"
#include "ReportUtil.h"
#include "ShellContextMenu.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <process.h>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

static const wchar_t* kMainClassName = L"PEInfoGuiMainWindow";

static const UINT WM_APP_ANALYSIS_DONE = WM_APP + 1;
static const UINT WM_APP_VERIFY_DONE = WM_APP + 2;

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
DECLARE_HANDLE(DPI_AWARENESS_CONTEXT);
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif

enum : UINT {
    IDC_BTN_OPEN = 1001,
    IDC_BTN_REFRESH = 1002,
    IDC_BTN_EXPORT_JSON = 1003,
    IDC_BTN_EXPORT_TEXT = 1004,
    IDC_BTN_COPY_SUMMARY = 1005,
    IDC_BTN_SETTINGS = 1006,
    IDC_TAB = 1010,
    IDC_FILEINFO = 1020,
    IDC_SUMMARY = 2001,
    IDC_SECTIONS = 2002,
    IDC_IMPORTS = 2003,
    IDC_EXPORTS = 2004,
    IDC_PDB = 2005,
    IDC_SIGNATURE = 2006,
    IDC_HASH = 2007,
    IDC_SIG_VERIFY = 3001
};

enum class TabIndex : int {
    Summary = 0,
    Sections = 1,
    Imports = 2,
    Exports = 3,
    DebugPdb = 4,
    Signature = 5,
    Hash = 6
};

struct VerifyResultMessage {
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
    HWND btnOpen = nullptr;
    HWND btnRefresh = nullptr;
    HWND btnExportJson = nullptr;
    HWND btnExportText = nullptr;
    HWND btnCopySummary = nullptr;
    HWND btnSettings = nullptr;
    HWND fileInfo = nullptr;
    HWND tab = nullptr;

    HWND pageSummary = nullptr;
    HWND pageSections = nullptr;
    HWND pageImports = nullptr;
    HWND pageExports = nullptr;
    HWND pagePdb = nullptr;
    HWND pageSignature = nullptr;
    HWND pageHash = nullptr;
    HWND btnSigVerify = nullptr;

    bool busy = false;
    std::wstring currentFile;
    std::wstring pendingFile;
    std::unique_ptr<PEAnalysisResult> analysis;

    HFONT uiFont = nullptr;
    UINT dpi = 96;
};

static UINT GetBestWindowDpi(HWND hwnd);
static HFONT CreateUiFontForDpi(UINT dpi);

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

static bool CopyToClipboard(HWND hwnd, const std::wstring& text) {
    if (!OpenClipboard(hwnd)) {
        return false;
    }
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!mem) {
        CloseClipboard();
        return false;
    }
    void* dst = GlobalLock(mem);
    memcpy(dst, text.c_str(), bytes);
    GlobalUnlock(mem);
    SetClipboardData(CF_UNICODETEXT, mem);
    CloseClipboard();
    return true;
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

static void PopulateImports(HWND list, const PEParser& parser) {
    ListView_DeleteAllItems(list);

    int row = 0;
    auto addDlls = [&](const std::vector<PEImportDLL>& dlls, const wchar_t* type) {
        for (const auto& d : dlls) {
            std::wstring dllName = ToWStringUtf8BestEffort(d.dllName);
            for (const auto& fn : d.functions) {
                SetListViewText(list, row, 0, type);
                SetListViewText(list, row, 1, dllName);
                SetListViewText(list, row, 2, ToWStringUtf8BestEffort(fn.name));
                ++row;
            }
        }
    };

    addDlls(parser.GetImports(), L"Import");
    addDlls(parser.GetDelayImports(), L"Delay");
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

static void PopulateSignature(HWND edit, const PEAnalysisResult& ar) {
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
        out << L"\r\n\u9a8c\u8bc1\uff1a\u672a\u6267\u884c\r\n";
    }
    SetWindowTextWString(edit, out.str());
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
    EnableWindow(s->btnOpen, !busy);
    EnableWindow(s->btnRefresh, !busy && !s->currentFile.empty());
    EnableWindow(s->btnExportJson, !busy && s->analysis != nullptr);
    EnableWindow(s->btnExportText, !busy && s->analysis != nullptr);
    EnableWindow(s->btnCopySummary, !busy && s->analysis != nullptr);
    EnableWindow(s->btnSettings, !busy);
    EnableWindow(s->btnSigVerify, !busy && s->analysis != nullptr && s->analysis->signaturePresenceReady);
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
    HWND pages[] = {s->pageSummary, s->pageSections, s->pageImports, s->pageExports, s->pagePdb, s->pageSignature, s->pageHash};
    for (int i = 0; i < static_cast<int>(std::size(pages)); ++i) {
        ShowWindow(pages[i], (i == static_cast<int>(idx)) ? SW_SHOW : SW_HIDE);
    }
    ShowWindow(s->btnSigVerify, (idx == TabIndex::Signature) ? SW_SHOW : SW_HIDE);
}

static void UpdateFileInfo(GuiState* s) {
    if (s->analysis == nullptr) {
        SetWindowTextWString(s->fileInfo, L"\u672a\u6253\u5f00\u6587\u4ef6");
        return;
    }

    const auto& h = s->analysis->parser.GetHeaderInfo();
    std::wostringstream out;
    out << s->analysis->filePath << L"\r\n";
    out << L"Bitness: " << (h.is64Bit ? L"x64" : (h.is32Bit ? L"x86" : L"Unknown"));
    if (s->analysis->signaturePresenceReady) {
        out << L"    Signature: " << SigPresenceToText(s->analysis->signaturePresence);
    }
    if (s->analysis->reportHash.has_value()) {
        out << L"    SHA256: " << s->analysis->reportHash->result;
    }
    SetWindowTextWString(s->fileInfo, out.str());
}

static void RefreshAllViews(GuiState* s) {
    if (s->analysis == nullptr) {
        SetWindowTextWString(s->pageSummary, L"\u62d6\u62fd EXE/DLL/SYS \u5230\u7a97\u53e3\uff0c\u6216\u70b9\u51fb\u201c\u6253\u5f00\u201d");
        ListView_DeleteAllItems(s->pageSections);
        ListView_DeleteAllItems(s->pageImports);
        ListView_DeleteAllItems(s->pageExports);
        SetWindowTextWString(s->pagePdb, L"");
        SetWindowTextWString(s->pageSignature, L"");
        SetWindowTextWString(s->pageHash, L"");
        UpdateFileInfo(s);
        return;
    }

    SetWindowTextWString(s->pageSummary, FormatSummaryText(*s->analysis));
    PopulateSections(s->pageSections, s->analysis->parser);
    PopulateImports(s->pageImports, s->analysis->parser);
    PopulateExports(s->pageExports, s->analysis->parser);
    PopulatePdb(s->pagePdb, s->analysis->pdb);
    PopulateSignature(s->pageSignature, *s->analysis);
    PopulateHash(s->pageHash, s->analysis->hashes);
    UpdateFileInfo(s);
}

static unsigned __stdcall AnalysisThreadProc(void* param) {
    auto* msg = reinterpret_cast<std::pair<HWND, std::wstring>*>(param);
    HWND hwnd = msg->first;
    std::wstring filePath = msg->second;
    delete msg;

    auto* resultMsg = new AnalysisResultMessage();
    auto ar = std::make_unique<PEAnalysisResult>();

    PEAnalysisOptions opt;
    opt.computePdb = true;
    opt.computeSignaturePresence = true;
    opt.verifySignature = false;
    opt.computeHashes = true;
    opt.hashAlgorithms = {HashAlgorithm::MD5, HashAlgorithm::SHA1, HashAlgorithm::SHA256};
    opt.timeFormat = ReportTimeFormat::Local;

    std::wstring err;
    if (!AnalyzePeFile(filePath, opt, *ar, err)) {
        resultMsg->ok = false;
        resultMsg->error = err;
    } else {
        resultMsg->ok = true;
        resultMsg->result = std::move(ar);
    }

    PostMessageW(hwnd, WM_APP_ANALYSIS_DONE, 0, reinterpret_cast<LPARAM>(resultMsg));
    return 0;
}

static unsigned __stdcall VerifyThreadProc(void* param) {
    auto* msg = reinterpret_cast<std::pair<HWND, std::wstring>*>(param);
    HWND hwnd = msg->first;
    std::wstring filePath = msg->second;
    delete msg;

    auto* vr = new VerifyResultMessage();
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

static void StartAnalysis(GuiState* s, const std::wstring& filePath) {
    if (s->busy) {
        return;
    }
    s->currentFile = filePath;
    s->analysis.reset();
    SetBusy(s, true);
    SetWindowTextWString(s->pageSummary, L"\u6b63\u5728\u89e3\u6790...");
    UpdateFileInfo(s);

    auto* payload = new std::pair<HWND, std::wstring>(s->hwnd, filePath);
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

static std::wstring PromptSaveFile(HWND hwnd, const wchar_t* title, const wchar_t* defExt, const wchar_t* filter) {
    wchar_t fileName[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.lpstrDefExt = defExt;
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) {
        return {};
    }
    return fileName;
}

static void ExportJson(GuiState* s) {
    if (s->analysis == nullptr) {
        return;
    }
    std::wstring path = PromptSaveFile(s->hwnd, L"\u5bfc\u51fa JSON", L"json", L"JSON (*.json)\0*.json\0All Files (*.*)\0*.*\0");
    if (path.empty()) {
        return;
    }

    ReportOptions ro;
    ro.showSummary = true;
    ro.showSections = true;
    ro.showImports = true;
    ro.showExports = true;
    ro.showPdb = true;
    ro.showSignature = true;
    ro.importsAll = true;
    ro.timeFormat = ReportTimeFormat::Local;

    std::string json = BuildJsonReport(ro,
                                       s->analysis->filePath,
                                       s->analysis->parser,
                                       s->analysis->pdb,
                                       s->analysis->signaturePresenceReady ? &s->analysis->signaturePresence : nullptr,
                                       &s->analysis->embeddedVerify,
                                       &s->analysis->catalogVerify,
                                       s->analysis->reportHash.has_value() ? &s->analysis->reportHash : nullptr);
    json.push_back('\n');
    if (!WriteAllBytes(path, json)) {
        MessageBoxError(s->hwnd, L"\u5199\u5165\u6587\u4ef6\u5931\u8d25");
    }
}

static void ExportText(GuiState* s) {
    if (s->analysis == nullptr) {
        return;
    }
    std::wstring path = PromptSaveFile(s->hwnd, L"\u5bfc\u51fa Text", L"txt", L"Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0");
    if (path.empty()) {
        return;
    }

    ReportOptions ro;
    ro.showSummary = true;
    ro.showSections = true;
    ro.showImports = true;
    ro.showExports = true;
    ro.showPdb = true;
    ro.showSignature = true;
    ro.importsAll = true;
    ro.quiet = false;
    ro.timeFormat = ReportTimeFormat::Local;

    std::wstring text = BuildTextReport(ro,
                                        s->analysis->filePath,
                                        s->analysis->parser,
                                        s->analysis->pdb,
                                        s->analysis->signaturePresenceReady ? &s->analysis->signaturePresence : nullptr,
                                        s->analysis->embeddedVerify,
                                        s->analysis->catalogVerify,
                                        s->analysis->reportHash,
                                        0,
                                        500);
    std::string utf8 = WStringToUtf8(text);
    if (!WriteAllBytes(path, utf8)) {
        MessageBoxError(s->hwnd, L"\u5199\u5165\u6587\u4ef6\u5931\u8d25");
    }
}

static void CopySummary(GuiState* s) {
    if (s->analysis == nullptr) {
        return;
    }
    std::wstring text = GetControlText(s->pageSummary);
    if (!CopyToClipboard(s->hwnd, text)) {
        MessageBoxError(s->hwnd, L"\u590d\u5236\u5931\u8d25");
    }
}

static void UpdateLayout(GuiState* s) {
    RECT rc = {};
    GetClientRect(s->hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    int pad = MulDiv(10, static_cast<int>(s->dpi), 96);
    int btnH = MulDiv(32, static_cast<int>(s->dpi), 96);
    int row1Y = pad;
    int x = pad;
    int btnW = MulDiv(104, static_cast<int>(s->dpi), 96);

    MoveWindow(s->btnOpen, x, row1Y, btnW, btnH, TRUE);
    x += btnW + pad;
    MoveWindow(s->btnRefresh, x, row1Y, btnW, btnH, TRUE);
    x += btnW + pad;
    int wideBtnW = MulDiv(126, static_cast<int>(s->dpi), 96);
    MoveWindow(s->btnExportJson, x, row1Y, wideBtnW, btnH, TRUE);
    x += wideBtnW + pad;
    MoveWindow(s->btnExportText, x, row1Y, wideBtnW, btnH, TRUE);
    x += wideBtnW + pad;
    MoveWindow(s->btnCopySummary, x, row1Y, wideBtnW, btnH, TRUE);
    x += wideBtnW + pad;
    MoveWindow(s->btnSettings, x, row1Y, btnW, btnH, TRUE);

    int fileInfoY = row1Y + btnH + pad;
    int fileInfoH = MulDiv(48, static_cast<int>(s->dpi), 96);
    MoveWindow(s->fileInfo, pad, fileInfoY, w - 2 * pad, fileInfoH, TRUE);

    int tabY = fileInfoY + fileInfoH + pad;
    int tabH = h - tabY - pad;
    MoveWindow(s->tab, pad, tabY, w - 2 * pad, tabH, TRUE);

    RECT pageRc = GetTabPageRect(s->hwnd, s->tab);
    int pageW = pageRc.right - pageRc.left;
    int pageH = pageRc.bottom - pageRc.top;

    MoveWindow(s->pageSummary, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageSections, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageImports, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pageExports, pageRc.left, pageRc.top, pageW, pageH, TRUE);
    MoveWindow(s->pagePdb, pageRc.left, pageRc.top, pageW, pageH, TRUE);

    int sigBtnH = MulDiv(32, static_cast<int>(s->dpi), 96);
    MoveWindow(s->btnSigVerify, pageRc.left, pageRc.top, MulDiv(140, static_cast<int>(s->dpi), 96), sigBtnH, TRUE);
    MoveWindow(s->pageSignature, pageRc.left, pageRc.top + sigBtnH + pad, pageW, pageH - sigBtnH - pad, TRUE);

    MoveWindow(s->pageHash, pageRc.left, pageRc.top, pageW, pageH, TRUE);
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

static void ApplyUiFontAndTheme(GuiState* s) {
    if (!s->uiFont) {
        return;
    }

    HWND controls[] = {
        s->btnOpen,
        s->btnRefresh,
        s->btnExportJson,
        s->btnExportText,
        s->btnCopySummary,
        s->btnSettings,
        s->fileInfo,
        s->tab,
        s->pageSummary,
        s->pageSections,
        s->pageImports,
        s->pageExports,
        s->pagePdb,
        s->pageSignature,
        s->pageHash,
        s->btnSigVerify,
    };
    for (HWND hwnd : controls) {
        if (hwnd) {
            SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(s->uiFont), TRUE);
        }
    }

    SetWindowTheme(s->tab, L"Explorer", nullptr);
    SetWindowTheme(s->pageSections, L"Explorer", nullptr);
    SetWindowTheme(s->pageImports, L"Explorer", nullptr);
    SetWindowTheme(s->pageExports, L"Explorer", nullptr);

    int editMargin = MulDiv(8, static_cast<int>(s->dpi), 96);
    SendMessageW(s->pageSummary, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pagePdb, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageSignature, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));
    SendMessageW(s->pageHash, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(editMargin, editMargin));

    DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;
    ListView_SetExtendedListViewStyleEx(s->pageSections, ex, ex);
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

            s->btnOpen = CreateWindowW(L"BUTTON", L"\u6253\u5f00", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_OPEN), nullptr, nullptr);
            s->btnRefresh = CreateWindowW(L"BUTTON", L"\u5237\u65b0", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_REFRESH), nullptr, nullptr);
            s->btnExportJson = CreateWindowW(L"BUTTON", L"\u5bfc\u51fa JSON", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_EXPORT_JSON), nullptr, nullptr);
            s->btnExportText = CreateWindowW(L"BUTTON", L"\u5bfc\u51fa Text", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_EXPORT_TEXT), nullptr, nullptr);
            s->btnCopySummary = CreateWindowW(L"BUTTON", L"\u590d\u5236\u6458\u8981", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_COPY_SUMMARY), nullptr, nullptr);
            s->btnSettings = CreateWindowW(L"BUTTON", L"\u8bbe\u7f6e", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_SETTINGS), nullptr, nullptr);

            s->fileInfo = CreateWindowW(L"STATIC", L"\u672a\u6253\u5f00\u6587\u4ef6", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_FILEINFO), nullptr, nullptr);

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
            ti.pszText = const_cast<wchar_t*>(L"Debug/PDB");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::DebugPdb), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Signature");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Signature), &ti);
            ti.pszText = const_cast<wchar_t*>(L"Hash");
            TabCtrl_InsertItem(s->tab, static_cast<int>(TabIndex::Hash), &ti);

            DWORD editStyle = WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_READONLY;
            s->pageSummary = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUMMARY), nullptr, nullptr);
            s->pagePdb = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PDB), nullptr, nullptr);
            s->pageSignature = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SIGNATURE), nullptr, nullptr);
            s->pageHash = CreateWindowExW(WS_EX_STATICEDGE, L"EDIT", L"", editStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_HASH), nullptr, nullptr);

            s->btnSigVerify = CreateWindowW(L"BUTTON", L"\u9a8c\u8bc1\u7b7e\u540d", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SIG_VERIFY), nullptr, nullptr);

            DWORD listStyle = WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS;
            s->pageSections = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SECTIONS), nullptr, nullptr);
            s->pageImports = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IMPORTS), nullptr, nullptr);
            s->pageExports = CreateWindowExW(WS_EX_STATICEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EXPORTS), nullptr, nullptr);

            auto colW = [&](int base) { return MulDiv(base, static_cast<int>(s->dpi), 96); };
            AddListViewColumn(s->pageSections, 0, colW(140), L"Name");
            AddListViewColumn(s->pageSections, 1, colW(120), L"RVA");
            AddListViewColumn(s->pageSections, 2, colW(120), L"VSize");
            AddListViewColumn(s->pageSections, 3, colW(120), L"RawOff");
            AddListViewColumn(s->pageSections, 4, colW(120), L"RawSize");
            AddListViewColumn(s->pageSections, 5, colW(140), L"Chars");

            AddListViewColumn(s->pageImports, 0, colW(92), L"Type");
            AddListViewColumn(s->pageImports, 1, colW(260), L"DLL");
            AddListViewColumn(s->pageImports, 2, colW(340), L"Function");

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
            ApplyUiFontAndTheme(s);
            UpdateLayout(s);
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_OPEN: {
                    std::wstring path = PromptOpenFile(hwnd);
                    if (!path.empty()) {
                        StartAnalysis(s, path);
                    }
                    return 0;
                }
                case IDC_BTN_REFRESH: {
                    if (!s->currentFile.empty()) {
                        StartAnalysis(s, s->currentFile);
                    }
                    return 0;
                }
                case IDC_BTN_EXPORT_JSON: {
                    ExportJson(s);
                    return 0;
                }
                case IDC_BTN_EXPORT_TEXT: {
                    ExportText(s);
                    return 0;
                }
                case IDC_BTN_COPY_SUMMARY: {
                    CopySummary(s);
                    return 0;
                }
                case IDC_BTN_SETTINGS: {
                    ShowSettingsDialog(hwnd);
                    return 0;
                }
                case IDC_SIG_VERIFY: {
                    if (s->analysis == nullptr || s->currentFile.empty()) {
                        return 0;
                    }
                    if (s->busy) {
                        return 0;
                    }
                    SetBusy(s, true);
                    auto* payload = new std::pair<HWND, std::wstring>(s->hwnd, s->currentFile);
                    uintptr_t th = _beginthreadex(nullptr, 0, VerifyThreadProc, payload, 0, nullptr);
                    if (th == 0) {
                        delete payload;
                        SetBusy(s, false);
                        MessageBoxError(s->hwnd, L"\u542f\u52a8\u9a8c\u8bc1\u7ebf\u7a0b\u5931\u8d25");
                        return 0;
                    }
                    CloseHandle(reinterpret_cast<HANDLE>(th));
                    return 0;
                }
            }
            break;
        }
        case WM_NOTIFY: {
            auto* nm = reinterpret_cast<NMHDR*>(lParam);
            if (nm->hwndFrom == s->tab && nm->code == TCN_SELCHANGE) {
                int idx = TabCtrl_GetCurSel(s->tab);
                ShowOnlyTab(s, static_cast<TabIndex>(idx));
                UpdateLayout(s);
                return 0;
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
                s->analysis.reset();
                RefreshAllViews(s);
                MessageBoxError(s->hwnd, r->error.empty() ? L"\u89e3\u6790\u5931\u8d25" : r->error);
                delete r;
                return 0;
            }
            s->analysis = std::move(r->result);
            SetBusy(s, false);
            RefreshAllViews(s);
            delete r;
            return 0;
        }
        case WM_APP_VERIFY_DONE: {
            auto* vr = reinterpret_cast<VerifyResultMessage*>(lParam);
            if (s->analysis != nullptr) {
                if (vr->ok) {
                    s->analysis->embeddedVerify = vr->embedded;
                    s->analysis->catalogVerify = vr->catalog;
                    PopulateSignature(s->pageSignature, *s->analysis);
                } else {
                    MessageBoxError(s->hwnd, vr->error.empty() ? L"\u9a8c\u8bc1\u5931\u8d25" : vr->error);
                }
            }
            delete vr;
            SetBusy(s, false);
            return 0;
        }
        case WM_DESTROY: {
            if (s->uiFont) {
                DeleteObject(s->uiFont);
                s->uiFont = nullptr;
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

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

