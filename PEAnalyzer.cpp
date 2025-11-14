#include "stdafx.h"
#include "PEAnalyzer.h"
#include "PEParser.h"
#include "HashCalculator.h"
#include <iostream>
#include <string>
#include <algorithm>
#include <commdlg.h>
#include <vector>

// Global variables
HINSTANCE g_hInstance = nullptr;
HWND g_hMainWindow = nullptr;
HWND g_hTabControl = nullptr;
HWND g_hPEPage = nullptr;
HWND g_hHashPage = nullptr;
HWND g_hFilePathEdit = nullptr;
HWND g_hBrowseButton = nullptr;
HWND g_hAnalyzeButton = nullptr;
HWND g_hTreeView = nullptr;
HWND g_hHashInputEdit = nullptr;
HWND g_hHashOutputEdit = nullptr;
HWND g_hHashButton = nullptr;
HWND g_hAlgorithmCombo = nullptr;
HWND g_hLabelPath = nullptr;
HWND g_hCardIdentifier = nullptr;
HWND g_hCardInfo = nullptr;
HWND g_hTextEPRVA = nullptr;
HWND g_hTextEPRAW = nullptr;
HWND g_hTextLinker = nullptr;
HWND g_hTextEPSection = nullptr;
HWND g_hTextFirstBytes = nullptr;
HWND g_hTextSubsystem = nullptr;
HWND g_hEditMd5Notice = nullptr;
HWND g_hNavList = nullptr;
HWND g_hSearchEdit = nullptr;
HWND g_hFindButton = nullptr;
HWND g_hDllList = nullptr;
HWND g_hApiList = nullptr;
std::vector<PEImportDLL> g_cachedImports;
HWND g_hHashInputEdit2 = nullptr;
HWND g_hHashResultEdit = nullptr;
HWND g_hChkMD5 = nullptr;
HWND g_hChkSHA1 = nullptr;
HWND g_hChkSHA256 = nullptr;
HWND g_hPagePE = nullptr;
HWND g_hPageImports = nullptr;
HWND g_hPageHash = nullptr;
int g_currentPage = 0;
bool EnsureDir(const std::wstring& path) {
    return CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}
bool SaveWindowBmp(HWND hwnd, const std::wstring& filePath) {
    RECT rc; GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    HDC hdc = GetDC(hwnd);
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
    HGDIOBJ old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = h;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    std::vector<BYTE> bits(w * h * 4);
    GetDIBits(hdc, bmp, 0, h, bits.data(), &bmi, DIB_RGB_COLORS);
    BITMAPFILEHEADER bfh = {};
    bfh.bfType = 0x4D42;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize = bfh.bfOffBits + (DWORD)bits.size();
    HANDLE hf = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { DeleteObject(bmp); DeleteDC(mem); ReleaseDC(hwnd, hdc); return false; }
    DWORD wr = 0;
    WriteFile(hf, &bfh, sizeof(bfh), &wr, nullptr);
    WriteFile(hf, &bmi.bmiHeader, sizeof(BITMAPINFOHEADER), &wr, nullptr);
    WriteFile(hf, bits.data(), (DWORD)bits.size(), &wr, nullptr);
    CloseHandle(hf);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(hwnd, hdc);
    return true;
}
void ShowPage(int index) {
    g_currentPage = index;
    ShowWindow(g_hPagePE, index == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageImports, index == 1 ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hPageHash, index == 2 ? SW_SHOW : SW_HIDE);
}

// Current tab index
int g_nCurrentTab = 0;

// Function prototypes
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool InitializeApplication(HINSTANCE hInstance);
void ShowMainWindow();
void RunMessageLoop();
void CreateTabControl(HWND hwnd);
void CreatePEPage(HWND hwnd);
void CreateHashPage(HWND hwnd);
void OnTabSelectionChanged();
void CreateVtabsUI(HWND hwnd);
void ShowPage(int index);
void RefreshImportsView();
void ApplyImportsFilter();
void UpdateFieldsWithPE(const std::wstring& filePath);
void OnBrowseFile();
void OnAnalyzePE();
void OnCalculateHash();
std::wstring OpenFileDialog(HWND hwnd);
void DisplayPEInfo(const std::wstring& filePath);

// Application entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    // Initialize application
    if (!InitializeApplication(hInstance)) {
        MessageBoxW(nullptr, L"Failed to initialize application", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Show main window
    ShowMainWindow();

    // Run message loop
    RunMessageLoop();

    return 0;
}

bool InitializeApplication(HINSTANCE hInstance) {
    g_hInstance = hInstance;

    // Register window class
    WNDCLASSEX wcex = {};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WindowProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = TEXT("PEAnalyzerWindowClass");
    wcex.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        return false;
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {};
    iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    iccex.dwICC = ICC_TAB_CLASSES | ICC_TREEVIEW_CLASSES;
    InitCommonControlsEx(&iccex);

    return true;
}

void ShowMainWindow() {
    // Create main window
    g_hMainWindow = CreateWindowExW(
        0,
        L"PEAnalyzerWindowClass",
        L"File Format Identifier",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        500, 320,
        nullptr,
        nullptr,
        g_hInstance,
        nullptr
    );

    if (!g_hMainWindow) {
        MessageBoxW(nullptr, L"Failed to create main window", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0,0,0,0, g_hMainWindow, nullptr, g_hInstance, nullptr);
    // Single-page UI will be created below

    CreateWindowW(L"STATIC", L"", WS_CHILD, 0,0,0,0, g_hMainWindow, nullptr, g_hInstance, nullptr);
    // Create single-page controls
    // Path label
    g_hLabelPath = CreateWindowW(L"STATIC", L"Path", WS_CHILD | WS_VISIBLE | SS_LEFT, 28, 58, 40, 20, g_hMainWindow, nullptr, g_hInstance, nullptr);
    // Path edit
    g_hFilePathEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 70, 44, 328, 20, g_hMainWindow, nullptr, g_hInstance, nullptr);
    // Browse button
    g_hBrowseButton = CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 404, 44, 48, 20, g_hMainWindow, (HMENU)1, g_hInstance, nullptr);
    // Identifier card label
    CreateWindowW(L"STATIC", L"Identifier", WS_CHILD | WS_VISIBLE | SS_LEFT, 28, 104, 100, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    // Identifier fields
    g_hTextEPRVA = CreateWindowW(L"STATIC", L"Entry Point(RVA):", WS_CHILD | WS_VISIBLE | SS_LEFT, 28, 126, 220, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hTextEPRAW = CreateWindowW(L"STATIC", L"Entry Point(RAW):", WS_CHILD | WS_VISIBLE | SS_LEFT, 28, 146, 220, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hTextLinker = CreateWindowW(L"STATIC", L"Linker Info.:", WS_CHILD | WS_VISIBLE | SS_LEFT, 28, 166, 220, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hTextEPSection = CreateWindowW(L"STATIC", L"EP Section:", WS_CHILD | WS_VISIBLE | SS_LEFT, 270, 126, 200, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hTextFirstBytes = CreateWindowW(L"STATIC", L"First Bytes:", WS_CHILD | WS_VISIBLE | SS_LEFT, 270, 146, 200, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hTextSubsystem = CreateWindowW(L"STATIC", L"SubSystem:", WS_CHILD | WS_VISIBLE | SS_LEFT, 270, 166, 200, 18, g_hMainWindow, nullptr, g_hInstance, nullptr);
    // MD5 & Notice
    g_hEditMd5Notice = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY, 24, 226, 432, 36, g_hMainWindow, nullptr, g_hInstance, nullptr);

    g_hNavList = CreateWindowW(L"LISTBOX", nullptr, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_BORDER, 16, 84, 140, 200, g_hMainWindow, (HMENU)200, g_hInstance, nullptr);
    SendMessageW(g_hNavList, LB_ADDSTRING, 0, (LPARAM)L"PE Info");
    SendMessageW(g_hNavList, LB_ADDSTRING, 0, (LPARAM)L"Imports");
    SendMessageW(g_hNavList, LB_ADDSTRING, 0, (LPARAM)L"Hash");
    SendMessageW(g_hNavList, LB_SETCURSEL, 1, 0);

    g_hPagePE = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 164, 84, 300, 200, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hPageImports = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 164, 84, 300, 200, g_hMainWindow, nullptr, g_hInstance, nullptr);
    g_hPageHash = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 164, 84, 300, 200, g_hMainWindow, nullptr, g_hInstance, nullptr);
    ShowPage(0);

    CreateWindowW(L"STATIC", L"Identifier", WS_CHILD | WS_VISIBLE | SS_LEFT, 12, 20, 100, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hTextEPRVA = CreateWindowW(L"STATIC", L"Entry Point(RVA):", WS_CHILD | WS_VISIBLE | SS_LEFT, 12, 44, 220, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hTextEPRAW = CreateWindowW(L"STATIC", L"Entry Point(RAW):", WS_CHILD | WS_VISIBLE | SS_LEFT, 12, 64, 220, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hTextLinker = CreateWindowW(L"STATIC", L"Linker Info.:", WS_CHILD | WS_VISIBLE | SS_LEFT, 12, 84, 220, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hTextEPSection = CreateWindowW(L"STATIC", L"EP Section:", WS_CHILD | WS_VISIBLE | SS_LEFT, 160, 44, 200, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hTextFirstBytes = CreateWindowW(L"STATIC", L"First Bytes:", WS_CHILD | WS_VISIBLE | SS_LEFT, 160, 64, 200, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hTextSubsystem = CreateWindowW(L"STATIC", L"SubSystem:", WS_CHILD | WS_VISIBLE | SS_LEFT, 160, 84, 200, 18, g_hPagePE, nullptr, g_hInstance, nullptr);
    g_hEditMd5Notice = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY, 12, 112, 276, 60, g_hPagePE, nullptr, g_hInstance, nullptr);

    g_hSearchEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 12, 12, 220, 20, g_hPageImports, (HMENU)100, g_hInstance, nullptr);
    g_hFindButton = CreateWindowW(L"BUTTON", L"Find", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 240, 12, 50, 20, g_hPageImports, (HMENU)101, g_hInstance, nullptr);
    g_hDllList = CreateWindowW(L"LISTBOX", nullptr, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_BORDER, 12, 40, 130, 160, g_hPageImports, (HMENU)201, g_hInstance, nullptr);
    g_hApiList = CreateWindowW(L"LISTBOX", nullptr, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_BORDER, 156, 40, 130, 160, g_hPageImports, (HMENU)202, g_hInstance, nullptr);

    g_hChkMD5 = CreateWindowW(L"BUTTON", L"MD5", WS_CHILD | WS_VISIBLE | BS_CHECKBOX, 12, 12, 60, 20, g_hPageHash, (HMENU)301, g_hInstance, nullptr);
    g_hChkSHA1 = CreateWindowW(L"BUTTON", L"SHA1", WS_CHILD | WS_VISIBLE | BS_CHECKBOX, 82, 12, 60, 20, g_hPageHash, (HMENU)302, g_hInstance, nullptr);
    g_hChkSHA256 = CreateWindowW(L"BUTTON", L"SHA256", WS_CHILD | WS_VISIBLE | BS_CHECKBOX, 152, 12, 70, 20, g_hPageHash, (HMENU)303, g_hInstance, nullptr);
    SendMessageW(g_hChkMD5, BM_SETCHECK, BST_CHECKED, 0);
    SendMessageW(g_hChkSHA1, BM_SETCHECK, BST_CHECKED, 0);
    SendMessageW(g_hChkSHA256, BM_SETCHECK, BST_CHECKED, 0);
    g_hHashInputEdit2 = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | WS_VSCROLL, 12, 40, 276, 60, g_hPageHash, (HMENU)304, g_hInstance, nullptr);
    g_hHashResultEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 12, 104, 276, 60, g_hPageHash, (HMENU)305, g_hInstance, nullptr);
    CreateWindowW(L"BUTTON", L"Calculate", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 232, 12, 56, 20, g_hPageHash, (HMENU)3, g_hInstance, nullptr);

    ShowWindow(g_hMainWindow, SW_SHOW);
    UpdateWindow(g_hMainWindow);
    DragAcceptFiles(g_hMainWindow, TRUE);
}

void RunMessageLoop() {
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_KEYDOWN: {
            if (wParam == VK_F12) {
                EnsureDir(L"artifacts");
                SaveWindowBmp(g_hMainWindow, L"artifacts\\ui_main.bmp");
                if (g_hPagePE) SaveWindowBmp(g_hPagePE, L"artifacts\\ui_pe.bmp");
                if (g_hPageImports) SaveWindowBmp(g_hPageImports, L"artifacts\\ui_imports.bmp");
                if (g_hPageHash) SaveWindowBmp(g_hPageHash, L"artifacts\\ui_hash.bmp");
            }
            return 0;
        }

        case WM_NOTIFY: {
            return 0;
        }

        case WM_COMMAND: {
            WORD wmId = LOWORD(wParam);
            WORD code = HIWORD(wParam);
            if (wmId == 1) { // Browse button
                OnBrowseFile();
            } else if (wmId == 2) { // Analyze button
                OnAnalyzePE();
            } else if (wmId == 3) { // Hash button
                wchar_t textBuf[4096];
                GetWindowTextW(g_hHashInputEdit2, textBuf, 4096);
                std::vector<HashAlgorithm> algs;
                if (SendMessageW(g_hChkMD5, BM_GETCHECK, 0, 0) == BST_CHECKED) algs.push_back(HashAlgorithm::MD5);
                if (SendMessageW(g_hChkSHA1, BM_GETCHECK, 0, 0) == BST_CHECKED) algs.push_back(HashAlgorithm::SHA1);
                if (SendMessageW(g_hChkSHA256, BM_GETCHECK, 0, 0) == BST_CHECKED) algs.push_back(HashAlgorithm::SHA256);
                if (algs.empty()) {
                    MessageBoxW(g_hMainWindow, L"Select at least one algorithm", L"Error", MB_OK | MB_ICONWARNING);
                    return 0;
                }
                HashCalculator calc;
                std::wstring output;
                if (wcslen(textBuf) > 0) {
                    auto results = calc.CalculateTextHashes(textBuf, algs);
                    for (const auto& r : results) {
                        output += r.algorithm + L": " + r.result + L"\r\n";
                    }
                } else {
                    wchar_t filePath[1024];
                    GetWindowTextW(g_hFilePathEdit, filePath, 1024);
                    if (wcslen(filePath) == 0) {
                        MessageBoxW(g_hMainWindow, L"Enter text or choose a file", L"Error", MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    auto results = calc.CalculateFileHashes(filePath, algs);
                    for (const auto& r : results) {
                        output += r.algorithm + L": " + r.result + L"\r\n";
                    }
                }
                SetWindowTextW(g_hHashResultEdit, output.c_str());
            } else if (wmId == 101) {
                wchar_t q[256];
                GetWindowTextW(g_hSearchEdit, q, 256);
                SendMessageW(g_hDllList, LB_RESETCONTENT, 0, 0);
                for (const auto& d : g_cachedImports) {
                    std::wstring w(d.dllName.begin(), d.dllName.end());
                    if (wcslen(q)==0 || wcsstr(w.c_str(), q)!=nullptr) {
                        SendMessageW(g_hDllList, LB_ADDSTRING, 0, (LPARAM)w.c_str());
                    }
                }
                SendMessageW(g_hApiList, LB_RESETCONTENT, 0, 0);
            } else if (wmId == 200 && code == LBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_hNavList, LB_GETCURSEL, 0, 0);
                ShowPage(sel);
            } else if (wmId == 201 && code == LBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_hDllList, LB_GETCURSEL, 0, 0);
                SendMessageW(g_hApiList, LB_RESETCONTENT, 0, 0);
                if (sel >= 0 && sel < (int)g_cachedImports.size()) {
                    const auto& functions = g_cachedImports[sel].functions;
                    for (const auto& f : functions) {
                        std::wstring nm = f.isOrdinal ? (L"Ordinal:" + std::to_wstring(f.ordinal)) : std::wstring(f.name.begin(), f.name.end());
                        SendMessageW(g_hApiList, LB_ADDSTRING, 0, (LPARAM)nm.c_str());
                    }
                }
            }
            return 0;
        }

        case WM_SIZE: {
            // Resize controls when window size changes
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            if (g_hLabelPath && g_hFilePathEdit && g_hBrowseButton) {
                SetWindowPos(g_hLabelPath, nullptr, 28, 58, 40, 20, SWP_NOZORDER);
                SetWindowPos(g_hFilePathEdit, nullptr, 70, 44, rect.right - 70 - 64 - 16, 20, SWP_NOZORDER);
                SetWindowPos(g_hBrowseButton, nullptr, rect.right - 64 - 16, 44, 48, 20, SWP_NOZORDER);
            }
            if (g_hEditMd5Notice) {
                SetWindowPos(g_hEditMd5Notice, nullptr, 24, rect.bottom - 54, rect.right - 48, 36, SWP_NOZORDER);
            }
            if (g_hNavList) {
                SetWindowPos(g_hNavList, nullptr, 16, 84, 140, rect.bottom - 100, SWP_NOZORDER);
            }
            if (g_hPagePE) {
                SetWindowPos(g_hPagePE, nullptr, 164, 84, rect.right - 180, rect.bottom - 100, SWP_NOZORDER);
            }
            if (g_hPageImports) {
                SetWindowPos(g_hPageImports, nullptr, 164, 84, rect.right - 180, rect.bottom - 100, SWP_NOZORDER);
            }
            if (g_hPageHash) {
                SetWindowPos(g_hPageHash, nullptr, 164, 84, rect.right - 180, rect.bottom - 100, SWP_NOZORDER);
            }
            if (g_hSearchEdit && g_hFindButton) {
                SetWindowPos(g_hSearchEdit, nullptr, 176, 94, rect.right - 220 - 176 - 16, 20, SWP_NOZORDER);
                SetWindowPos(g_hFindButton, nullptr, rect.right - 16 - 50, 94, 50, 20, SWP_NOZORDER);
            }
            if (g_hDllList && g_hApiList) {
                int listWidth = (rect.right - 180 - 24) / 2;
                int listHeight = rect.bottom - 120 - 20;
                SetWindowPos(g_hDllList, nullptr, 176, 120, listWidth, listHeight, SWP_NOZORDER);
                SetWindowPos(g_hApiList, nullptr, 176 + listWidth + 8, 120, listWidth, listHeight, SWP_NOZORDER);
            }
            if (g_hChkMD5 && g_hChkSHA1 && g_hChkSHA256 && g_hHashInputEdit2 && g_hHashResultEdit) {
                SetWindowPos(g_hChkMD5, nullptr, 176, rect.bottom - 90, 60, 20, SWP_NOZORDER);
                SetWindowPos(g_hChkSHA1, nullptr, 236, rect.bottom - 90, 60, 20, SWP_NOZORDER);
                SetWindowPos(g_hChkSHA256, nullptr, 296, rect.bottom - 90, 70, 20, SWP_NOZORDER);
                SetWindowPos(g_hHashInputEdit2, nullptr, 176, rect.bottom - 66, rect.right - 180 - 24, 30, SWP_NOZORDER);
                SetWindowPos(g_hHashResultEdit, nullptr, 176, rect.bottom - 32, rect.right - 180 - 24, 22, SWP_NOZORDER);
            }

            return 0;
        }

        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            wchar_t szFile[MAX_PATH];
            
            // Get the first dropped file
            if (DragQueryFileW(hDrop, 0, szFile, MAX_PATH)) {
                SetWindowTextW(g_hFilePathEdit, szFile);
                // Automatically analyze the file
                // Update simplified fields
                PEParser parser;
                if (parser.LoadFile(szFile)) {
                    UpdateFieldsWithPE(szFile);
                }
            }
            
            DragFinish(hDrop);
            return 0;
        }

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

void CreateTabControl(HWND hwnd) {
    // Create tab control
    g_hTabControl = CreateWindowExW(
        0,
        L"SysTabControl32",
        nullptr,
        WS_CHILD | WS_VISIBLE | TCS_TABS,
        10, 10, 760, 520,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    // Add tabs
    TCITEMW tie = {};
    tie.mask = TCIF_TEXT;
    
    // PE Analysis tab - use shorter text to avoid truncation
    wchar_t tab1Text[] = L"PE";
    tie.pszText = tab1Text;
    TabCtrl_InsertItem(g_hTabControl, 0, &tie);
    
    // Hash Calculator tab - use shorter text to avoid truncation
    wchar_t tab2Text[] = L"Hash";
    tie.pszText = tab2Text;
    TabCtrl_InsertItem(g_hTabControl, 1, &tie);
}

void CreatePEPage(HWND hwnd) {
    // Create PE page (initially hidden)
    g_hPEPage = CreateWindowExW(
        WS_EX_CONTROLPARENT,
        L"STATIC",
        nullptr,
        WS_CHILD | SS_OWNERDRAW,
        20, 40, 740, 480,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    // File path label - make it single line to avoid wrapping
    CreateWindowW(L"STATIC", L"File Path:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 20, 80, 20,
        g_hPEPage, nullptr, g_hInstance, nullptr);

    // File path edit control
    g_hFilePathEdit = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        100, 20, 380, 25,
        g_hPEPage, nullptr, g_hInstance, nullptr);

    // Browse button
    g_hBrowseButton = CreateWindowW(L"BUTTON", L"Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        490, 20, 80, 25,
        g_hPEPage, (HMENU)1, g_hInstance, nullptr);

    // Analyze button
    g_hAnalyzeButton = CreateWindowW(L"BUTTON", L"Analyze PE",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        580, 20, 100, 25,
        g_hPEPage, (HMENU)2, g_hInstance, nullptr);

    // Tree view for PE info - make it larger and better positioned
    g_hTreeView = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SysTreeView32",
        nullptr,
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
        20, 60, 700, 380,
        g_hPEPage, nullptr, g_hInstance, nullptr
    );
}

void CreateHashPage(HWND hwnd) {
    // Create Hash page (initially hidden)
    g_hHashPage = CreateWindowExW(
        WS_EX_CONTROLPARENT,
        L"STATIC",
        nullptr,
        WS_CHILD | SS_OWNERDRAW,
        20, 40, 740, 480,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    // Input label - make it single line
    CreateWindowW(L"STATIC", L"Input Text:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 20, 80, 20,
        g_hHashPage, nullptr, g_hInstance, nullptr);

    // Hash input edit control
    g_hHashInputEdit = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | WS_VSCROLL,
        20, 50, 700, 100,
        g_hHashPage, nullptr, g_hInstance, nullptr);

    // Algorithm label
    CreateWindowW(L"STATIC", L"Algorithm:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 170, 80, 20,
        g_hHashPage, nullptr, g_hInstance, nullptr);

    // Algorithm combo box
    g_hAlgorithmCombo = CreateWindowW(L"COMBOBOX", nullptr,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        110, 170, 150, 200,
        g_hHashPage, nullptr, g_hInstance, nullptr);

    // Add algorithm options
    SendMessageW(g_hAlgorithmCombo, CB_ADDSTRING, 0, (LPARAM)L"MD5");
    SendMessageW(g_hAlgorithmCombo, CB_ADDSTRING, 0, (LPARAM)L"SHA1");
    SendMessageW(g_hAlgorithmCombo, CB_ADDSTRING, 0, (LPARAM)L"SHA256");
    SendMessageW(g_hAlgorithmCombo, CB_SETCURSEL, 0, 0);

    // Calculate hash button
    g_hHashButton = CreateWindowW(L"BUTTON", L"Calculate Hash",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        280, 170, 120, 25,
        g_hHashPage, (HMENU)3, g_hInstance, nullptr);

    // Output label - single line
    CreateWindowW(L"STATIC", L"Hash Result:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 210, 100, 20,
        g_hHashPage, nullptr, g_hInstance, nullptr);

    // Hash output edit control
    g_hHashOutputEdit = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        20, 240, 700, 200,
        g_hHashPage, nullptr, g_hInstance, nullptr);
}

void OnTabSelectionChanged() {
    int selectedTab = TabCtrl_GetCurSel(g_hTabControl);
    
    if (selectedTab == 0) {
        // Show PE Analysis page
        ShowWindow(g_hPEPage, SW_SHOW);
        ShowWindow(g_hHashPage, SW_HIDE);
    } else {
        // Show Hash Calculator page
        ShowWindow(g_hPEPage, SW_HIDE);
        ShowWindow(g_hHashPage, SW_SHOW);
    }
    
    g_nCurrentTab = selectedTab;
}

void OnAnalyzePE() {
    wchar_t filePath[1024];
    GetWindowTextW(g_hFilePathEdit, filePath, 1024);
    
    if (wcslen(filePath) > 0) {
        UpdateFieldsWithPE(filePath);
    } else {
        MessageBoxW(g_hMainWindow, L"Please select a file first", L"Error", MB_OK | MB_ICONWARNING);
    }
}

void OnCalculateHash() {
    wchar_t inputText[4096];
    GetWindowTextW(g_hHashInputEdit, inputText, 4096);
    
    if (wcslen(inputText) == 0) {
        MessageBoxW(g_hMainWindow, L"Please enter text to hash", L"Error", MB_OK | MB_ICONWARNING);
        return;
    }
    
    int selectedIndex = static_cast<int>(SendMessageW(g_hAlgorithmCombo, CB_GETCURSEL, 0, 0));
    
    HashAlgorithm algorithm;
    if (selectedIndex == 0) {
        algorithm = HashAlgorithm::MD5;
    } else if (selectedIndex == 1) {
        algorithm = HashAlgorithm::SHA1;
    } else {
        algorithm = HashAlgorithm::SHA256;
    }
    
    HashCalculator calculator;
    HashResult result = calculator.CalculateTextHash(inputText, algorithm);
    
    if (result.success) {
        SetWindowTextW(g_hHashOutputEdit, result.result.c_str());
    } else {
        MessageBoxW(g_hMainWindow, result.errorMessage.c_str(), L"Error", MB_OK | MB_ICONERROR);
    }
}

void OnBrowseFile() {
    std::wstring filePath = OpenFileDialog(g_hMainWindow);
    if (!filePath.empty()) {
        SetWindowTextW(g_hFilePathEdit, filePath.c_str());
        UpdateFieldsWithPE(filePath);
    }
}

std::wstring OpenFileDialog(HWND hwnd) {
    wchar_t szFile[MAX_PATH] = {0};
    
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"Executable Files\0*.exe;*.dll\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    if (GetOpenFileNameW(&ofn)) {
        return std::wstring(szFile);
    }
    
    return L"";
}

void DisplayPEInfo(const std::wstring& filePath) { UNREFERENCED_PARAMETER(filePath); }

void UpdateFieldsWithPE(const std::wstring& filePath) {
    PEParser parser;
    if (!parser.LoadFile(filePath)) {
        MessageBoxW(g_hMainWindow, parser.GetLastError().c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    const auto& hdr = parser.GetHeaderInfo();

    wchar_t buf[256];
    swprintf(buf, 256, L"Entry Point(RVA): 0x%08X", hdr.entryPoint);
    SetWindowTextW(g_hTextEPRVA, buf);

    std::ifstream f(filePath, std::ios::binary | std::ios::ate);
    size_t fileSize = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);
    std::vector<BYTE> data(fileSize);
    if (fileSize > 0) {
        f.read(reinterpret_cast<char*>(data.data()), fileSize);
    }
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(data.data());
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(data.data() + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    DWORD raw = 0;
    DWORD maxRawEnd = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto* s = &sec[i];
        DWORD va = s->VirtualAddress;
        DWORD vs = s->Misc.VirtualSize;
        if (hdr.entryPoint >= va && hdr.entryPoint < va + vs) {
            raw = s->PointerToRawData + (hdr.entryPoint - va);
        }
        DWORD rawEnd = s->PointerToRawData + s->SizeOfRawData;
        if (rawEnd > maxRawEnd) maxRawEnd = rawEnd;
    }
    swprintf(buf, 256, L"Entry Point(RAW): 0x%08X", raw);
    SetWindowTextW(g_hTextEPRAW, buf);

    swprintf(buf, 256, L"Linker Info.: %u.%u", nt->OptionalHeader.MajorLinkerVersion, nt->OptionalHeader.MinorLinkerVersion);
    SetWindowTextW(g_hTextLinker, buf);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto* s = &sec[i];
        DWORD va = s->VirtualAddress;
        DWORD vs = s->Misc.VirtualSize;
        if (hdr.entryPoint >= va && hdr.entryPoint < va + vs) {
            size_t n = strnlen(reinterpret_cast<const char*>(s->Name), 8);
            std::string tmp(reinterpret_cast<const char*>(s->Name), n);
            std::wstring w(tmp.begin(), tmp.end());
            swprintf(buf, 256, L"EP Section: %s", w.c_str());
            SetWindowTextW(g_hTextEPSection, buf);
            break;
        }
    }

    if (raw + 4 <= fileSize) {
        swprintf(buf, 256, L"First Bytes: %02X,%02X,%02X,%02X", data[raw], data[raw+1], data[raw+2], data[raw+3]);
    } else {
        wcscpy_s(buf, L"First Bytes: N/A");
    }
    SetWindowTextW(g_hTextFirstBytes, buf);

    const char* subs = "Unknown";
    switch (nt->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: subs = "Win32 GUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: subs = "Windows CUI"; break;
        case IMAGE_SUBSYSTEM_NATIVE: subs = "Native"; break;
        default: break;
    }
    std::wstring wsubs; for (const char* p=subs; *p; ++p) wsubs.push_back((wchar_t)*p);
    swprintf(buf, 256, L"SubSystem: %s", wsubs.c_str());
    SetWindowTextW(g_hTextSubsystem, buf);

    HashCalculator hc;
    auto md5 = hc.CalculateFileHash(filePath, HashAlgorithm::MD5);
    g_cachedImports = parser.GetImports();
    SendMessageW(g_hDllList, LB_RESETCONTENT, 0, 0);
    for (const auto& d : g_cachedImports) {
        std::wstring w(d.dllName.begin(), d.dllName.end());
        SendMessageW(g_hDllList, LB_ADDSTRING, 0, (LPARAM)w.c_str());
    }
    SendMessageW(g_hApiList, LB_RESETCONTENT, 0, 0);
    std::wstring notice;
    if (maxRawEnd < fileSize) {
        wchar_t nbuf[256];
        swprintf(nbuf, 256, L"Notice: 0x%08X extra bytes found, starting at offset 0x%08X", static_cast<unsigned>(fileSize - maxRawEnd), maxRawEnd);
        notice = nbuf;
    }
    std::wstring info = L"MD5: " + md5.result + (notice.empty() ? L"" : (L"\r\n" + notice));
    SetWindowTextW(g_hEditMd5Notice, info.c_str());
}