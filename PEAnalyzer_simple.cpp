#include "stdafx.h"
#include "PEAnalyzer.h"
#include "PEParser.h"
#include "HashCalculator.h"

// Global variables
HINSTANCE g_hInstance = nullptr;
HWND g_hMainWindow = nullptr;

// Function prototypes
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool InitializeApplication(HINSTANCE hInstance);
void ShowMainWindow();
void RunMessageLoop();

// Application entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize application
    if (!InitializeApplication(hInstance)) {
        MessageBox(nullptr, L"Failed to initialize application", L"Error", MB_OK | MB_ICONERROR);
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
    wcex.lpszClassName = L"PEAnalyzerWindowClass";
    wcex.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        return false;
    }

    return true;
}

void ShowMainWindow() {
    // Create main window
    g_hMainWindow = CreateWindowEx(
        0,
        L"PEAnalyzerWindowClass",
        L"PE Analyzer & Hash Calculator",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        nullptr,
        nullptr,
        g_hInstance,
        nullptr
    );

    if (!g_hMainWindow) {
        MessageBox(nullptr, L"Failed to create main window", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Show and update window
    ShowWindow(g_hMainWindow, SW_SHOW);
    UpdateWindow(g_hMainWindow);
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
            // Initialize UI controls here
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw background
            RECT rect;
            GetClientRect(hwnd, &rect);
            FillRect(hdc, &rect, (HBRUSH)(COLOR_WINDOW + 1));
            
            // Draw title
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0, 0, 128));
            HFONT hFont = CreateFont(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            
            TextOut(hdc, 50, 50, L"PE Analyzer & Hash Calculator", 30);
            
            SelectObject(hdc, hOldFont);
            DeleteObject(hFont);
            
            EndPaint(hwnd, &ps);
            return 0;
        }

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}